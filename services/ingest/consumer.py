#!/usr/bin/env python3
"""Prahari spine consumer.

Reads the ``events:raw`` Redis stream via a consumer group, validates every
message against the ``SecurityEvent`` contract, and tallies a proof-of-spine
report: totals, breakdown by activity type, benign vs malicious, malicious
events per attack stage, and the distinct MITRE techniques observed.

No detection logic — this only proves that events flow Redis -> consumer and
that the labeled backbone (benign baseline + all attack stages) is intact.

The consumer drains the stream and exits on its own:
  * exits after --idle-timeout seconds with no new messages (once it has seen
    at least one), or
  * exits after --startup-grace seconds if nothing ever arrives.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections import Counter
from pathlib import Path

import redis

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dotenv import load_dotenv  # noqa: E402

from packages.schema import SecurityEvent  # noqa: E402

load_dotenv(_REPO_ROOT / ".env")

STREAM = "events:raw"


def ensure_group(r: redis.Redis, stream: str, group: str) -> None:
    """Create the consumer group at id 0 (read whole stream); ignore if exists."""
    try:
        r.xgroup_create(name=stream, groupname=group, id="0", mkstream=True)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


def main() -> None:
    ap = argparse.ArgumentParser(description="Consume + validate the events:raw spine.")
    ap.add_argument("--stream", default=STREAM)
    ap.add_argument("--group", default="spine")
    ap.add_argument("--consumer", default="c1")
    ap.add_argument(
        "--idle-timeout",
        type=float,
        default=5.0,
        help="exit after this many idle seconds once draining",
    )
    ap.add_argument(
        "--startup-grace",
        type=float,
        default=30.0,
        help="exit if nothing ever arrives within this many seconds",
    )
    ap.add_argument("--block-ms", type=int, default=1000)
    ap.add_argument(
        "--redis-url", default=os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    args = ap.parse_args()

    r = redis.from_url(args.redis_url, decode_responses=True)
    r.ping()
    ensure_group(r, args.stream, args.group)

    total = 0
    invalid = 0
    by_activity: Counter[str] = Counter()
    benign = malicious = 0
    by_stage: Counter[int] = Counter()
    techniques: set[str] = set()
    stage_names: dict[int, str] = {}

    start = time.time()
    last_msg = None
    while True:
        resp = r.xreadgroup(
            args.group,
            args.consumer,
            {args.stream: ">"},
            count=200,
            block=args.block_ms,
        )
        if resp:
            for _stream, messages in resp:
                for msg_id, fields in messages:
                    total += 1
                    try:
                        ev = SecurityEvent.model_validate_json(fields["data"])
                    except Exception:
                        invalid += 1
                        r.xack(args.stream, args.group, msg_id)
                        continue
                    by_activity[ev.activity] += 1
                    lbl = ev.raw.get("label", {}) if isinstance(ev.raw, dict) else {}
                    if lbl.get("is_malicious"):
                        malicious += 1
                        stg = lbl.get("attack_stage")
                        if stg is not None:
                            by_stage[stg] += 1
                            stage_names[stg] = lbl.get("stage_name", "")
                        if lbl.get("mitre_technique"):
                            techniques.add(lbl["mitre_technique"])
                    else:
                        benign += 1
                    r.xack(args.stream, args.group, msg_id)
            last_msg = time.time()
        else:
            now = time.time()
            if last_msg is None:
                if now - start > args.startup_grace:
                    break
            elif now - last_msg > args.idle_timeout:
                break

    _print_report(
        total,
        invalid,
        by_activity,
        benign,
        malicious,
        by_stage,
        stage_names,
        techniques,
    )


def _print_report(
    total, invalid, by_activity, benign, malicious, by_stage, stage_names, techniques
) -> None:
    line = "=" * 56
    print(f"\n{line}")
    print("  PRAHARI SPINE — events:raw consumer tally")
    print(line)
    print(f"  total events validated : {total}")
    print(f"  schema-invalid         : {invalid}")
    print(f"  benign                 : {benign}")
    print(f"  malicious              : {malicious}")

    print("\n  by activity type:")
    for act in ("process", "network", "auth", "file"):
        print(f"    {act:<10} {by_activity.get(act, 0)}")

    print("\n  malicious by attack stage:")
    if by_stage:
        for stg in sorted(by_stage):
            print(f"    stage {stg}  {by_stage[stg]:>3}  {stage_names.get(stg, '')}")
    else:
        print("    (none observed)")

    techs = sorted(techniques)
    print(f"\n  distinct MITRE techniques observed ({len(techs)}):")
    print(f"    {', '.join(techs) if techs else '(none)'}")
    print(line)
    # spine is sound only if we saw both baseline and all 6 attack stages
    ok = benign > 0 and len(by_stage) == 6 and len(techs) == 6 and invalid == 0
    print(
        f"  SPINE STATUS: {'OK — baseline + all 6 stages present' if ok else 'INCOMPLETE'}"
    )
    print(line)


if __name__ == "__main__":
    main()
