#!/usr/bin/env python3
"""Prahari replay harness.

Regenerates the deterministic synthetic event stream (via the scenario
generator) and XADDs each normalized ``SecurityEvent`` onto the Redis stream
``events:raw``, preserving relative inter-event timing scaled by --speed.

  --speed  time-compression factor (simulated seconds per real second).
           1        = real time (21 simulated days take 21 days)
           15000    = default "compressed": ~21 days replayed in ~2 minutes
           1000000+ = effectively as-fast-as-possible (used by `make spine-test`)
  --seed   deterministic generator seed (must match for reproducible event_ids)
  --reset  delete the stream before replaying (clean slate)

Each event is stored as a single ``data`` field holding ``model_dump_json()``;
the consumer reconstructs it with ``SecurityEvent.model_validate_json``.
Ground truth is (re)written so it always matches the replayed events.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

import redis

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dotenv import load_dotenv  # noqa: E402

from packages.scenario.generator import Generator, write_outputs  # noqa: E402

load_dotenv(_REPO_ROOT / ".env")

STREAM = "events:raw"
MAX_SLEEP_S = 30.0  # safety clamp so a single multi-day gap can't stall a run


def main() -> None:
    ap = argparse.ArgumentParser(description="Replay synthetic telemetry to Redis.")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument(
        "--speed",
        type=float,
        default=15000.0,
        help="time-compression factor (sim seconds per real second)",
    )
    ap.add_argument("--stream", default=STREAM)
    ap.add_argument("--reset", action="store_true", help="delete stream before replay")
    ap.add_argument(
        "--redis-url", default=os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    args = ap.parse_args()

    r = redis.from_url(args.redis_url)
    r.ping()
    if args.reset:
        r.delete(args.stream)

    gen = Generator(seed=args.seed)
    events = gen.generate()
    gt = write_outputs(events, args.seed)

    speed = max(args.speed, 1e-9)
    prev_ts = None
    benign = malicious = 0
    t0 = time.time()
    for ev in events:
        if prev_ts is not None:
            delay = (ev.timestamp - prev_ts).total_seconds() / speed
            if delay > 0:
                time.sleep(min(delay, MAX_SLEEP_S))
        prev_ts = ev.timestamp
        r.xadd(args.stream, {"data": ev.model_dump_json()})
        if ev.raw.get("label", {}).get("is_malicious"):
            malicious += 1
        else:
            benign += 1

    elapsed = time.time() - t0
    span_lo = events[0].timestamp.date().isoformat()
    span_hi = events[-1].timestamp.date().isoformat()
    print("\n=== replay complete ===")
    print(f"stream      : {args.stream}")
    print(f"total       : {len(events)}")
    print(f"benign      : {benign}")
    print(f"malicious   : {malicious}")
    print(f"date span   : {span_lo} .. {span_hi}")
    print(f"techniques  : {', '.join(gt['distinct_techniques'])}")
    print(f"speed       : {args.speed}x  (wall time {elapsed:.1f}s)")
    print(f"seed        : {args.seed}")


if __name__ == "__main__":
    main()
