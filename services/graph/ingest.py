#!/usr/bin/env python3
"""Prahari graph ingester — builds the Neo4j provenance/entity graph.

Consumes the Redis ``events:raw`` stream via a dedicated consumer group
``graph`` (independent of the spine consumer), and MERGEs nodes + relationships
into Neo4j idempotently. Every event relationship is keyed on ``event_id`` and
carries ``ts`` (a Neo4j datetime), ``activity`` and the ground-truth-only props
``gt_malicious`` / ``gt_attack_stage`` / ``gt_technique`` read from raw.label.
GROUND-TRUTH PROPS ARE FOR SCORING/INSPECTION ONLY — never detection inputs.

Event -> graph mapping (adapted to the field reality observed in STEP 0):
  process : (:User)-[:STARTED]->(:Process)-[:ON_HOST]->(:Host)
  auth    : (:User)-[:AUTH {success, offhours}]->(:Host)      (actor.host = host logged into)
  network : (:Host)-[:CONNECTED_TO {dst_port}]->(:IP)         (no process in telemetry)
            (if a process were present: (:Process)-[:CONNECTED_TO]->(:IP))
  file    : (:User)-[:ACCESSED {action}]->(:File)-[:ON_HOST]->(:Host)  (no process in telemetry)

Lateral-movement projection (host-to-host), in addition to the above:
  auth    : resolve(src.ip) -[:REACHED {via:'auth'}]-> actor.host
            iff src.ip is internal AND its host != actor.host (a *remote* logon;
            local/kerberos logons where src.ip == the host's own IP are excluded)
  network : actor.host -[:REACHED {via:'network'}]-> resolve(dst.ip)
            iff dst.ip is internal AND != actor.host (external C2/exfil excluded)

Batch mode (default): create/seek the group to read the whole stream from id 0,
drain until exhausted, then exit. ``--follow`` is reserved for a future live
mode (not implemented). ``--reset`` wipes the Neo4j graph and re-reads the
stream from the beginning for a clean, reproducible load.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import redis

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dotenv import load_dotenv  # noqa: E402

from packages.schema import SecurityEvent  # noqa: E402
from services.graph.schema import (  # noqa: E402
    HostMap,
    create_schema,
    get_driver,
    load_host_map,
)

load_dotenv(_REPO_ROOT / ".env")

STREAM = "events:raw"
GROUP = "graph"
BH_START, BH_END = 9, 17  # business hours for the offhours flag
WRITE_ACTIONS = ("dropped", "staged", "archive", "dump", "created", "write")

# --- Cypher (UNWIND batches, one MERGE pattern per activity) ----------------

CY_PROCESS = """
UNWIND $rows AS row
MERGE (u:User {name: row.user})
MERGE (h:Host {name: row.host})
MERGE (p:Process {key: row.pkey})
  SET p.name = row.pname, p.pid = row.pid, p.cmdline = row.cmdline, p.host = row.host
MERGE (u)-[s:STARTED {event_id: row.event_id}]->(p)
  SET s.ts = datetime(row.ts), s.activity = 'process',
      s.gt_malicious = row.gt_malicious, s.gt_attack_stage = row.gt_stage,
      s.gt_technique = row.gt_tech
MERGE (p)-[:ON_HOST]->(h)
"""

CY_AUTH = """
UNWIND $rows AS row
MERGE (u:User {name: row.user})
MERGE (h:Host {name: row.host})
MERGE (u)-[a:AUTH {event_id: row.event_id}]->(h)
  SET a.ts = datetime(row.ts), a.activity = 'auth',
      a.success = row.success, a.offhours = row.offhours,
      a.gt_malicious = row.gt_malicious, a.gt_attack_stage = row.gt_stage,
      a.gt_technique = row.gt_tech
"""

CY_NETWORK_HOST = """
UNWIND $rows AS row
MERGE (h:Host {name: row.host})
MERGE (ip:IP {addr: row.dst_ip})
  SET ip.internal = row.dst_internal
MERGE (h)-[c:CONNECTED_TO {event_id: row.event_id}]->(ip)
  SET c.ts = datetime(row.ts), c.activity = 'network', c.dst_port = row.dst_port,
      c.gt_malicious = row.gt_malicious, c.gt_attack_stage = row.gt_stage,
      c.gt_technique = row.gt_tech
"""

CY_NETWORK_PROC = """
UNWIND $rows AS row
MERGE (p:Process {key: row.pkey})
MERGE (ip:IP {addr: row.dst_ip})
  SET ip.internal = row.dst_internal
MERGE (p)-[c:CONNECTED_TO {event_id: row.event_id}]->(ip)
  SET c.ts = datetime(row.ts), c.activity = 'network', c.dst_port = row.dst_port,
      c.gt_malicious = row.gt_malicious, c.gt_attack_stage = row.gt_stage,
      c.gt_technique = row.gt_tech
"""

CY_FILE = """
UNWIND $rows AS row
MERGE (u:User {name: row.user})
MERGE (h:Host {name: row.host})
MERGE (f:File {key: row.fkey})
  SET f.path = row.path, f.host = row.host
MERGE (u)-[ac:ACCESSED {event_id: row.event_id}]->(f)
  SET ac.ts = datetime(row.ts), ac.activity = 'file', ac.action = row.action,
      ac.gt_malicious = row.gt_malicious, ac.gt_attack_stage = row.gt_stage,
      ac.gt_technique = row.gt_tech
MERGE (f)-[:ON_HOST]->(h)
"""

CY_IP = """
UNWIND $rows AS row
MERGE (ip:IP {addr: row.addr})
  SET ip.internal = row.internal
"""

CY_HAS_IP = """
UNWIND $rows AS row
MATCH (ip:IP {addr: row.addr})
MERGE (h:Host {name: row.host})
MERGE (h)-[:HAS_IP]->(ip)
"""

CY_REACHED = """
UNWIND $rows AS row
MATCH (a:Host {name: row.src_host})
MATCH (b:Host {name: row.dst_host})
MERGE (a)-[r:REACHED {event_id: row.event_id}]->(b)
  SET r.via = row.via, r.ts = datetime(row.ts),
      r.gt_malicious = row.gt_malicious, r.gt_attack_stage = row.gt_stage,
      r.gt_technique = row.gt_tech
"""


def _gt(label: dict[str, Any]) -> dict[str, Any]:
    return {
        "gt_malicious": bool(label.get("is_malicious")),
        "gt_stage": label.get("attack_stage"),
        "gt_tech": label.get("mitre_technique"),
    }


def _offhours(ts_iso: str) -> bool:
    hour = datetime.fromisoformat(ts_iso).hour
    return hour < BH_START or hour >= BH_END


def _file_action(detail: str) -> str:
    d = (detail or "").lower()
    return "write" if any(k in d for k in WRITE_ACTIONS) else "read"


class Buckets:
    """Accumulates rows per activity pattern for batched UNWIND writes."""

    def __init__(self) -> None:
        self.process: list[dict] = []
        self.auth: list[dict] = []
        self.network_host: list[dict] = []
        self.network_proc: list[dict] = []
        self.file: list[dict] = []
        self.reached: list[dict] = []
        self.ips: dict[str, bool] = {}  # addr -> internal
        self.has_ip: dict[str, str] = {}  # addr -> host (internal only)

    def note_ip(self, addr: str | None, hm: HostMap) -> None:
        if not addr:
            return
        internal = hm.is_internal(addr)
        self.ips[addr] = internal
        host = hm.resolve_host(addr)
        if internal and host:
            self.has_ip[addr] = host


def classify(ev: SecurityEvent, hm: HostMap, buckets: Buckets) -> None:
    eid = str(ev.event_id)
    ts = ev.timestamp.isoformat()
    label = ev.raw.get("label", {}) if isinstance(ev.raw, dict) else {}
    detail = ev.raw.get("detail", "") if isinstance(ev.raw, dict) else ""
    gt = _gt(label)
    user, host = ev.actor.user, ev.actor.host

    if ev.activity == "process":
        pkey = f"{host}|{ev.process.pid}|{ev.process.name}"
        buckets.process.append(
            {
                "event_id": eid,
                "ts": ts,
                "user": user,
                "host": host,
                "pkey": pkey,
                "pname": ev.process.name,
                "pid": ev.process.pid,
                "cmdline": ev.process.cmdline,
                **gt,
            }
        )

    elif ev.activity == "auth":
        buckets.auth.append(
            {
                "event_id": eid,
                "ts": ts,
                "user": user,
                "host": host,
                "success": True,
                "offhours": _offhours(ts),
                **gt,
            }
        )
        buckets.note_ip(ev.src.ip, hm)
        buckets.note_ip(ev.dst.ip, hm)
        # REACHED (auth): remote logon from src.ip's host INTO actor.host
        src_host = hm.resolve_host(ev.src.ip)
        if hm.is_internal(ev.src.ip) and host and src_host and src_host != host:
            buckets.reached.append(
                {
                    "event_id": eid,
                    "ts": ts,
                    "via": "auth",
                    "src_host": src_host,
                    "dst_host": host,
                    **gt,
                }
            )

    elif ev.activity == "network":
        dst_ip = ev.dst.ip
        dst_internal = hm.is_internal(dst_ip)
        row = {
            "event_id": eid,
            "ts": ts,
            "host": host,
            "dst_ip": dst_ip,
            "dst_internal": dst_internal,
            "dst_port": ev.dst.port,
            **gt,
        }
        if ev.process.name:  # process branch (not present in current telemetry)
            row["pkey"] = f"{host}|{ev.process.pid}|{ev.process.name}"
            buckets.network_proc.append(row)
        else:
            buckets.network_host.append(row)
        buckets.note_ip(ev.src.ip, hm)
        buckets.note_ip(dst_ip, hm)
        # REACHED (network): actor.host -> resolve(dst.ip)
        dst_host = hm.resolve_host(dst_ip)
        if dst_internal and host and dst_host and dst_host != host:
            buckets.reached.append(
                {
                    "event_id": eid,
                    "ts": ts,
                    "via": "network",
                    "src_host": host,
                    "dst_host": dst_host,
                    **gt,
                }
            )

    elif ev.activity == "file":
        fkey = f"{host}|{ev.file.path}"
        buckets.file.append(
            {
                "event_id": eid,
                "ts": ts,
                "user": user,
                "host": host,
                "fkey": fkey,
                "path": ev.file.path,
                "action": _file_action(detail),
                **gt,
            }
        )


def flush(driver, buckets: Buckets) -> None:
    ip_rows = [{"addr": a, "internal": i} for a, i in buckets.ips.items()]
    has_ip_rows = [{"addr": a, "host": h} for a, h in buckets.has_ip.items()]
    plan = [
        (CY_IP, ip_rows),
        (CY_PROCESS, buckets.process),
        (CY_AUTH, buckets.auth),
        (CY_NETWORK_HOST, buckets.network_host),
        (CY_NETWORK_PROC, buckets.network_proc),
        (CY_FILE, buckets.file),
        (CY_HAS_IP, has_ip_rows),
        (CY_REACHED, buckets.reached),
    ]
    with driver.session() as s:
        for cypher, rows in plan:
            if rows:
                s.run(cypher, rows=rows)


def ensure_group(r: redis.Redis, stream: str, group: str, reset: bool) -> None:
    try:
        r.xgroup_create(name=stream, groupname=group, id="0", mkstream=True)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise
        if reset:  # re-read the whole stream from the beginning
            r.xgroup_setid(name=stream, groupname=group, id="0")


def drain_stream(
    r: redis.Redis, group: str, consumer: str, stream: str
) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    invalid = 0
    while True:
        resp = r.xreadgroup(group, consumer, {stream: ">"}, count=500, block=200)
        if not resp:
            break
        for _stream, messages in resp:
            for msg_id, fields in messages:
                try:
                    events.append(SecurityEvent.model_validate_json(fields["data"]))
                except Exception:
                    invalid += 1
                r.xack(stream, group, msg_id)
    if invalid:
        print(f"[warn] {invalid} schema-invalid messages skipped")
    return events


def main() -> None:
    ap = argparse.ArgumentParser(description="Ingest events:raw into the Neo4j graph.")
    ap.add_argument("--stream", default=STREAM)
    ap.add_argument("--group", default=GROUP)
    ap.add_argument("--consumer", default="g1")
    ap.add_argument(
        "--reset",
        action="store_true",
        help="DETACH DELETE the graph and re-read the stream from id 0",
    )
    ap.add_argument(
        "--follow",
        action="store_true",
        help="(reserved for future live mode — not implemented)",
    )
    ap.add_argument(
        "--redis-url", default=os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    args = ap.parse_args()

    if args.follow:
        print("[info] --follow (live mode) is not implemented yet; running batch mode.")

    hm = load_host_map()
    r = redis.from_url(args.redis_url, decode_responses=True)
    r.ping()
    driver = get_driver()

    try:
        create_schema(driver)
        if args.reset:
            with driver.session() as s:
                s.run("MATCH (n) DETACH DELETE n")
            print("[reset] graph wiped")
        ensure_group(r, args.stream, args.group, args.reset)

        events = drain_stream(r, args.group, args.consumer, args.stream)
        buckets = Buckets()
        by_activity: Counter[str] = Counter()
        mal_by_stage: Counter[int] = Counter()
        for ev in events:
            classify(ev, hm, buckets)
            by_activity[ev.activity] += 1
            lbl = ev.raw.get("label", {}) if isinstance(ev.raw, dict) else {}
            if lbl.get("is_malicious") and lbl.get("attack_stage") is not None:
                mal_by_stage[lbl["attack_stage"]] += 1
        flush(driver, buckets)

        _summary(events, by_activity, buckets, mal_by_stage)
    finally:
        driver.close()


def _summary(events, by_activity, buckets: Buckets, mal_by_stage) -> None:
    print("\n=== graph ingest complete ===")
    print(f"events ingested : {len(events)}")
    for act in ("process", "network", "auth", "file"):
        print(f"  {act:<9}: {by_activity.get(act, 0)}")
    print(
        f"IP nodes        : {len(buckets.ips)} "
        f"({sum(buckets.ips.values())} internal)"
    )
    print(
        f"REACHED edges   : {len(buckets.reached)} "
        f"({sum(1 for x in buckets.reached if x['gt_malicious'])} malicious)"
    )
    if mal_by_stage:
        print(f"malicious stages: {dict(sorted(mal_by_stage.items()))}")


if __name__ == "__main__":
    main()
