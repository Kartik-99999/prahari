#!/usr/bin/env python3
"""Prahari deterministic behavioural -> ATT&CK mapper.

For each event in the top incident, assigns the single most likely ATT&CK
technique (parent granularity) using a DOCUMENTED rule table over behavioural
facts only — activity, process name/command line, ports, external flags,
lateral context, and the UEBA "reasons". Ground truth (gt_*) is NEVER read here.
RAG (services.attribution.rag) supplies a corroborating candidate that is
recorded in the rationale.

The inferred technique is written onto the matching Neo4j edges as
``inferred_technique`` / ``inferred_confidence`` / ``inferred_rationale`` — kept
STRICTLY SEPARATE from gt_technique — and into data/incidents.json.

Rule table (first match wins), behavioural fact -> parent technique:
  R1 cmdline ~ lsass/comsvcs/minidump/mimikatz/procdump, or file is a .dmp  -> T1003
  R2 cmdline ~ 7z/rar/tar/archive, or file is .7z/.rar/.zip/exam-records    -> T1560
  R3 cmdline ~ winword/excel/office macro lineage ("spawned by winword")    -> T1566
  R4 auth from an EXTERNAL source IP (valid-account reuse)                  -> T1078
  R5 auth remote-logon, or net to another internal host on 445/3389        -> T1021
  R6 net to EXTERNAL ip: if host already archived data -> T1041, else       -> T1071
  R7 process running an interpreter with -enc/encodedcommand/downloadstring -> T1059
  else                                                                      -> (none)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.attribution.attack_kb import get_kb  # noqa: E402
from services.attribution.rag import retrieve  # noqa: E402
from services.graph.schema import get_driver, load_host_map  # noqa: E402

EVENTS = _REPO_ROOT / "data" / "events.jsonl"
SCORES = _REPO_ROOT / "data" / "ueba_scores.csv"
INCIDENTS = _REPO_ROOT / "data" / "incidents.json"

LATERAL_PORTS = {445, 3389, 5985, 5986}
CRED_KW = ("lsass", "comsvcs", "minidump", "mimikatz", "procdump")
# archive: match the tool invocation, not loose substrings (avoid "tar" inside words)
ARCHIVE_CMD = ("7z ", "7z.exe", "winrar", "rar a", "tar -c", "tar c", "-czf")
ARCHIVE_PNAME = ("7z.exe", "rar.exe", "winrar.exe")
ARCHIVE_EXT = (".7z", ".rar", ".zip", ".tar", ".gz")
# phishing: require office-macro PROCESS LINEAGE, not a bare office-app launch
PHISH_KW = (
    "spawned by winword",
    "spawned by excel",
    "spawned by outlook",
    "macro",
    "vba ",
)
INTERP_KW = ("-enc", "encodedcommand", "downloadstring", "iex ")


def _load_events() -> dict[str, dict]:
    out = {}
    with EVENTS.open() as f:
        for line in f:
            line = line.strip()
            if line:
                e = json.loads(line)
                out[e["event_id"]] = e
    return out


def map_event(
    ev: dict, hm, host_archived_before: bool
) -> tuple[str | None, float, str]:
    activity = ev["activity"]
    proc = ev.get("process") or {}
    pname = (proc.get("name") or "").lower()
    cmd = (proc.get("cmdline") or "").lower()
    fpath = ((ev.get("file") or {}).get("path") or "").lower()
    host = (ev.get("actor") or {}).get("host")
    src_ip = (ev.get("src") or {}).get("ip")
    dst_ip = (ev.get("dst") or {}).get("ip")
    dst_port = (ev.get("dst") or {}).get("port")

    ext_dst = bool(dst_ip) and not hm.is_internal(dst_ip)
    ext_auth = activity == "auth" and bool(src_ip) and not hm.is_internal(src_ip)
    src_host = hm.resolve_host(src_ip)
    dst_host = hm.resolve_host(dst_ip)
    auth_lateral = (
        activity == "auth" and hm.is_internal(src_ip) and src_host and src_host != host
    )
    net_lateral = (
        activity == "network"
        and hm.is_internal(dst_ip)
        and dst_host
        and dst_host != host
        and dst_port in LATERAL_PORTS
    )

    # R1 — OS credential dumping
    if any(k in cmd for k in CRED_KW) or (
        activity == "file" and fpath.endswith(".dmp")
    ):
        return "T1003", 0.9, "LSASS/credential-dumping tooling or .dmp artifact"
    # R2 — archive collected data
    if (
        any(k in cmd for k in ARCHIVE_CMD)
        or pname in ARCHIVE_PNAME
        or (activity == "file" and any(fpath.endswith(x) for x in ARCHIVE_EXT))
    ):
        return "T1560", 0.88, "archiving utility / staged archive of collected data"
    # R3 — phishing (office-macro lineage spawning interpreter)
    if any(k in cmd for k in PHISH_KW):
        return "T1566", 0.85, "interpreter spawned via office-document macro lineage"
    # R4 — valid accounts (external auth source)
    if ext_auth:
        return (
            "T1078",
            0.9,
            f"authentication from external IP {src_ip} using a valid account",
        )
    # R5 — lateral movement over remote services
    if net_lateral:
        return (
            "T1021",
            0.85,
            f"remote-service connection {host}->{dst_host} on port {dst_port}",
        )
    if auth_lateral:
        return "T1021", 0.82, f"remote logon into {host} from {src_host}"
    # R6 — external network: exfil if data was archived on this host, else C2 beacon
    if activity == "network" and ext_dst:
        if host_archived_before:
            return (
                "T1041",
                0.85,
                f"outbound transfer from {host} to external {dst_ip} after local archiving (exfil)",
            )
        return (
            "T1071",
            0.7,
            f"outbound connection from {host} to external {dst_ip} (application-layer C2/beacon)",
        )
    # R7 — suspicious interpreter execution
    if activity == "process" and any(k in cmd for k in INTERP_KW):
        return "T1059", 0.6, "command/script interpreter with encoded/download payload"
    return None, 0.0, "no attack-technique indicators in behavioural facts"


def _rag_query(ev: dict, reasons: list[str]) -> str:
    proc = ev.get("process") or {}
    parts = [
        ev["activity"],
        proc.get("name") or "",
        proc.get("cmdline") or "",
        (ev.get("file") or {}).get("path") or "",
    ]
    dp = (ev.get("dst") or {}).get("port")
    if dp:
        parts.append(f"port {dp}")
    parts.extend(reasons)
    return " ".join(p for p in parts if p)


def run(write: bool = True) -> dict:
    events = _load_events()
    hm = load_host_map()
    incidents = json.loads(INCIDENTS.read_text())
    top = incidents[0]
    members = top["member_event_ids"]

    # reasons per event (behavioural context from UEBA, not labels)
    import csv

    reasons_by_id: dict[str, list[str]] = {}
    with SCORES.open() as f:
        for row in csv.DictReader(f):
            try:
                reasons_by_id[row["event_id"]] = json.loads(row.get("reasons") or "[]")
            except Exception:  # noqa: BLE001
                reasons_by_id[row["event_id"]] = []

    # which hosts archived data, and when (earliest) — for exfil-vs-beacon disambiguation
    archive_ts: dict[str, str] = {}
    for eid in members:
        ev = events[eid]
        cmd = ((ev.get("process") or {}).get("cmdline") or "").lower()
        pn = ((ev.get("process") or {}).get("name") or "").lower()
        fp = ((ev.get("file") or {}).get("path") or "").lower()
        if (
            any(k in cmd for k in ARCHIVE_CMD)
            or pn in ARCHIVE_PNAME
            or any(fp.endswith(x) for x in ARCHIVE_EXT)
        ):
            h = (ev.get("actor") or {}).get("host")
            if h and (h not in archive_ts or ev["timestamp"] < archive_ts[h]):
                archive_ts[h] = ev["timestamp"]

    inferences = {}
    for eid in members:
        ev = events[eid]
        host = (ev.get("actor") or {}).get("host")
        archived_before = host in archive_ts and archive_ts[host] < ev["timestamp"]
        tid, conf, rationale = map_event(ev, hm, archived_before)
        rag_hits = retrieve(_rag_query(ev, reasons_by_id.get(eid, [])), k=2)
        rag_ids = [h["technique_id"] or h["source"] for h in rag_hits]
        full_rationale = f"{rationale}; RAG candidates: {', '.join(rag_ids)}"
        kb_name = get_kb().technique_by_id(tid).name if tid else None
        inferences[eid] = {
            "inferred_technique": tid,
            "inferred_technique_name": kb_name,
            "inferred_confidence": conf,
            "inferred_rationale": full_rationale,
        }

    labeled = {k: v for k, v in inferences.items() if v["inferred_technique"]}
    print(
        f"top incident: {top['id']}  members: {len(members)}  "
        f"labeled with a technique: {len(labeled)}"
    )
    from collections import Counter

    dist = Counter(v["inferred_technique"] for v in labeled.values())
    print("inferred technique distribution:", dict(sorted(dist.items())))

    # persist into incidents.json
    top["event_inferences"] = inferences
    top["inferred_techniques"] = sorted(dist)
    INCIDENTS.write_text(json.dumps(incidents, indent=2))

    if write:
        _write_neo4j(inferences)
    return inferences


def _write_neo4j(inferences: dict) -> None:
    rows = [
        {
            "event_id": eid,
            "tech": v["inferred_technique"] or "",
            "conf": v["inferred_confidence"],
            "rat": v["inferred_rationale"],
        }
        for eid, v in inferences.items()
        if v["inferred_technique"]
    ]
    cypher = """
    UNWIND $rows AS row
    MATCH ()-[r {event_id: row.event_id}]->()
    SET r.inferred_technique = row.tech,
        r.inferred_confidence = row.conf,
        r.inferred_rationale = row.rat
    RETURN count(r) AS n
    """
    driver = get_driver()
    try:
        with driver.session() as s:
            # clear any prior inferred_* so re-runs reflect only the current mapping
            s.run(
                "MATCH ()-[r]->() WHERE r.inferred_technique IS NOT NULL "
                "REMOVE r.inferred_technique, r.inferred_confidence, "
                "r.inferred_rationale"
            )
            n = s.run(cypher, rows=rows).single()["n"]
        print(
            f"Wrote inferred_technique onto {n} Neo4j relationships "
            f"({len(rows)} labeled events)."
        )
    finally:
        driver.close()


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Map incident events to ATT&CK techniques."
    )
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args()
    run(write=not args.no_write)


if __name__ == "__main__":
    main()
