#!/usr/bin/env python3
"""Prahari incident-lifecycle -> audit ledger.

Records the full incident lifecycle into the tamper-evident ledger, in order:
  1. one DETECTION entry  (incident confirmed; evidence = member event_ids + MTTD)
  2. one ATTRIBUTION entry (techniques + predicted next_moves)
  3. one entry PER response action (auto-executed | gated-approved, with approver)

Deterministic + idempotent: clears (TRUNCATE) and rebuilds the ledger each run,
so a fresh `make respond` always yields the same chain.
"""

from __future__ import annotations

import csv
import json
import sys
from datetime import datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.soar import audit  # noqa: E402

INCIDENTS = _REPO_ROOT / "data" / "incidents.json"
ATTRIBUTION = _REPO_ROOT / "data" / "attribution_report.json"
RESPONSE_LOG = _REPO_ROOT / "data" / "response_log.json"
SCORES = _REPO_ROOT / "data" / "ueba_scores.csv"
GT = _REPO_ROOT / "data" / "ground_truth.json"

STRONG = 0.9
CONFIRM_COUNT = 3
DET_POLICY = "detection-v1"
DET_MODEL = "ueba(iforest+ecod)+pagerank-fusion-v1"


def _mttd() -> dict:
    """Confirmed-detection time (gt-free) + MTTD/dwell reporting metrics."""
    inc = json.loads(INCIDENTS.read_text())[0]
    anomaly = {}
    with SCORES.open() as f:
        for row in csv.DictReader(f):
            anomaly[row["event_id"]] = float(row["anomaly_score"])
    # confirmed = timestamp of the CONFIRM_COUNT-th strong (anomaly>=STRONG) member,
    # in chronological order — uses detection signal only, no ground truth.
    ts_by_id = _event_ts()
    timed = sorted(inc["member_event_ids"], key=lambda e: ts_by_id.get(e, ""))
    strong = 0
    confirmed_at = None
    for e in timed:
        if anomaly.get(e, 0) >= STRONG:
            strong += 1
            if strong >= CONFIRM_COUNT:
                confirmed_at = ts_by_id[e]
                break
    # MTTD/dwell are post-hoc REPORTING metrics (ground truth used only for scoring)
    gt = json.loads(GT.read_text())
    s1 = min(e["timestamp"] for e in gt["events"] if e["attack_stage"] == 1)
    s6 = max(e["timestamp"] for e in gt["events"] if e["attack_stage"] == 6)
    cdt = datetime.fromisoformat(confirmed_at)
    mttd = (cdt - datetime.fromisoformat(s1)).total_seconds() / 86400.0
    dwell = (datetime.fromisoformat(s6) - cdt).total_seconds() / 86400.0
    return {
        "confirmed_at": confirmed_at,
        "attack_start": s1,
        "exfil_complete": s6,
        "mttd_days_after_foothold": round(mttd, 2),
        "dwell_days_before_exfil": round(dwell, 2),
    }


def _event_ts() -> dict:
    out = {}
    with SCORES.open() as f:
        for row in csv.DictReader(f):
            out[row["event_id"]] = row["ts"]
    return out


def record_lifecycle(conn=None) -> list[dict]:
    own = conn is None
    conn = conn or audit.get_conn()
    try:
        audit.build_schema(conn)
        audit.clear(conn)

        inc = json.loads(INCIDENTS.read_text())[0]
        attribution = (
            json.loads(ATTRIBUTION.read_text())
            if ATTRIBUTION.exists()
            else {"mode": "n/a", "model": None, "attribution": {}}
        )
        attr = attribution.get("attribution", {})
        log = json.loads(RESPONSE_LOG.read_text())
        mttd = _mttd()

        receipts = []

        # 1. DETECTION
        receipts.append(
            audit.append(
                {
                    "ts": mttd["confirmed_at"],
                    "actor": "prahari.detector",
                    "action": "DETECT",
                    "target": inc["id"],
                    "decision": "confirmed",
                    "rationale": (
                        f"Incident {inc['id']} confirmed by correlated weak signals "
                        f"across {inc['hosts']} with a lateral path; MTTD "
                        f"{mttd['mttd_days_after_foothold']}d after foothold, "
                        f"{mttd['dwell_days_before_exfil']}d before exfil."
                    ),
                    "evidence": {
                        "incident_id": inc["id"],
                        "n_events": inc["n_events"],
                        "member_event_ids": inc["member_event_ids"],
                        **mttd,
                    },
                    "blast_radius": "-",
                    "result": {
                        "incident_score": inc["incident_score"],
                        "has_lateral_path": inc["has_lateral_path"],
                        "hosts": inc["hosts"],
                    },
                    "policy_version": DET_POLICY,
                    "model_version": DET_MODEL,
                },
                conn,
            )
        )

        # 2. ATTRIBUTION
        ca = attr.get("campaign_assessment", {})
        receipts.append(
            audit.append(
                {
                    "ts": mttd["confirmed_at"],
                    "actor": "prahari.attribution-agent",
                    "action": "ATTRIBUTE",
                    "target": inc["id"],
                    "decision": attribution.get("mode", "n/a"),
                    "rationale": ca.get(
                        "summary", "ATT&CK attribution of the incident."
                    ),
                    "evidence": {
                        "techniques": [
                            t["technique_id"] for t in attr.get("techniques", [])
                        ],
                        "next_moves": [
                            m["predicted_technique"] for m in attr.get("next_moves", [])
                        ],
                        "threat_profile": ca.get("threat_profile"),
                        "advisory_citations": ca.get("advisory_citations", []),
                    },
                    "blast_radius": "-",
                    "result": {"overall_confidence": attr.get("overall_confidence")},
                    "policy_version": "attack-mapper-v1",
                    "model_version": (
                        attribution.get("model")
                        or f"attribution-{attribution.get('mode', 'n/a')}"
                    ),
                },
                conn,
            )
        )

        # 3. one entry per response action
        for r in log["records"]:
            approver = (
                r.get("approval", {}).get("approver") if r.get("approval") else None
            )
            receipts.append(
                audit.append(
                    {
                        "ts": r.get("executed_at"),
                        "actor": "prahari.soar",
                        "action": r["action"],
                        "target": r["target"],
                        "decision": r["decision"],
                        "rationale": r["rationale"],
                        "evidence": {
                            "gate": r["gate"],
                            "approver": approver,
                            "playbook_step": r["step"],
                        },
                        "blast_radius": r["blast_radius"],
                        "result": r["result"],
                        "policy_version": log.get("gate_policy"),
                        "model_version": f"planner-{log.get('planner_mode', 'n/a')}",
                    },
                    conn,
                )
            )

        return receipts
    finally:
        if own:
            conn.close()


def main() -> None:
    import psycopg

    try:
        receipts = record_lifecycle()
    except psycopg.Error as e:
        print(
            f"[lifecycle] ledger unavailable ({e}); run `make audit-build` first.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"[lifecycle] recorded {len(receipts)} ledger entries:")
    for r in receipts:
        print(
            f"   seq {r['seq']}  prev={r['prev_hash'][:10]}  entry={r['entry_hash'][:10]}"
        )


if __name__ == "__main__":
    main()
