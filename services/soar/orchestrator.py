#!/usr/bin/env python3
"""Prahari SOAR orchestrator.

Executes the planned containment playbook in order. Per action it applies the
gate policy:
  * gate == auto  (blast_radius LOW/MEDIUM) -> auto-execute via the connector.
  * gate == human (blast_radius HIGH)        -> simulate a human-approval gate:
        record the approval request, a simulated approver + timestamps, then —
        on (simulated) approval — execute the connector.

Each action produces an execution record (timestamp, decision, result) written
to data/response_log.json. (A tamper-evident hash-chained ledger replaces this
simple JSON log in the next task.)
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.soar import connectors  # noqa: E402

PLAYBOOK = _REPO_ROOT / "data" / "response_playbook.json"
RESPONSE_LOG = _REPO_ROOT / "data" / "response_log.json"

SIM_APPROVER = "soc-lead@exams.gov.local"  # simulated human approver for HIGH gates


def _now() -> datetime:
    return datetime.now(timezone.utc)


def orchestrate() -> dict:
    plan = json.loads(PLAYBOOK.read_text())
    steps = plan["playbook"]
    records = []
    auto = gated = 0

    for i, step in enumerate(steps, 1):
        action, target = step["action"], step["target"]
        gate, blast = step["gate"], step["blast_radius"]
        rec = {
            "step": i,
            "action": action,
            "target": target,
            "blast_radius": blast,
            "gate": gate,
            "rationale": step["rationale"],
        }

        if gate == "human":
            gated += 1
            requested = _now()
            # --- simulated human-in-the-loop approval -------------------
            approved = requested + timedelta(seconds=90)  # simulated review latency
            rec["approval"] = {
                "required": True,
                "approver": SIM_APPROVER,
                "requested_at": requested.isoformat(),
                "approved_at": approved.isoformat(),
                "note": "SIMULATED approval — high blast-radius action requires a "
                "human sign-off before execution.",
            }
            result = connectors.execute(action, target)
            rec["decision"] = "gated-approved"
            rec["result"] = result
            rec["executed_at"] = _now().isoformat()
        else:
            auto += 1
            result = connectors.execute(action, target)
            rec["decision"] = "auto-executed"
            rec["result"] = result
            rec["executed_at"] = _now().isoformat()
        records.append(rec)

    log = {
        "incident_id": plan["incident_id"],
        "planner_mode": plan.get("mode"),
        "gate_policy": plan.get("gate_policy"),
        "generated_at": _now().isoformat(),
        "total_steps": len(steps),
        "auto_executed": auto,
        "gated_approved": gated,
        "records": records,
    }
    RESPONSE_LOG.write_text(json.dumps(log, indent=2))
    return log


def main() -> None:
    argparse.ArgumentParser(description="Execute the SOAR playbook.").parse_args()
    if not PLAYBOOK.exists():
        print(
            "No playbook found — run the planner first (make respond).", file=sys.stderr
        )
        sys.exit(1)
    log = orchestrate()
    print(
        f"\n[orchestrator] incident {log['incident_id']}  "
        f"steps={log['total_steps']}  auto={log['auto_executed']}  "
        f"gated={log['gated_approved']}"
    )
    print(f"  {'#':<3}{'action':<17}{'target':<16}{'blast':<8}{'decision':<16}status")
    print("  " + "-" * 70)
    for r in log["records"]:
        print(
            f"  {r['step']:<3}{r['action']:<17}{r['target']:<16}"
            f"{r['blast_radius']:<8}{r['decision']:<16}{r['result']['status']}"
        )
    if log["gated_approved"]:
        print("\n  Human-gated actions (HIGH blast radius):")
        for r in log["records"]:
            if r["gate"] == "human":
                ap = r["approval"]
                print(
                    f"    {r['action']}({r['target']}) — approved by "
                    f"{ap['approver']} at {ap['approved_at'][:19]}"
                )
    print(f"\n[orchestrator] wrote {RESPONSE_LOG}")


if __name__ == "__main__":
    main()
