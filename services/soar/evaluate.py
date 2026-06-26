#!/usr/bin/env python3
"""Prahari SOAR automation-coverage metric.

automation_coverage = auto-executable steps / total steps (%), with the
auto-vs-gated breakdown and which actions were gated and why.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
RESPONSE_LOG = _REPO_ROOT / "data" / "response_log.json"
PLAYBOOK = _REPO_ROOT / "data" / "response_playbook.json"


def main() -> None:
    if RESPONSE_LOG.exists():
        data = json.loads(RESPONSE_LOG.read_text())
        steps = data["records"]
        incident = data["incident_id"]
        gate_policy = data.get("gate_policy")
    else:
        data = json.loads(PLAYBOOK.read_text())
        steps = data["playbook"]
        incident = data["incident_id"]
        gate_policy = data.get("gate_policy")

    total = len(steps)
    auto = sum(1 for s in steps if s["gate"] == "auto")
    gated = total - auto
    coverage = auto / total if total else 0.0
    by_blast = Counter(s["blast_radius"] for s in steps)

    print("=" * 64)
    print(f"  SOAR AUTOMATION COVERAGE — incident {incident}")
    print("=" * 64)
    print(f"  gate policy : {gate_policy}")
    print(f"  total steps : {total}")
    print(f"  auto-executable : {auto}")
    print(f"  human-gated     : {gated}")
    print(f"\n  AUTOMATION COVERAGE : {auto}/{total} = {coverage * 100:.1f}%")
    print(
        f"\n  blast-radius breakdown: "
        f"LOW={by_blast.get('LOW', 0)}  MEDIUM={by_blast.get('MEDIUM', 0)}  "
        f"HIGH={by_blast.get('HIGH', 0)}"
    )
    print(
        f"  auto = LOW+MEDIUM ({by_blast.get('LOW', 0) + by_blast.get('MEDIUM', 0)})"
        f"  |  gated = HIGH ({by_blast.get('HIGH', 0)})"
    )

    print("\n  auto-executed actions:")
    for s in steps:
        if s["gate"] == "auto":
            print(f"    [{s['blast_radius']:<6}] {s['action']}({s['target']})")

    print("\n  human-gated actions (and WHY):")
    for s in steps:
        if s["gate"] == "human":
            why = (
                "critical asset"
                if s["action"] == "isolate_host"
                else (
                    "high-privilege account"
                    if s["action"] == "disable_user"
                    else "high blast radius"
                )
            )
            print(
                f"    [{s['blast_radius']:<6}] {s['action']}({s['target']}) "
                f"-> requires human approval ({why})"
            )

    print(
        "\n  Interpretation: Prahari auto-contains the reversible / low-impact "
        f"steps\n  ({coverage * 100:.0f}% of the playbook) and escalates only the "
        "high-impact actions\n  (isolating the exam-records server, disabling the "
        "domain admin) to a human."
    )


if __name__ == "__main__":
    main()
