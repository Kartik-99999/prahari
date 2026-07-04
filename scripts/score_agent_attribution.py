#!/usr/bin/env python3
"""Score a live attribution-agent report against ground truth — honestly.

Joins each `submit_attribution` technique's cited `event_ids` to the scenario's
`ground_truth.json`, on the same per-malicious-event basis as the deterministic
mapper's documented number. Reports both technique-SET recall (did the agent name
the right techniques?) and per-EVENT grounding (did it cite the actually-malicious
events?). The second number is the honest one; see docs/LIVE_AGENT_RUN.md.

Usage:
  python -m scripts.score_agent_attribution \
      --report data/attribution_report.json --gt data/ground_truth.json
  python -m scripts.score_agent_attribution \
      --report data/scenario2/attribution_report.json \
      --gt data/scenario2/ground_truth.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def base(t: str | None) -> str:
    return (t or "").split(".")[0].strip().upper()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", type=Path, default=Path("data/attribution_report.json"))
    ap.add_argument("--gt", type=Path, default=Path("data/ground_truth.json"))
    args = ap.parse_args()

    rep = json.loads(args.report.read_text())
    gt = json.loads(args.gt.read_text())

    # ground truth: malicious event_id -> base technique
    gt_ev = {
        e["event_id"]: base(e.get("mitre_technique"))
        for e in gt.get("events", [])
        if e.get("mitre_technique")
    }
    gt_techs = sorted(set(gt_ev.values()))

    # agent assertions: (event_id, technique)
    rows = [
        (ev, base(t.get("technique_id")))
        for t in rep.get("attribution", {}).get("techniques", [])
        for ev in t.get("event_ids", [])
    ]
    agent_techs = sorted({tid for _, tid in rows})
    cited_events = {e for e, _ in rows}

    named_in_gt = sorted(set(agent_techs) & set(gt_techs))
    cited_mal = [(e, tid) for e, tid in rows if e in gt_ev]
    correct = [(e, tid) for e, tid in cited_mal if tid == gt_ev[e]]

    print(f"report            : {args.report}  (mode={rep.get('mode')})")
    print(f"GT malicious events: {len(gt_ev)}   distinct techniques: {gt_techs}")
    print(f"agent techniques   : {agent_techs}")
    print(f"agent cited events : {len(cited_events)} distinct")
    print("-" * 60)
    print(f"technique-SET  : {len(named_in_gt)}/{len(gt_techs)} GT techniques named  {named_in_gt}")
    print(f"per-EVENT      : {len(cited_mal)} cited events are GT-malicious; "
          f"{len(correct)} technique-correct  << the honest number")
    if not cited_mal:
        print("               (agent grounded 0 citations on malicious events — "
              "see docs/LIVE_AGENT_RUN.md 'Why / the fix')")


if __name__ == "__main__":
    main()
