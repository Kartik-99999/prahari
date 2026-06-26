#!/usr/bin/env python3
"""Prahari attribution accuracy evaluation.

Reads gt_technique ONLY here. Compares the deterministic mapper's
inferred_technique against ground truth for the 13 malicious events and reports
technique-level accuracy, precision over labeled events, and the benign
false-attribution count. Flags "defensible adjacent" mismatches (behaviourally
correct but labelled under a different kill-chain stage by the scenario).
"""

from __future__ import annotations

import json
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
INCIDENTS = _REPO_ROOT / "data" / "incidents.json"
GT = _REPO_ROOT / "data" / "ground_truth.json"
ATTRIBUTION_REPORT = _REPO_ROOT / "data" / "attribution_report.json"

# Behaviourally-defensible adjacencies: the mapper sees a real technique, but the
# scenario labels that event under a different (stage-level) technique.
ADJACENT = {
    frozenset({"T1071", "T1566"}),  # C2 beacon vs the phishing stage that launched it
    frozenset({"T1059", "T1566"}),  # interpreter execution vs the phishing stage
    frozenset({"T1071", "T1041"}),  # C2 channel vs exfil over that channel
    frozenset({"T1005", "T1560"}),  # collecting local data vs archiving it
}


def main() -> None:
    incidents = json.loads(INCIDENTS.read_text())
    top = incidents[0]
    inferences = top.get("event_inferences", {})
    gt = json.loads(GT.read_text())
    gt_events = {e["event_id"]: e for e in gt["events"]}

    print("=" * 72)
    print(f"  ATTRIBUTION ACCURACY — top incident {top['id']}")
    print("=" * 72)
    print(f"  {'stage':<6}{'activity':<9}{'gt_technique':<14}{'inferred':<12}match")
    print("  " + "-" * 50)

    exact = adjacent = 0
    rows = sorted(gt_events.values(), key=lambda e: (e["attack_stage"], e["timestamp"]))
    for e in rows:
        eid = e["event_id"]
        gt_t = e["mitre_technique"]
        inf = inferences.get(eid, {})
        inf_t = inf.get("inferred_technique")
        if inf_t == gt_t:
            flag, _ = "match ✓", exact
            exact += 1
        elif inf_t and frozenset({inf_t, gt_t}) in ADJACENT:
            flag = "~adjacent"
            adjacent += 1
        elif inf_t:
            flag = "MISS ✗"
        else:
            flag = "(none) ✗"
        print(
            f"  {e['attack_stage']:<6}{e['activity']:<9}{gt_t:<14}"
            f"{str(inf_t):<12}{flag}"
        )

    n = len(rows)
    accuracy = exact / n
    print("\n  " + "-" * 50)
    print(f"  technique-level accuracy (exact)   : {exact}/{n} = {accuracy:.3f}")
    print(
        f"  + defensible-adjacent              : {adjacent}/{n} "
        f"(=> {(exact + adjacent)}/{n} = {(exact + adjacent) / n:.3f} incl. adjacent)"
    )

    # precision over ALL events the mapper labeled (across the whole incident)
    labeled = {eid: v for eid, v in inferences.items() if v.get("inferred_technique")}
    correct = sum(
        1
        for eid, v in labeled.items()
        if eid in gt_events
        and v["inferred_technique"] == gt_events[eid]["mitre_technique"]
    )
    benign_labeled = [eid for eid in labeled if eid not in gt_events]
    precision = correct / len(labeled) if labeled else 0.0
    print(f"  events labeled with a technique    : {len(labeled)}")
    print(
        f"  precision (exact gt match / labeled): {correct}/{len(labeled)} "
        f"= {precision:.3f}"
    )
    print(f"  benign-in-incident false-attributions: {len(benign_labeled)}")

    if adjacent:
        print(
            "\n  Defensible-adjacent mismatches (behaviourally correct, different "
            "stage label):"
        )
        for e in rows:
            inf_t = inferences.get(e["event_id"], {}).get("inferred_technique")
            if (
                inf_t
                and inf_t != e["mitre_technique"]
                and frozenset({inf_t, e["mitre_technique"]}) in ADJACENT
            ):
                print(
                    f"    stage {e['attack_stage']} {e['activity']}: inferred "
                    f"{inf_t} vs gt {e['mitre_technique']} — "
                    f"{inferences[e['event_id']]['inferred_rationale'].split(';')[0]}"
                )

    # --- agent comparison (if the agent has produced a report) -------------
    if ATTRIBUTION_REPORT.exists():
        compare_agent(gt_events, inferences, exact, n)


def compare_agent(gt_events: dict, inferences: dict, det_exact: int, n: int) -> None:
    report = json.loads(ATTRIBUTION_REPORT.read_text())
    mode = report.get("mode", "?")
    # event_id -> agent technique
    agent_by_event: dict[str, str] = {}
    for t in report.get("attribution", {}).get("techniques", []):
        for eid in t.get("event_ids", []):
            agent_by_event[eid] = t["technique_id"]

    print("\n" + "=" * 72)
    print(f"  AGENT vs GROUND TRUTH vs DETERMINISTIC   (agent mode: {mode})")
    print("=" * 72)
    print(
        f"  {'stage':<6}{'gt':<8}{'deterministic':<15}{'agent':<10}"
        f"{'agent✓':<8}agree?"
    )
    print("  " + "-" * 56)

    agent_exact = agent_adjacent = agree = added = 0
    rows = sorted(gt_events.values(), key=lambda e: (e["attack_stage"], e["timestamp"]))
    for e in rows:
        eid = e["event_id"]
        gt_t = e["mitre_technique"]
        det_t = inferences.get(eid, {}).get("inferred_technique")
        ag_t = agent_by_event.get(eid)
        # parent-level comparison (agent may emit a sub-technique as added insight)
        ag_parent = ag_t.split(".")[0] if ag_t else None
        if ag_parent == gt_t:
            agent_exact += 1
            ok = "✓"
            if ag_t and "." in ag_t:
                added += 1  # richer sub-technique beyond coarse gt
        elif ag_t and frozenset({ag_parent, gt_t}) in ADJACENT:
            agent_adjacent += 1
            ok = "~adj"
        else:
            ok = "✗"
        agreement = (
            "="
            if ag_parent and ag_parent == (det_t.split(".")[0] if det_t else None)
            else "≠"
        )
        if agreement == "=":
            agree += 1
        print(
            f"  {e['attack_stage']:<6}{gt_t:<8}{str(det_t):<15}{str(ag_t):<10}"
            f"{ok:<8}{agreement}"
        )

    print("\n  " + "-" * 56)
    print(f"  deterministic baseline (exact)  : {det_exact}/{n} = {det_exact / n:.3f}")
    print(
        f"  agent technique-accuracy (exact): {agent_exact}/{n} = {agent_exact / n:.3f}"
        f"  (+{agent_adjacent} defensible-adjacent)"
    )
    print(f"  agent–deterministic agreement   : {agree}/{n} = {agree / n:.3f}")
    print(f"  agent added-insight (sub-techniques beyond coarse gt): {added}")
    if mode == "fallback":
        print(
            "  NOTE: fallback mode mirrors the deterministic mapper (no API key), "
            "so\n        agent==deterministic by construction. Add ANTHROPIC_API_KEY "
            "for an\n        independent live-agent comparison."
        )
    oc = report.get("attribution", {}).get("overall_confidence")
    print(f"  agent overall_confidence        : {oc}")


if __name__ == "__main__":
    main()
