# PRAHARÍ — Live Agent Run (measured, with the fix that made it real)

**Two things are proven here, both by measurement against ground truth:**

1. The tool-using Claude attribution agent **runs live end-to-end** through a
   Claude Code subscription — a real multi-call tool-use investigation, **no
   `ANTHROPIC_API_KEY`**. This closed the earlier *"live agent — PENDING."*
2. After an honest first scoring exposed a **citation-grounding bug** (the agent
   cited *benign* events), we fixed the root cause and re-measured. It now grounds
   its attribution on the **actually-malicious** events — and on the held-out
   insider scenario it correctly attributes **20 malicious events vs the
   deterministic mapper's 2** (the 2/45 gap), measured, not eyeballed.

Everything below is reproducible: `make attribute-agent-live` /
`make scenario2-agent-live` to run, `make score-agent` to score.

## Transport (no API key)

Same **tools** (`get_incident_events`, `get_graph_context`, `search_attack_kb`,
`lookup_technique`, `submit_attribution`), same **cite-or-abstain** prompt, same
**no-ground-truth** guarantee (`gt_*` never in a tool result), same `TOOL_DISPATCH`
as the Messages-API path. The child CLI runs with `--tools ""` (its own Bash/Read
stripped) and `ANTHROPIC_API_KEY` scrubbed; JSON-over-text with session `--resume`;
transient CLI errors are retried. `mode = live-cc`, `model = claude-sonnet-4-6`.
Implementation: `run_cc()` in `services/attribution/agent.py` (`--claude-cli`).

## The bug we caught by scoring (and why honesty paid off)

The first live runs produced fluent, right-sounding narratives — so at a glance
they looked great. Scoring the cited `event_ids` against ground truth told the
real story: **0 of 17 (scenario-1) and 0 of 22 (scenario-2) cited events were
actually malicious.** Root cause: `get_incident_events` returned the incident's
events **in timestamp order**, and the tool-result was **truncated at 12k chars** —
so on a 124-event incident the model only ever saw the earliest ~40 (benign, day-1
baseline) events; the later malicious events were literally cut off. It then
narrated from process/entity names and cited whatever benign context was in view.

## The fix

- `get_incident_events` now returns events **ranked by the system's own
  `fused_score`/`anomaly_score`** (most anomalous first), each tagged with
  `anomaly_rank` + score, capped to top-K (default 60).
- Tool-result char budget raised so the ranked set is never truncated.
- System prompt instructs: *ground every technique in HIGH-anomaly events; do not
  cite low-score baseline events as evidence.*
- Offline check confirmed the ranked top-K surfaces **100 %** of each incident's
  malicious events (scenario-1 13/13, scenario-2 23/23) before any live re-run.

## Scored against ground truth — before vs after the fix

Per-event basis = the same per-malicious-event measure as the mapper's **2/45**.

| Metric | Scenario-1 (APT) | Scenario-2 (insider) |
|---|---|---|
| GT distinct techniques | 6 | 6 |
| Agent techniques in GT — **before → after** | 4/6 → **6/6** | 4/6 → **4/6** |
| Citations landing on a **malicious** event — **before → after** | 0 → **17 / 21** | 0 → **24 / 25** |
| **Per-event technique-correct — before → after** | 0 → **11** | 0 → **20** |
| Deterministic mapper, same scenario (reference) | 12/13 | **2/45** |

**Scenario-1 highlights (after):** T1021 lateral-movement 4/4 events exact,
T1003 credential-dumping 2/2 (a technique it *missed* before the fix), T1560
archive 2/2, T1041 exfiltration 2/2, all 6 GT techniques recovered.

**Scenario-2 highlight (after):** **T1005 data-from-local-system — 18/18 events
correct**, the core `pg_dump` data-theft of the insider campaign; plus T1078 and
T1074 exact. 20 correct malicious attributions where the deterministic mapper
manages 2. This is the head-to-head win the fallback mapper cannot deliver on the
held-out insider case — and it is a *measured* number.

## Honest residuals (still true)

- Not every citation is exact: scenario-1 has 11 exact of 21 citation-pairs,
  scenario-2 20 of 25. Some techniques are grounded on a malicious event but with
  a defensible-adjacent label (e.g. T1071 for a C2 beacon GT labels T1566); a few
  low-confidence "extra" techniques remain. Confidences track this (the agent
  drops to 0.5 when hedging).
- Scenario-2 still names 4/6 distinct GT techniques (misses T1052 physical-media
  exfil and, this run, T1087). The agent addresses the top incident's events, not
  all 45 malicious events fleet-wide.
- An LLM agent is not bit-reproducible; wording/confidences vary run-to-run. The
  **deterministic mapper (92.3%) stays the stable, reproducible attribution
  number**; the agent's contribution is now a *grounded* narrative + next-move
  prediction that measurably beats the mapper on the hard insider case.

## Bottom line

Runs live with no key; **caught its own grounding failure by scoring; fixed it; and
now grounds on the malicious events — 20 correct insider attributions vs the
mapper's 2.** Reported with the before/after so the rigor is visible, not hidden.
