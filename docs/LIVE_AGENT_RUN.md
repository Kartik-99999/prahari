# PRAHARÍ — Live Agent Run (evidence + honest scoring)

**What is proven here:** the tool-using Claude attribution agent **runs live and
end-to-end** — a real multi-call tool-use investigation through a Claude Code
subscription, no `ANTHROPIC_API_KEY`. This closes the earlier *"live agent —
PENDING"* status.

**What is *not* claimed here:** that the live agent beats the deterministic mapper
on accuracy. We **scored both live runs against ground truth** (below) and the
result is humbling and reported straight: the agent writes a fluent, mostly-correct
technique *narrative*, but its per-event **evidence citations land on benign
context events, not the malicious ones** — so the reproducible attribution *number*
remains the **deterministic mapper (92.3% exact on the controlled scenario, §3 of
`RESULTS.md`)**. The agent's demonstrated value is (a) it runs the live loop and
(b) it surfaces the right entities + a mostly-correct technique set as a readable
brief — not verified per-event precision.

The runtime `data/…/attribution_report.json` files are gitignored (regenerated
artifacts); the runs below are transcribed from the captured logs/reports, and the
scoring is reproducible from those reports + the scenarios' `ground_truth.json`.

## How it ran without an `ANTHROPIC_API_KEY`

```bash
make attribute-agent-live      # controlled APT scenario   (INC-001)
make scenario2-agent-live      # held-out insider scenario (no external C2)
```

- Same **tools** (`get_incident_events`, `get_graph_context`, `search_attack_kb`,
  `lookup_technique`, `submit_attribution`), same **cite-or-abstain** prompt, same
  **no-ground-truth** guarantee (`gt_*` never enters a tool result), same
  `TOOL_DISPATCH` as the Messages-API path (`run_live`).
- Transport is JSON-over-text with session `--resume`. The child CLI runs with
  `--tools ""` (its own Bash/Read stripped, so it is purely our protocol endpoint)
  and `ANTHROPIC_API_KEY` scrubbed from its env. `mode = live-cc`,
  `model = claude-sonnet-4-6`, run **2026-07-04**.

Implementation: `run_cc()` in `services/attribution/agent.py` (`--claude-cli`).
`PRAHARI_CC_DEBUG=1` prints the per-turn trace.

---

## Run 1 — controlled APT (`INC-001`)

**Autonomous investigation (6 tool calls):**
`get_incident_events(INC-001)` → `search_attack_kb("database exfiltration pg_dump
… lateral movement")` → `get_graph_context(DB-EXAMS / WS03 / 203.0.113.66)` →
`submit_attribution`. Usage: 6 CLI calls · ~10,969 output tokens.

**Techniques it named:** T1078, T1021, T1005, T1560, T1071, T1041.
**Kill chain:** T1078 → T1005 → T1021 → T1560 → T1071 → T1041.
**Predicted next moves:** T1565, T1078 (admin.it), T1070, T1567.

## Run 2 — held-out insider, **no external C2** (`scenario2`, `--no-write`)

**Autonomous investigation (9 tool calls):** `get_incident_events` →
`get_graph_context ×3` → `search_attack_kb ×2` → `lookup_technique ×2` →
`submit_attribution`. Usage: 9 CLI calls · ~8,562 output tokens.

**Techniques it named:** T1078, T1087, T1021, T1213, T1005, T1074, T1567.
**Kill chain:** T1078 → T1087 → T1021 → T1213 → T1005 → T1074 → T1567.
Narrative correctly identified the two insider accounts (`db.service`,
`data.analyst`), `pg_dump`, `backup.sh`, and OneDrive, and a coherent ~25-day
low-and-slow campaign — a genuinely readable brief.

---

## Scored against ground truth (the honest part)

Method (offline, reproducible): join each `submit_attribution` technique's cited
`event_ids` to the scenario's `ground_truth.json`, using the same **per-malicious-
event** basis as the deterministic mapper's documented **2/45**.

| Metric | Scenario-1 (APT) | Scenario-2 (insider) |
|---|---|---|
| GT distinct techniques | 6 (T1003,T1021,T1041,T1078,T1560,T1566) | 6 (T1005,T1052,T1074,T1078,T1087,T1560) |
| Agent distinct techniques **named** that are in GT | **4 / 6** (T1021,T1041,T1078,T1560) | **4 / 6** (T1005,T1074,T1078,T1087) |
| Distinct events the agent **cited** | 17 | 22 |
| …of those, that are actually **malicious** in GT | **0** | **0** |
| Per-event technique matches (mapper-comparable) | **0** | **0** |

**Reading this straight:** at the *technique-set* level the agent is respectable
(4/6 correct technique names in each scenario). At the *evidence* level it fails:
**every** cited event is a benign "routine process" / "file access" event, not one
of the anomaly-labelled malicious events. The incident it investigated *does*
contain malicious events (scenario-2 INC-001 = 23 malicious of 124, 19%), but the
agent grounded its techniques on the surrounding benign context instead. Spot-check:
the events it described as "`pg_dump`" and "`onedrive.exe`" resolve to
`is_malicious=False`.

So the agent **does not** beat the mapper's 2/45 — measured the same way it grounds
**0** malicious events in either scenario.

### Why (root cause) and the fix

`get_incident_events` / `get_graph_context` return the incident's events and graph
neighbourhood **without ranking by `anomaly_score`/`fused_score`**, so the malicious
needles are diluted by benign context. The model then narrates from salient
*entity/process names* and attaches technique labels to whatever event IDs are in
view — which skew benign. This is a **citation-grounding** gap, not a detection
gap (UEBA + fusion still isolate the malicious events; ROC 0.9987 on scenario-2).
Concrete fix, not yet implemented: have the incident/graph tools return events
**sorted by the system's own anomaly/fused score** (and expose that score to the
agent) so cite-or-abstain pins to the events the detector already flagged; then
re-score per-event precision. Tracked as the top attribution follow-up.

## Bottom line

- **Live loop:** works, no API key — real and demo-ready (● LIVE badge).
- **Narrative / technique-set:** useful, 4/6 correct technique names per scenario.
- **Per-event attribution accuracy:** **the deterministic mapper (92.3%) remains
  the only defensible number**; the live agent's citations are not yet
  ground-truth-faithful. Reported honestly rather than dressed up as a win.
