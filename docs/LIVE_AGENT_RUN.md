# PRAHARÍ — Live Agent Run (evidence)

**Status: the tool-using Claude attribution agent has been run live and end-to-end.**
This is the proof artifact for what earlier docs listed as *"live agent — PENDING."*

The runtime `data/…/attribution_report.json` files are gitignored (they are
regenerated artifacts), so the two live runs below are transcribed here verbatim
from the captured run logs and reports.

## How it ran without an `ANTHROPIC_API_KEY`

The build environment has no API key. Rather than leave the live tool-use loop
unverified, the agent gained a second transport that reuses an existing **Claude
Code subscription** through the local `claude` CLI in headless mode:

```bash
make attribute-agent-live      # controlled APT scenario   (INC-001)
make scenario2-agent-live      # held-out insider scenario (no external C2)
```

- Same **tools** (`get_incident_events`, `get_graph_context`, `search_attack_kb`,
  `lookup_technique`, `submit_attribution`), same **cite-or-abstain** system
  prompt, same **no-ground-truth** guarantee (`gt_*` never enters a tool result),
  and the same `TOOL_DISPATCH` used by the Messages-API path (`run_live`).
- Transport is JSON-over-text with session `--resume` for continuity. The child
  CLI is launched with `--tools ""` (its own Bash/Read tools stripped, so it acts
  purely as our protocol endpoint) and `ANTHROPIC_API_KEY` scrubbed from its env.
- Reported `mode = live-cc`, `model = claude-sonnet-4-6`, run **2026-07-04**.

Implementation: `run_cc()` in `services/attribution/agent.py` (flag `--claude-cli`).
Set `PRAHARI_CC_DEBUG=1` to print the per-turn trace shown below.

---

## Run 1 — controlled APT (`INC-001`)

**Agent investigation (6 tool calls, autonomous):**

| # | tool | argument |
|---|------|----------|
| 1 | `get_incident_events` | `INC-001` |
| 2 | `search_attack_kb` | *"database exfiltration pg_dump exam results theft insider threat lateral movement"* |
| 3 | `get_graph_context` | `DB-EXAMS` |
| 4 | `get_graph_context` | `WS03` |
| 5 | `get_graph_context` | `203.0.113.66` |
| 6 | `submit_attribution` | *(full structured attribution)* |

**Techniques (each cited to specific events — no ground truth seen):**

| Technique | Conf | Grounding (agent's own words, abridged) |
|---|---|---|
| **T1078** Valid Accounts | 0.88 | `db.service` a new user→host pairing on DB-EXAMS (fused 0.98); a service account operating interactively is anomalous |
| **T1021** Remote Services | 0.90 | `exam.clerk` on WS03 (10.10.1.13) directly opens TCP to DB-EXAMS (10.10.0.20) on **5432** — a clerk-role account reaching PostgreSQL |
| **T1005** Data from Local System | 0.85 | `db.service` accesses `results_draft.docx` on DB-EXAMS twice (fused 0.98/0.96) |
| **T1560** Archive Collected Data | 0.87 | `pg_dump` (globally rare, previously unseen on DB-EXAMS) invoked repeatedly, serialising the database |
| **T1071** Application Layer Protocol | 0.68 | external `203.0.113.66` → WS03 on **443** on 2026-05-02 (anomaly 0.996, fused 1.0) early in the campaign |
| **T1041** Exfiltration Over C2 | 0.72 | `203.0.113.66` → DB-EXAMS on 443 at 2026-05-21T03:05, matching the incident exfil window |

**Kill chain:** T1078 → T1005 → T1021 → T1560 → T1071 → T1041
**Predicted next moves:** T1565 Data Manipulation · T1078 (admin.it expansion) · T1070 Indicator Removal · T1567 Exfiltration Over Web Service
**Overall confidence:** 0.78 · **RAG citations:** `insider_lowandslow`, `insider_valid_accounts`, `exfiltration`
**Usage:** 6 CLI calls · ~10,969 output tokens

> *Campaign:* "A low-and-slow, 19.74-day insider-assisted campaign targeting an
> academic examination results database (DB-EXAMS)… pivoted laterally into the
> PostgreSQL exam database using direct service-port access, systematically dumped
> it via `pg_dump`/`backup.sh`, and exfiltrated the archive to 203.0.113.66 over
> HTTPS at the campaign's close."

---

## Run 2 — held-out insider, **no external C2** (`scenario2`)

This is the harder, more informative case: a purely-internal insider campaign the
deterministic mapper barely touches. Frozen thresholds, `--no-write` (the
scenario-1 demo graph is never mutated).

**Agent investigation (9 tool calls, autonomous):**

`get_incident_events` → `get_graph_context ×3` → `search_attack_kb ×2` →
`lookup_technique ×2` → `submit_attribution`.

**Techniques:**

| Technique | Conf | Grounding (abridged) |
|---|---|---|
| **T1078** Valid Accounts | 0.85 | `db.service` new user-host pairing on DB-EXAMS |
| **T1087** Account Discovery | 0.78 | `data.analyst` on WS05 repeated LDAP queries (**389**) to the domain controller |
| **T1021** Remote Services | 0.72 | `data.analyst` WS05 (10.10.1.15) → 10.10.0.10 over **445** (SMB/CIFS) |
| **T1213** Data from Information Repositories | 0.90 | both `db.service` and `data.analyst` accessed `/var/lib/exam-records/…` |
| **T1005** Data from Local System | 0.88 | `pg_dump` — previously-unseen, globally-rare process under `db.service` |
| **T1074** Data Staged | 0.68 | `backup.sh` executed 5+ times alongside `pg_dump` |
| **T1567** Exfiltration Over Web Service | 0.78 | `onedrive.exe` — previously-unseen process on WS05 under `data.analyst` |

**Kill chain:** T1078 → T1087 → T1021 → T1213 → T1005 → T1074 → T1567
**Predicted next moves:** T1565 Data Manipulation · T1070 Indicator Removal · T1531 Account Access Removal · T1567 (continued)
**Overall confidence:** 0.80 · **RAG citations:** `insider_valid_accounts`, `insider_lowandslow`, `data_staging`, `account_discovery`
**Usage:** 9 CLI calls · ~8,562 output tokens

> *Threat profile (agent):* "High-confidence insider threat… demonstrates
> operational-security awareness (scores kept low, legitimate tooling used
> throughout — `pg_dump`, OneDrive, `winword.exe`), knowledge of internal network
> topology (direct DB access, LDAP enumeration), and patience (24+ day campaign)."

Why this matters: with **no external C2 to key on**, the agent still reconstructed
the full coordinated-insider chain across **two** accounts and correctly flagged
**OneDrive as the covert exfiltration channel (T1567)** — grounded in behavioural
novelty, not signatures, and citing the retrieved insider-threat advisories.

---

## Honesty notes

- These are **live-cc** runs (subscription CLI). The Messages-API transport
  (`run_live`, triggered by a real `ANTHROPIC_API_KEY` via `make attribute-agent`)
  shares the identical tools, prompt, and dispatch — the CLI transport exercises
  that same loop and contract.
- Reproducibility caveat: an LLM agent is not bit-deterministic like the frozen
  UEBA/graph core. Tool *inputs* are deterministic (seeded scenarios); the agent's
  wording and confidences vary run-to-run. The **deterministic mapper** (92.3%
  exact on the controlled scenario) remains the reproducible attribution number;
  the agent adds narrative, RAG-cited reasoning, and next-move prediction — most
  valuable exactly where the mapper is weakest (the held-out insider case).
- Wall-clock: each run is a handful of CLI round-trips; the final
  `submit_attribution` turn dominates (large structured payload generation).
