# PRAHARÍ — Hackathon Submission Brief & Document-Generation Spec

> **READ THIS FIRST.** This file is a complete, self-contained source of truth. It is meant to be handed to an AI agent that has **no prior context** about this project. It contains (Part 1) every fact about the project and (Part 2) a precise spec for each document to produce. **Use only the facts in this file — do not invent numbers, features, or claims. Preserve every "honest caveat" in §1.8 — do NOT inflate results.** All documents go in the repository unless noted.
>
> Repository: **https://github.com/Kartik-99999/prahari** (branch `main`). Project root referenced as `~/prahari`.

---

# PART 1 — PROJECT DOSSIER (all facts)

## 1.1 Identity
- **Name:** PRAHARÍ (Hindi: "guardian/sentinel"). Style the wordmark with the final **í** in saffron `#FF9933`; rest in white/light.
- **Tagline:** *Behavioural Cyber Resilience for Critical National Infrastructure.*
- **One-line pitch:** An AI platform that detects behavioural anomalies, fuses weak signals across a graph into a single attack chain, maps it to MITRE ATT&CK, and orchestrates auditable autonomous response — compressing detection from **weeks to hours**.
- **Hackathon:** Problem Statement #7 — *AI-Driven Cyber Resilience for Critical National Infrastructure* (Theme: Cybersecurity / Industrial Intelligence / National Security).
- **Judging weights:** Innovation 25% · Business Impact 25% · Technical Excellence 20% · Scalability 15% · User Experience 15%.
- **Evaluation focus (judges measure these explicitly):** anomaly detection rate & false-positive rate on benchmark datasets; APT attribution accuracy at MITRE ATT&CK **technique** level; incident-response automation coverage (% of playbook steps executable autonomously); MTTD/MTTR improvement vs a baseline SOC; full auditability of every automated action.

## 1.2 The problem & context (for Business Impact framing)
- CERT-In handled **1.59M+ cybersecurity incidents in 2023**, climbing through 2024–25.
- **AIIMS Delhi** paralysed 2+ weeks by ransomware (2022); **CBSE** examination-records data breach (2024) and a coordinated attack on CBSE digital infrastructure (early 2026).
- India's National Cyber Security Policy: **70%+ of government entities run end-of-life IT** — attackers don't need to work hard to get in.
- The deeper problem is **detection speed**. APTs run **low-and-slow** to evade signature-based detection. By the time a signature exists, the attack already succeeded. Industry mean dwell time is **~200 days** (Mandiant). What's needed is a **behavioural** intelligence layer that flags deviation from normal, not signature matches.

## 1.3 The solution & thesis
**Thesis: detect behaviour, not signatures.** PRAHARÍ is one closed, fully-auditable loop:

```
Ingest / normalize (OCSF)
  → UEBA unsupervised anomaly scoring (no signatures)
    → Graph weak-signal FUSION (Neo4j provenance graph + "anomaly lift")
      → MITRE ATT&CK attribution + next-move prediction (Claude agents + RAG)
        → SOAR autonomous response w/ blast-radius human-in-the-loop gates
          → Tamper-evident hash-chained audit ledger (every action)
Fronted by: FastAPI BFF + Next.js SOC analyst console (cinematic incident replay)
```
Three pillars: **(1) UEBA** — learn per-entity normal, score deviation unsupervised; **(2) Graph fusion** — connect individually-ignorable weak signals into one ranked attack chain across hosts and days; **(3) Agentic AI** — Claude agents map to ATT&CK, predict the next move, and plan response.

## 1.4 Architecture & tech stack
**Services (Python):** `services/{ingest, ueba, graph, attribution, soar, api}`.
**Data stores:** Neo4j (provenance/entity graph; APOC + Graph-Data-Science plugins) · Redis (event bus, `events:raw` stream, consumer groups for fan-out) · Postgres (tamper-evident audit ledger).
**Agents:** Anthropic SDK tool-use loop. **Two agents** (multi-agent): an **attribution agent** and a **response-planner agent**. Default model `claude-sonnet-4-6` (env `PRAHARI_AGENT_MODEL`; `claude-opus-4-8` optional). Both degrade gracefully to deterministic logic when no `ANTHROPIC_API_KEY` is set.
**RAG / knowledge:** Chroma vector store over MITRE ATT&CK (live STIX bundle, 697 techniques / 222 parent) + 6 representative CERT-In-style advisory snippets (`data/threat_intel/*.md`).
**ML:** scikit-learn + pyod (IsolationForest + ECOD, unsupervised) + streaming novelty features.
**Schema:** OCSF-style `SecurityEvent` (pydantic) — `packages/schema`.
**Frontend:** Next.js 16 (App Router, TypeScript, Tailwind, Turbopack), Cytoscape.js + fcose for the provenance-graph visualization.
**Infra:** Docker Compose (neo4j, redis, postgres). Dev host used Colima as the container runtime (macOS, no Docker Desktop). Postgres published on host port **5433** (to coexist with a local Postgres on 5432).
**Audit:** SHA-256 hash-chained, append-only Postgres table + a BEFORE UPDATE/DELETE trigger that raises (defense-in-depth: prevention + detection).

## 1.5 The synthetic scenario & kill chain
A controllable, labeled scenario (the demo + metrics run on this; see caveats §1.8).
- **Network:** *State Examinations Authority* (CBSE-style). ~8 users (incl. `admin.it` domain admin, `exam.clerk`, `db.service`), ~6 hosts (`WS01–WS04` workstations, `DC01` domain controller, `DB-EXAMS` server hosting the exam-records Postgres), internal `10.10.x.x`, external C2 `203.0.113.66`.
- **Window:** 2026-05-01 → 05-21 (21 days). **2128 events** total = **2115 benign / 13 malicious**. Deterministic (seed=42).
- **Low-and-slow 6-stage APT kill chain:**
  1. **T1566 Phishing** → foothold on WS03 (Word macro spawns PowerShell beacon) — May 2.
  2. **T1078 Valid Accounts** → off-hours (02:13) reused-credential logon — May 4.
  3. **T1003 OS Credential Dumping** (LSASS dump) on WS03 — May 6.
  4. **T1021 Lateral Movement** WS03 → DC01 → DB-EXAMS — May 9 & May 13.
  5. **T1560 Archive Collected Data** (exam-records staged) on DB-EXAMS — May 19.
  6. **T1041 Exfiltration over C2** to the external IP — May 21.
  (Plus **T1071** application-layer C2 observed behaviourally during stage 1.)
- Ground-truth labels travel only in `event.raw["label"]` and are **never** used as detection inputs.

## 1.6 The metrics slate (EXACT — use verbatim)
All numbers computed live from persisted artifacts (`data/metrics_slate.json`), not hardcoded.

| Stage | Metric | Value |
|---|---|---|
| **UEBA (detection)** | ROC-AUC | **0.9988** |
| | PR-AUC | 0.8676 |
| | Recall (detection rate) @ ~1% FPR | **100% (13/13)** |
| | Full recall reached at | 0.66% FPR |
| | Mean anomaly score: malicious vs benign | 0.912 vs 0.243 |
| **Fusion (correlation)** | Dominant incident INC-001 score (vs next) | 34.16 (≈4× next) |
| | Malicious recall in top incident | **13/13** |
| | Weak signals recovered by fusion | **4/4** (0.68–0.75 → ≥0.90) |
| | Incident precision | 21.7% (benign *context*, not false positives) |
| | Lateral path surfaced | WS03 → DC01 → DB-EXAMS |
| **Attribution** | ATT&CK technique accuracy | **92.3% (12/13 exact)** |
| | False attributions | **0** |
| | (the 1 non-exact is defensible-adjacent: T1071 C2 vs stage-label T1566) | |
| **SOAR (response)** | Automation coverage | **75% (6 auto / 2 human-gated)** |
| **MTTD** | Confirmed detection after foothold | **1.66 days** |
| | Lead before exfil | 17 days |
| | vs industry mean dwell | ~200 days |
| **MTTR** | Automated containment latency once confirmed | **<1s (0.0043s)** |
| **Auditability** | Hash chain | 10 entries, verified ✓, append-only, tamper-detected at exact seq |

**Counterfactual headline:** containment fires on day **1.7** (May 4), severing C2 **17 days before** the May-21 exfil → **the breach is prevented.**

## 1.7 Engineering & integrity differentiators (these win Technical Excellence / trust)
- **Honest-viz:** the console graph colors/sizes edges by the system's **own `anomaly_score`** (gt-free). The ground-truth "malicious" flag is only an opt-in, clearly-labeled **"eval only"** overlay — never the default. The attack *emerges* from what the system computed.
- **No label leakage:** detection never uses ground-truth labels OR the synthetic `severity` field (a planted proxy); agents never receive `gt_*`. Enforced in code by an `assert_no_leakage` guard.
- **Platform-enforced gates:** the response-planner **proposes** `{action, target, rationale}`; the **platform** computes blast-radius and the gate decision — so the AI **cannot weaken or bypass a human gate.**
- **Fusion = "anomaly lift":** `fused = personalized_PageRank / uniform_PageRank` over an event-similarity graph — divides out benign-hub bias so weak-but-connected malicious events rise.
- **Tamper-evident audit:** SHA-256 prev-hash chain + DB append-only trigger; a privileged insider who rewrites one row is caught by `verify_chain()` at the exact entry.

## 1.8 HONEST CAVEATS (MANDATORY — every document must preserve these; do not hide or inflate)

> **UPDATE (2026-07-02) — read before applying caveat 1.** The G1–G6 work (commits `73ede5a`…`604a9f6`) has **superseded caveat 1**: the CIC-IDS-2017 public benchmark is now DONE (macro ROC-AUC **0.845**; DDoS 0.910 with 84.6% det@10%FPR), plus held-out generalization with frozen thresholds (ROC 0.9987, 100% recall@1%FPR), an OT/Modbus scenario (ROC 0.792, 3/4 ICS techniques), a 1M-event scale benchmark (~54k ev/s), and an adversarial probe — all in `docs/RESULTS.md`, all independently re-verified (`VERIFICATION_REPORT.md`). Documents should cite those results. **Caveat 2 updated** (2026-07-04): the live agent now *runs* end-to-end via the subscription CLI, but honest scoring shows its per-event citations land on benign events — the deterministic mapper stays the accuracy number (see updated caveat 2 and `docs/LIVE_AGENT_RUN.md`). Caveats 3–4 remain true. The "controlled scenario vs benchmark — never conflate" rule still applies verbatim.

1. **Results are on a synthetic, controlled scenario** (13 malicious events in a self-built dataset), **not yet a public benchmark.** The near-perfect numbers reflect a clean scenario. The planned next step is a **CICIDS-2017** run for a defensible benchmark number. Frame synthetic metrics as "controlled scenario" and never imply they are benchmark results. *(See UPDATE above — this step is now complete.)*
2. **The live Claude attribution agent runs end-to-end** (2026-07-04) on both scenarios through the Claude Code **subscription CLI** (`make attribute-agent-live`), so **no `ANTHROPIC_API_KEY` was required** — a real 6–9-call tool-use investigation. **Scored against ground truth (honest):** it names 4/6 distinct GT techniques per scenario but grounds its per-event citations on **benign** context events (0 malicious cited in either scenario), so it does **not** beat the deterministic mapper — the **92.3% mapper stays the accuracy number**, and citation-grounding (rank incident events by `anomaly_score`) is the top follow-up. Transcripts + scoring in `docs/LIVE_AGENT_RUN.md`. (This supersedes the earlier "single live run pending," and corrects an interim overclaim that the agent "recovered the 2/45 gap.")
3. **OT/ICS is represented synthetically** — no real OT hardware integration.
4. **Depth over breadth:** one fully-worked incident/scenario, not a broad fleet.
State these as honest scope boundaries + roadmap, not as failures.

## 1.9 Repository structure & how to run
```
~/prahari
├── docker-compose.yml          # neo4j (+apoc,gds) · redis · postgres(:5433)
├── Makefile                    # all pipeline + app targets
├── pyproject.toml              # Python deps (uv/venv)
├── .env.example                # copy to .env (NEO4J_AUTH, POSTGRES_*, REDIS_URL, ANTHROPIC_API_KEY)
├── packages/{schema, scenario, attack_subset.json}
├── services/{ingest, ueba, graph, attribution, soar, api}
├── console/                    # Next.js SOC console (Cytoscape graph, ATT&CK frame, replay)
├── data/{README.md, threat_intel/*.md}   # advisories tracked; events/ground-truth/attack bundle gitignored
├── docs/                       # console_graph.png, console_attack.png, replay_1..3.png, ueba_roc_pr.png, architecture.md, graph_model.md
└── scripts/                    # health_check, api_smoke, audit_tamper_demo, ...
```
**Run:** `cp .env.example .env` → `make up` (start infra) → `make health` (expect Neo4j/Redis/Postgres OK).
**Pipeline (deterministic):** `make graph-load` → `make ueba-score` → `make ueba-eval` → `make fuse` → `make incidents` → `make incidents-eval` → `make attack-kb` → `make attribute-baseline` → `make attribute-eval` → (optional, with key) `make attribute-agent` → `make respond` → `make audit-verify` → `make audit-tamper-demo` → `make loop-summary`.
**App:** `make api` (FastAPI on :8000) + in `console/`: `npm install && npm run dev` (Next.js on :3000). Console "Demo mode" gives a clean 16:9 capture; replay plays at 1×/4×/12×.

## 1.10 Available assets (reference these in docs; don't recreate)
- **Screenshots** in `docs/`: `console_graph.png` (provenance graph), `console_attack.png` (ATT&CK frame), `replay_1/2/3.png` (replay at foothold/confirmed/end), `ueba_roc_pr.png` (ROC/PR curves).
- **Designed pitch deck:** `~/Downloads/PRAHARI_Pitch_Deck_DESIGNED.pptx` (12 slides, embeds the screenshots).
- **Metrics:** `data/metrics_slate.json` (regenerate via `make loop-summary`).
- **Architecture notes:** `docs/architecture.md`, `docs/graph_model.md`.

## 1.11 BFF API surface (for API doc)
FastAPI on `:8000`, CORS for `:3000`. Strips all `gt_` from responses.
- `GET /api/health` · `GET /api/metrics/slate` · `GET /api/incidents` · `GET /api/incidents/{id}` · `GET /api/incidents/{id}/graph` (nodes+edges for viz) · `GET /api/incidents/{id}/playbook` · `POST /api/incidents/{id}/actions/{idx}/decision` (approve/deny → appends a real audit-ledger entry) · `GET /api/audit` (entries + `verify_chain` result).

---

# PART 2 — DOCUMENTS TO PRODUCE

Produce these as Markdown files in the repo (unless noted). Priority: **P0 = must-have for submission**, P1 = high value, P2 = nice-to-have. Use facts from Part 1 only. Keep the honest caveats (§1.8).

## 2.1 `README.md` — repo front door  **[P0]**
Audience: judges opening the repo first. ~1–2 screens, scannable.
Sections: project name + tagline (§1.1) → one-paragraph problem (§1.2) → the closed-loop diagram block (§1.3) → a **Results** table (lift the §1.6 table; add the "controlled scenario" caveat inline) → **Architecture** (one image: embed `docs/architecture` diagram or `docs/console_graph.png`; bullet the stack §1.4) → **Quickstart** (§1.9 run steps) → **What makes it different** (§1.7, 4 bullets) → **Honest scope & roadmap** (§1.8) → repo map (§1.9 tree) → license/team placeholder. Embed 2–3 `docs/*.png` screenshots. Badges optional (Python, Next.js, Neo4j).

## 2.2 `docs/ARCHITECTURE.md` — architecture document  **[P0]**
The 6-stage loop in depth: per stage describe inputs, what it does, the datastore, and outputs (§1.3–1.4). Include the event flow (`events:raw` Redis stream → consumer groups). Explain the integrity guardrails (§1.7). Reference the OCSF `SecurityEvent` schema. Include/point to the architecture diagram image. End with the deployment view (Docker Compose, the three datastores, the BFF+console).

## 2.3 `docs/TECHNICAL_DESIGN.md` — technical deep-dive / whitepaper  **[P1]**
The "how it actually works" doc. Cover, with specifics from Part 1: (a) UEBA — features (temporal/novelty/structural), unsupervised IsolationForest+ECOD + streaming novelty, the `anomaly_score = 0.5·model + 0.5·novelty` blend, and the **no-leakage** discipline; (b) Graph model — node/edge types, the `:REACHED` lateral-movement projection; (c) **Fusion** — the personalized-PR "anomaly lift" and why naive PageRank fails; (d) Incident assembly + scoring; (e) Attribution — ATT&CK KB + RAG + the deterministic mapper (92.3%) + the live agent (tools, cite-or-abstain, gt-free); (f) SOAR — connectors, blast-radius, **platform-enforced** gates; (g) Audit — hash-chain construction + append-only trigger + tamper detection. Note design decisions and trade-offs.

## 2.4 `docs/RESULTS.md` — evaluation report  **[P0]**
The metrics slate (§1.6 table verbatim) + **methodology** for each judge metric (how detection rate/FPR, ATT&CK accuracy, automation coverage, MTTD/MTTR, auditability are computed). Include the counterfactual (§1.6). **Lead with the §1.8 caveat** that these are controlled-scenario results and CICIDS-2017 is the planned benchmark. Reference `docs/ueba_roc_pr.png`. Explain incident precision 21.7% honestly (benign *context* on compromised hosts, not false positives).

## 2.5 `docs/API.md` — BFF reference  **[P2]**
Document each endpoint in §1.11: method, path, purpose, a sample JSON shape, and that `gt_` is stripped. Note the POST decision endpoint writes a real audit entry.

## 2.6 `docs/SETUP.md` — run guide  **[P1]** (or fold into README)
Prereqs (Docker/Colima, Python 3.11+, Node 20+), the §1.9 run steps, the `.env` keys, troubleshooting (port 5433 coexistence; `make health`), and the optional live-agent step (`ANTHROPIC_API_KEY` → `make attribute-agent`).

## 2.7 `docs/DEMO_SCRIPT.md` — demo video script + shot list  **[P0]**
Use this verbatim narrative (~2.5 min, replay at 4×); format it as a table/script:
- **[0:00–0:20] Problem:** CERT-In 1.59M incidents; CBSE breach; 200+-day dwell — "by the time a signature exists, the attack already succeeded."
- **[0:20–0:35] Setup:** the console; "behavioural, not signatures"; hit Play (4×).
- **[0:35–1:00] Attack unfolds:** graph reveals; phishing foothold, 2am reused credential, memory dump — weak signals a SOC ignores; the graph fuses them; WS03→DC01→DB-EXAMS lights up.
- **[1:00–1:12] Detection:** CONFIRMED at May 4 — "1.7 days after foothold, 17 days before exfil."
- **[1:12–1:35] Attribution:** ATT&CK frame; "92.3% technique accuracy"; predicts T1070 log-wiping + T1486 ransomware before they happen.
- **[1:35–2:00] Response:** auto-contain (sever C2) in milliseconds; 2 high-impact actions need one-click human approval; "the May-21 exfil never completes — breach prevented."
- **[2:00–2:20] Trust:** the audit ledger; a tampered row breaks the chain at the exact entry.
- **[2:20–2:35] Close:** metrics ribbon; "detection in hours, not months."
**Shot-list notes:** before recording set `ANTHROPIC_API_KEY` + `make attribute-agent && make respond` so the agent badge shows ● LIVE; capture 1920×1080, Demo mode; flip the "ground-truth overlay (eval only)" toggle while saying "the system is never told which events are malicious"; for the tamper beat run `make audit-tamper-demo`. Calm SOC-operator voice, not hype.

## 2.8 `SUBMISSION.md` — hackathon-portal answers  **[P0]**
Ready-to-paste answers for typical submission fields, each tuned to the judging weight in parentheses:
- **Problem statement** (Impact, §1.2) · **Solution summary** (§1.3) · **Innovation / what's novel** (Innovation — §1.7: graph anomaly-lift + agentic attribution + platform-enforced gates) · **Business impact** (Impact — the weeks-to-hours + breach-prevented counterfactual + India fit) · **Technical approach & stack** (§1.4) · **What we built** (the working closed loop + console) · **Results** (§1.6 + caveat) · **Scalability** (Docker, streaming consumer-group fan-out, IT+OT via OCSF, designed for end-of-life infra) · **Challenges & honest limitations** (§1.8) · **Future scope** (see 2.9) · **Demo + repo links** (repo URL §1; deck; video). Keep each answer tight; lead with the metric or the differentiator.

## 2.9 `docs/ROADMAP.md` — future scope  **[P1]**
Near-term: CICIDS-2017 benchmark numbers; the live-agent run; real CERT-In advisory feed. Platform vision (the other PS#7 capabilities as roadmap, not claimed-as-built): cyber-resilience **digital twin** (attack-path simulation), live **CVE-driven vulnerability prioritization**, multi-tenant for state CERTs, real IT/OT connector library.

## 2.10 `EXECUTIVE_SUMMARY.md` — one-pager  **[P1]**
One page: the problem (1 line), the solution (the loop), the 5 headline numbers (MTTD 1.66d vs ~200d; ROC-AUC 0.9988 / 100% recall @ ~1% FPR; 92.3% attribution; 75% automation; tamper-evident audit), the counterfactual, and one screenshot. For a judge who reads nothing else.

## 2.11 Non-Markdown deliverables (note, don't generate as .md)
- **Pitch deck** — already exists at `~/Downloads/PRAHARI_Pitch_Deck_DESIGNED.pptx` (12 slides). Only regenerate if asked.
- **Architecture diagram (image)** — render a polished PNG/SVG from §1.3–1.4 (6 stages left→right, datastores beneath, the audit ledger spanning all, console on the side, attack data-path in red, control-plane in teal). Deck slide 5 already contains a drawn version.
- **Demo video** — recorded by the team using §2.7.

---

# PART 3 — GLOBAL STYLE RULES (apply to every document)
- **Honesty is a feature.** Always tag the metrics as a **controlled scenario**, not a public benchmark (§1.8). Never claim live-agent results, real OT, or benchmark numbers that don't exist. Judges reward calibrated honesty.
- **Lead with the number or the differentiator**, then explain. Keep prose tight; prefer tables/bullets.
- **Aesthetic:** "night-shift SOC" — if any doc is styled, use the palette: bg `#0A0E14`, teal accent `#2DD4BF`, threat amber→red `#FACC15`→`#EF4444`, success `#34D399`, saffron `#FF9933` only on the wordmark; monospace for telemetry (technique codes, hashes, metrics).
- **Map to the judging weights:** Innovation (graph fusion + agents), Business Impact (India + weeks-to-hours + breach prevented), Technical Excellence (the loop + integrity guardrails + real measured metrics), Scalability (streaming/Docker/IT+OT), UX (the cinematic console).
- **Use exact identifiers:** PRAHARÍ, INC-001, WS03→DC01→DB-EXAMS, the technique IDs (T1566/T1078/T1003/T1021/T1560/T1041/T1071, predicted T1070/T1486), and the metrics from §1.6 — verbatim.
- **Repo URL:** https://github.com/Kartik-99999/prahari
