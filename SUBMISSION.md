# PRAHARÍ — Hackathon Portal Answers (ready to paste)

> PS#7 — *AI-Driven Cyber Resilience for Critical National Infrastructure*. Each answer is tuned to the judging weight it serves (Innovation 25 · Business Impact 25 · Technical Excellence 20 · Scalability 15 · UX 15). All numbers are real, reproducible, and independently re-verified (`VERIFICATION_REPORT.md`).

---

## Problem statement *(Business Impact)*

India's critical infrastructure is losing the detection race. CERT-In handled **1.59M+ incidents in 2023**; AIIMS Delhi was paralysed 2+ weeks by ransomware; CBSE's examination records were breached; **70%+ of government entities run end-of-life IT**. The root failure is speed: APTs operate low-and-slow below signature thresholds, and mean dwell time is **~200 days** (Mandiant). By the time a signature exists, the attack has already succeeded. Defenders need a behavioural layer that flags *deviation from normal* — and a response loop fast enough to matter.

## Solution summary

PRAHARÍ (Hindi: *guardian*) is one closed, fully-auditable loop: OCSF ingest → **unsupervised UEBA** anomaly scoring (no signatures, no labels) → **graph weak-signal fusion** in Neo4j ("anomaly lift") that assembles individually-ignorable events into one ranked attack chain → **Claude-agent MITRE ATT&CK attribution + next-move prediction** over a RAG knowledge base → **SOAR autonomous response** with platform-enforced human gates → a **tamper-evident hash-chained audit ledger**. Fronted by a cinematic Next.js SOC console. Result: detection in **hours, not months** — in our controlled scenario, containment fires **17 days before** the scheduled exfiltration. The breach is prevented.

## Innovation — what's novel *(Innovation, 25%)*

1. **Graph "anomaly lift" fusion:** `fused = personalized_PageRank / uniform_PageRank` over an event-similarity graph — dividing out benign-hub centrality so weak-but-connected signals (0.68–0.75) rise to ≥0.90 and weld into one campaign. Naive PageRank promotes busy hubs; the ratio promotes *conspiracies*.
2. **Agentic attribution with integrity rails:** tool-using Claude agents reason over live MITRE ATT&CK (697 techniques) + advisories, must cite-or-abstain, never see ground truth, and predict the adversary's *next* techniques (T1070, T1486) before they happen.
3. **The AI cannot bypass a human gate:** the response agent only *proposes*; the platform computes blast radius and enforces the gate. Autonomy where safe (75% of steps), human sovereignty where it matters.
4. **Honesty engineered in:** `assert_no_leakage` guards, frozen-threshold held-out evals, a ground-truth-free console, and an adversarial self-probe published in our own results.

## Business impact *(Business Impact, 25%)*

- **Weeks → hours:** MTTD **1.66 days** after foothold vs ~200-day industry dwell; automated containment in **<1 s** once confirmed; the modelled CBSE-style exam-records exfiltration is **prevented outright** (C2 severed 17 days early).
- **Fits India's reality:** signature-free behavioural detection protects the end-of-life estates attackers target; the audit ledger gives government-grade accountability for every autonomous action; multi-tenancy for state CERTs is the designed growth path.
- **SOC economics:** graph fusion turns thousands of ignorable alerts into **one ranked incident** (top incident ≈4× the score of the next), attacking alert fatigue — the reason real intrusions get missed.

## Technical approach & stack *(Technical Excellence, 20%)*

Python microservices (`ingest/ueba/graph/attribution/soar/api`) · OCSF-style pydantic `SecurityEvent` · Redis Streams with consumer-group fan-out · unsupervised IsolationForest+ECOD with streaming novelty features (`0.5·model + 0.5·novelty`) · Neo4j provenance graph (APOC+GDS) with personalized-PageRank anomaly lift (α=0.85, τ=0.90) · Chroma RAG over live ATT&CK STIX + curated advisories · two Anthropic tool-use agents (attribution, response-planner) with deterministic fallback · SHA-256 hash-chained append-only Postgres ledger with tamper triggers · FastAPI BFF · Next.js 16 console — a scrolling product-page over the live BFF (generic incident client, honest offline state, no fixtures). Everything seeded and reproducible via `make` targets.

## What we built (working, not slideware)

The **entire loop runs end-to-end live**: 2,128-event 21-day APT replay → detection → fusion → attribution → gated response → verified audit chain, plus the analyst console with cinematic replay — all triggerable in one command (`make attack`, ~20 s, no API key), with streaming on-the-wire scoring (`make stream`) and a one-page explainable analyst brief (`make brief`). An **independent re-run of every stage passed all gates** — numbers matched our published results to <0.1% (`VERIFICATION_REPORT.md`).

## Results *(Technical Excellence)*

- **Public benchmark (CIC-IDS-2017, held-out, unsupervised):** DDoS ROC-AUC **0.910** (84.6% detection @10% FPR), PortScan 0.781, **macro 0.845**.
- **Controlled scenario (labelled synthetic APT):** ROC-AUC **0.9988**, **100% recall @ ~1% FPR (13/13)**; fusion recovers **4/4 weak signals**; ATT&CK technique accuracy **92.3%, 0 false attributions**; SOAR automation **75%**; **MTTD 1.66 d**, MTTR <1 s; tamper-evident audit demonstrated live.
- **Generalization (held-out insider attack, frozen thresholds, no external C2):** ROC **0.9987**, **100% recall @1% FPR (45/45)**, MTTD **~7 min**.
- **IT+OT (Modbus/SCADA PLC attack, hardened with benign operator writes):** we measured the IT-only gap, then closed it with OT-native behavioural features — ROC 0.840 → **0.895**, malicious setpoint-writes alarmed **8/16 → 13/16** @1% FPR, MTTD ~4 min.
- **Adversarial self-probe:** evading the off-hours signal collapses recall@1%FPR to 13% — but ROC holds 0.915 and 80% recall @5% FPR. We publish this.
*Controlled-scenario numbers are on our own clean synthetic data and are reported separately from the public benchmark — never conflated.*

## Scalability *(Scalability, 15%)*

Measured, not asserted: **~54k events/s end-to-end at 1M events on a single core, 2.5 GB RSS**; Neo4j bulk ingest ~55k nodes/s, aggregate queries ~120 ms over 100k nodes. The feature builder is O(1)/event; Redis consumer groups fan each stage out horizontally; the shared OCSF schema is how one pipeline covers IT *and* OT (demonstrated). Docker Compose today; the same topology maps to k8s.

## Challenges & honest limitations

1. Near-perfect loop metrics come from a **controlled synthetic scenario**; our defensible public number is CIC-IDS-2017 **macro ROC 0.845** — both reported, clearly separated.
2. The Claude attribution agent **runs live end-to-end** on both scenarios via the Claude Code **subscription CLI** (no API key) — a real 6–9-call tool-use investigation. We scored it against ground truth, caught it citing **benign** events, fixed the root cause (rank incident events by anomaly score), and re-measured ([`docs/LIVE_AGENT_RUN.md`](docs/LIVE_AGENT_RUN.md)): it now **reliably grounds on the malicious events** (14–24 of ~25 citations, vs the mapper's ~2 on the held-out insider case). The *exact* ATT&CK label on adjacent techniques varies run-to-run (a favourable run hit 20 exact), so the **92.3%** mapper stays the stable reproducible number and we report grounding as the robust win.
3. **OT is synthetic** (Modbus semantics over OCSF), no real PLC hardware. We published the IT-only gap (writes evade IT-shaped scoring), then shipped the fix — OT-native behavioural features lift write detection to 13/16 — with residuals still reported (3 repeat writes below the 1% budget; T0859 undetectable in a 24/7 plant).
4. Incident *consolidation* for all-internal insiders fragments (2 incidents instead of 1) — detection holds, and we document why.

## Future scope

Live-agent quantified run (`make attribute-agent` with a key) · user-pivoted OT correlation · real CERT-In advisory feed → RAG · cyber-resilience **digital twin** (attack-path simulation) · CVE-driven vulnerability prioritization · multi-tenant deployment for state CERTs · production connector library (EDR/firewall/IdP). Detail: `docs/ROADMAP.md`.

## Links

- **Repo:** https://github.com/Kartik-99999/prahari
- **Live demo:** http://3.7.9.1:3000 (running console on AWS — landing page → live analyst console; API at `:8000`)
- **Demo video:** https://drive.google.com/file/d/13jo_jX9gD92pBCs7jl9IvDX5Eh3KyCss/view?usp=sharing
- **Pitch deck:** https://docs.google.com/presentation/d/1-G-D1Oqkmc8oPEyWIR0riOxE5lSFINIp/edit?usp=sharing
- **Results & methodology:** `docs/RESULTS.md` · **Independent verification:** `VERIFICATION_REPORT.md`
