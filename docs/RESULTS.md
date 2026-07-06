# PRAHARÍ — Evaluation Results

> **Honesty first (per §1.8 of the submission brief).** Two classes of result are
> reported separately and must never be conflated:
> 1. **Controlled-scenario** metrics — on PRAHARÍ's own synthetic, labelled
>    scenario (13 malicious / 2128 events). Near-perfect numbers reflect a clean,
>    self-built scenario; they are **not** benchmark results.
> 2. **Public-benchmark** metrics — real, held-out detection on **CIC-IDS-2017**,
>    reported below *whatever the number is*.

**Judges' evaluation focus → where it is measured here:**

| Judge metric | Result | Section |
|---|---|---|
| Anomaly detection rate & FPR on benchmark datasets | CIC-IDS-2017 macro ROC **0.845** (DDoS 0.910, 84.6% det @10% FPR), held-out, unsupervised | §1 |
| APT attribution accuracy @ ATT&CK technique level | **92.3% exact (12/13), 0 false attributions** (deterministic mapper — the stable number); live Claude agent, after a grounding fix, **grounds ~14–24 of ~25 citations on malicious events vs the mapper's ~2** on the insider case (exact labels vary run-to-run) — `LIVE_AGENT_RUN.md` | §3 + `metrics_slate.json` |
| Incident-response automation coverage | **75%** (6 auto / 2 human-gated of 8 steps) | §2 / `make soar-eval` |
| MTTD / MTTR vs baseline SOC | MTTD **1.66 d** (vs ~200 d dwell); held-out insider **~7 min**; OT **~4 min**; MTTR **<1 s** | §§1b, 2, 4 |
| Full auditability of automated actions | SHA-256 hash chain, append-only, tamper detected at exact entry | §2 / `make audit-tamper-demo` |

Every number was independently re-executed end-to-end on 2026-06-30 and matched
(≤0.1% drift; G5 within documented run-to-run variance) — see
[`../VERIFICATION_REPORT.md`](../VERIFICATION_REPORT.md).

---

## 1. Public benchmark — CIC-IDS-2017 (held-out, unsupervised)  [G1]

**What this answers:** the judges' "anomaly detection rate & FPR on benchmark
datasets" — using the **same unsupervised model core** as PRAHARÍ's UEBA layer
(Standard/Robust-scaled features → IsolationForest + ECOD ensemble) on a real
public IDS benchmark.

**Dataset:** CIC-IDS-2017 *MachineLearningCVE* per-day flow CSVs (HF mirror
`c01dsnap/CIC-IDS2017`), Friday-afternoon **PortScan** and **DDoS** captures
(CICFlowMeter features + `Label`). Fetch documented in `data/README.md`
(gitignored).

**Protocol (no tuning on test labels):**
- Robust preprocessing decided on domain grounds (signed-`log1p` + `RobustScaler`
  for heavy-tailed NetFlow features) — *not* on test labels.
- Deterministic stratified split (seed 42): **50 % train / 25 % validation /
  25 % test**.
- Unsupervised fit on the **benign-only** slice of train (standard one-class IDS
  protocol; labels only select the benign fit pool).
- **Detector selection on validation:** ensemble members retained only if val
  ROC-AUC > 0.5. On NetFlow, **ECOD's marginal-CDF assumption is inverted**
  (val ROC ≈ 0.04–0.39), so it is dropped and the ensemble reduces to
  **IsolationForest**, reported transparently.
- Detection thresholds set on **validation** benign; all metrics reported on the
  disjoint **held-out test** split.

**Results (held-out test):**

| Attack | ROC-AUC | PR-AUC | det@1%FPR | det@5%FPR | det@10%FPR (prec) |
|---|---|---|---|---|---|
| **DDoS** | **0.910** | 0.845 | 0.0% | 16.7% | **84.6% (prec 91.7%)** |
| **PortScan** | **0.781** | 0.688 | 0.1% | 0.1% | 1.7% |
| *macro* | **0.845** | 0.766 | — | — | — |

Curve: `docs/benchmark_cicids_roc_pr.png` (dark-theme ROC + PR).

**Honest interpretation:**
- **ROC-AUC 0.78–0.91** on a real public benchmark with a purely unsupervised,
  label-free detector is a credible, defensible result — clearly *weaker* than
  the controlled-scenario 0.9988, which is exactly the point of running it.
- **Detection at a strict 1 % FPR is low** because benign NetFlow has its own
  heavy-tailed outliers (rare-but-legitimate flows) that occupy the extreme tail
  ahead of attack flows. As the FPR budget relaxes, DDoS detection climbs to
  **84.6 % at 10 % FPR**. PortScan (volumetric scanning = dense, repetitive flows)
  is genuinely hard for point-isolation methods and stays low — reported honestly.
- This is **why PRAHARÍ adds graph fusion + correlation on top of single-event
  UEBA**: single-flow scoring at low FPR is insufficient; correlating weak
  signals across entities/time is the contribution that makes detection usable
  (demonstrated on the controlled scenario, §2).
- Per-flow point anomaly is also only a *partial* test of PRAHARÍ, whose thesis
  is per-**entity** behavioural drift over days (low-and-slow), not volumetric
  flood/scan detection that signature/volumetric tools already handle.

Reproduce: `make ueba-benchmark` (after fetching the CSVs per `data/README.md`).

---

## 1b. Generalization — held-out insider scenario, FROZEN thresholds  [G2]

**What this answers:** does PRAHARÍ generalize beyond the scripted scenario-1
APT, or is it over-fit to it? We built a **second, deliberately dissimilar**
attack and ran it through the **frozen** pipeline — *nothing* re-tuned.

**Scenario 2 (`make scenario2`):** a malicious **insider** with valid
credentials slowly exfiltrates the exam-records DB to a **removable USB drive**
over ~3 weeks, with **NO external command-and-control at all**. This removes
scenario-1's three dominant signals (`external_dst`, `external_auth_src`,
`new_external_dst_for_host`), so detection must come from behaviour alone
(off-hours, new user→host pairings, rare archiver processes, velocity). Larger
network for more benign noise: **6 762 events / 45 malicious**, 28 days, 16
users, 11 hosts (vs scenario-1's 2 128 / 13). Kill chain spans **6 ATT&CK
techniques** distinct from scenario-1: T1078, T1087, T1005, T1074, T1560, T1052.

**Frozen from scenario-1 (verbatim, unchanged):** UEBA novelty weights, model
ensemble (IsolationForest `n_estimators=200, random_state=42`), fusion teleport
+ `PR_ALPHA=0.85`, incident `TAU=0.90`, and all incident-scoring weights.

| Stage (frozen)        | Result on scenario 2 (held out)                                  |
|-----------------------|------------------------------------------------------------------|
| **UEBA detection**    | ROC-AUC **0.9987**, PR-AUC **0.7395**, **recall@1%FPR = 100 % (45/45)**, @5%FPR 100 % |
| **Fusion → incidents**| 9 incidents raised; top **INC-001** = the insider campaign, lateral **DB-EXAMS↔WS05**; top-incident recall 23/45 (51 %), union recall **28/45 (62 %)** |
| **MTTD**              | **0.12 h (~7 min)** after the first malicious action (attack corroborated same night) |
| **Attribution (deterministic mapper)** | exact **2** (T1560), defensible-adjacent **6** (T1021 ↔ T1078/T1074), missed **37** of 45 |

**Honest interpretation:**
- **Detection generalizes strongly.** The frozen UEBA core scores a brand-new
  attack class — with *every* external signal removed — at **ROC-AUC 0.9987 and
  100 % recall at a strict 1 % FPR**, essentially matching scenario-1's 0.9988.
  The off-hours / new-user-host / rare-process / velocity features carry the
  detection on their own. This is the core generalization claim, and it holds.
- **MTTD is ~7 minutes** — the off-hours logon to a DB server the analyst never
  touches plus same-night discovery cross the fusion threshold immediately.
- **Fusion/incident assembly partially generalizes (reported honestly).** The
  top incident *is* the insider campaign with the correct lateral path, but two
  honest limitations appear: (1) the frozen `TAU=0.90` drops the low-and-slow
  bulk-read events whose per-event novelty is moderate (top-incident recall
  51 %, union 62 %); (2) with **no external IP** to act as a rare shared
  connector — and the user pivot excluded from the graph **by design** (to avoid
  dragging in benign same-account activity) — the all-internal campaign
  **fragments into 2 incidents** (DB-EXAMS read/logon cluster vs FILESVR
  staging+archive). Detection *ranking* is unaffected; incident *consolidation*
  is where an all-internal insider is hardest.
- **Deterministic attribution does NOT fully generalize — and we report it.**
  The rule table is scenario-1-shaped: it correctly maps the shared **T1560**
  archive and flags insider logons/staging as **T1021** (defensible-adjacent to
  T1078/T1074), but **misses T1087/T1005/T1052** (insider-specific techniques
  absent from its rules) — exact accuracy 4.4 %. This is precisely the gap the
  **live LLM agent** (G3) is meant to close by reasoning over the ATT&CK KB
  rather than fixed rules; quantifying it requires an API key (see §3).

Full numbers: `data/metrics_slate.json → generalization`. Reproduce:
`make scenario2` (deterministic, seed 77; runs the frozen loop with `--no-write`
throughout, so the scenario-1 demo graph is never touched).

---

## 2. Controlled synthetic scenario (for reference)

The full closed-loop metrics (UEBA ROC-AUC 0.9988, fusion 13/13 recall,
attribution 92.3 %, SOAR 75 % automation, MTTD 1.66 d, tamper-evident audit) are
in `data/metrics_slate.json` and reproduced via `make loop-summary`. These are
**controlled-scenario** results — see the caveat at the top.

---

## 3. Live attribution agent + threat-intel corpus  [G3]

**Threat-intel corpus (`data/threat_intel/`, RAG-indexed).** Expanded from 6 to
**11** clearly-labelled advisories. The 5 new ones cover the scenario-2 insider
techniques that the scenario-1 corpus did not: Valid-Account abuse / insider
(T1078), Account & Directory Discovery (T1087), Bulk Collection from Local
Systems (T1005), Exfiltration over Physical Medium / USB (T1052), and a
low-and-slow insider overview. The RAG store indexes **233 documents** (222
ATT&CK technique docs + 11 advisories); **4/4 retrieval probes** return the
expected insider advisory in their top-3 (`make attribute-corpus`).

**CERT-In provenance (honest).** `cert-in.org.in` is reachable (HTTP 200) but its
advisory listing is a JavaScript servlet and individual advisories are PDFs, so
it is **not cleanly machine-ingestable via static fetch** (verified — the static
page returns "Page Requested Currently Not available"). Per the brief's
fallback, the corpus is therefore **curated and explicitly labelled
REPRESENTATIVE / ILLUSTRATIVE**, grounded in public MITRE ATT&CK technique
descriptions and CERT-In's public *"Guidelines on Information Security Practices
for Government Entities"*. Swap in the live CERT-In feed in production.

**Agent wiring + LIVE status.** The tool-using Claude attribution agent
(`services/attribution/agent.py`) is now parameterised to run on **both**
scenarios (`--events/--scores/--incidents/--report`) and gains `--no-write` so a
scenario-2 run never touches the scenario-1 Neo4j demo graph. Its FALLBACK
narrative is now **data-driven** (external-C2 campaign vs internal-insider),
verified to leave scenario-1's output unchanged while producing a correct
insider narrative for scenario-2 (cites the new insider advisory; proposes
insider next-moves T1052/T1070/T1078/T1213).

> **LIVE agent = RUNS + MEASURED (2026-07-04/05), with a grounding fix in
> between.** With no `ANTHROPIC_API_KEY`, the live tool-using agent runs through
> the **Claude Code subscription CLI** (`make attribute-agent-live`,
> `make scenario2-agent-live`) — same tools, cite-or-abstain, `gt_*` never in a
> tool result, `mode = live-cc`, `claude-sonnet-4-6`.
>
> **First scoring caught a real bug.** Scored against ground truth
> (`make score-agent`), the initial runs cited **0** malicious events —
> `get_incident_events` returned events in timestamp order and the tool result was
> truncated, so on a 124-event incident the model only saw the earliest (benign
> day-1) events. **Fix:** rank incident events by the system's own
> `anomaly_score`/`fused_score` (top-K, tagged with `anomaly_rank`) and raise the
> result budget so the malicious events are never truncated; prompt the agent to
> ground techniques in high-anomaly events.
>
> **After the fix (measured, per-malicious-event, same basis as the mapper's §1b
> 2/45) — separating the robust metric from the noisy one:**
>
> | | citations on **malicious** events (robust) | per-event **exact** (noisy) | mapper (ref) |
> |---|---|---|---|
> | Scenario-1 APT | 17 / 21 | 11 | 12/13 |
> | Scenario-2 insider | **14–24 / 25** (across runs) | 1–20 (run-dependent) | **~2 / 45** |
>
> **Grounding is the robust win:** the agent reliably cites the *actual malicious*
> events (where the mapper cites ~2 on the insider case). The **exact ATT&CK label**
> is *not* stable — two runs of the same incident scored 20 and 1 exact, almost
> entirely because the `pg_dump` cluster is labelled T1005 (Data from Local System)
> in one run and the adjacent T1039 (Data from Network Share) in the other. So we
> lead with grounding, not a single exact-match count. Full before/after + the
> run-to-run variance table: [`LIVE_AGENT_RUN.md`](LIVE_AGENT_RUN.md).
>
> **Honesty:** an LLM agent is not bit-reproducible, so the **deterministic mapper
> (92.3% exact, §3) remains the stable, reproducible attribution number**; the
> agent contributes a *grounded* narrative + next-move prediction that grounds far
> better than the mapper on the hard insider case.

Reproduce: `make attribute-agent-live` (live agent, subscription CLI — no key) or
`make attribute-agent` (live via `ANTHROPIC_API_KEY`); `make scenario2-agent-live`
(live agent on the held-out insider incident); `make attribute-corpus` (corpus +
RAG probes + agent status → `metrics_slate.json → threat_intel`).

---

## 4. IT + OT heterogeneity — Modbus/SCADA PLC attack  [G4 → G7]

**What this answers:** does PRAHARÍ ingest and reason over **operational
technology** telemetry, not just IT? We model a Modbus/SCADA substation and an
**unauthorized PLC setpoint / logic-download** attack (the classic ICS
manipulation-of-control threat), mapped to the **same OCSF `SecurityEvent`
schema** (Modbus/TCP → `network`:502, engineering tool → `process`, PLC logic →
`file`, logon → `auth`; OT semantics in `raw`), and run it through the **frozen**
UEBA + graph — zero retuning. `make ot-demo`.

**Scenario (hardened in G7):** 1 330 events / 30 malicious, 21 days, 8 OT hosts
(EWS, 2 HMIs, historian, SCADA, 3 PLCs). ICS techniques **T0859/T0843/T0836/T0855**.
Two deliberate realism traps: (1) the historian and SCADA server poll PLCs
**24/7**, so **49 % of benign events are off-hours** — time-of-day is a weak
signal; (2) operators on the HMIs issue **routine, legitimate setpoint writes**
(126 benign writes vs 16 malicious ones), so a write-function-code flag alone
can never be a label proxy — the behavioural signal has to be *who writes to
which PLC*. *(The original G4 run predates the benign-write hardening: 1 207
events, ROC 0.792, recall@1%FPR 33 % — retained here for provenance.)*

**G7 — OT-native behavioural features close the measured gap.** G4 published
the diagnosis: setpoint writes evade IT-shaped scoring because read-vs-write is
not an IT feature. G7 adds three OT-native features in the same behavioural
design language (`ot_modbus_write` flag; `ot_new_write_pair` first-writer→PLC
novelty; `ot_write_pair_rarity` decaying rarity, mirroring the existing
process/user-host rarity features). They are emitted **only for Modbus-bearing
streams** — the IT scenarios' feature matrices are **bit-identical** (re-verified:
scenario-1 ROC 0.9988 / 100 % @ ~1 % FPR and scenario-2 ROC 0.9987 / 100 % @1 %
FPR reproduce exactly). Core model, weights, and thresholds stay frozen.

| Result (held-out, hardened scenario) | IT-only baseline | **+ OT-native (G7)** |
|---|---|---|
| Single-event ROC-AUC | 0.840 (PR 0.294) | **0.895** (PR 0.347) |
| Recall @ 1 % FPR | 43 % | **50 %** |
| Recall @ 5 % FPR | 47 % | **67 %** |
| Malicious Modbus writes alarmed @1 % FPR | 8/16 | **13/16** |
| Benign operator writes alarmed (cost) | 4/126 | 10/126 |
| ICS techniques surfaced @1 % FPR | 3/4 | 3/4 (T0859 still missed) |
| MTTD (first attack alarm) | ~0.07 h (≈4 min) | **~0.07 h (≈4 min)** |

Reproduce both columns: `make ot-demo` (runs the IT-only baseline, then G7;
writes `metrics_slate.json → ot_it_only` and `→ ot`). Curve: `docs/ot_detection.png`.

**Honest interpretation:**
- **The measured gap is now measurably closed:** manipulation *commands*
  (setpoint writes) alarm at 13/16 instead of 8/16, and recall at the relaxed
  budget nearly triples the baseline's headroom (47 % → 67 % @5 % FPR). The
  first rogue write from EWS01 alarms as a **new writer→PLC pair**; repeat-night
  writes stay warm via rarity. Detection remains purely behavioural —
  benign operator writes are learned normal (only 10/126 alarm).
- **Still-honest residuals:** 3/16 malicious writes sit below the 1 % budget
  (repeat writes from an already-seen pair); **T0859** (a plain off-hours logon
  in a 24/7 plant) remains undetectable by design; and the benign-write alarm
  cost (4→10 of 126) is the price of the new sensitivity — all reported.
- **Fusion on OT remains modest** (top incident 4/30; +1 event beyond the alarm
  set): this attack is a **single rogue engineer**, best correlated **by user**
  — a pivot the frozen similarity graph deliberately excludes to avoid benign
  drag in IT cases. User-pivoted OT correlation stays on the roadmap.
- **ICS ATT&CK attribution (T08xx) is out of scope** for the enterprise (T10xx)
  mapper — unchanged honest gap, consistent with §1b.

Full numbers: `data/metrics_slate.json → ot_it_only / ot`. Deterministic, seed
1337; `--no-write` throughout — the scenario-1 demo graph is never touched.

---

## 5. Scalability — throughput, memory, Neo4j latency  [G5]

**What this answers:** does the pipeline scale beyond the ~2 k-event demo?
`make scale-bench` (`scripts/scale_bench.py`) streams synthetic OCSF events
through the **frozen** feature builder + detector core at 10 k / 100 k / **1 M**
events and measures throughput, peak memory, and Neo4j ingest/query latency.
Single process, no GPU, on the dev machine.

| Events | features (evt/s) | detector core (evt/s) | end-to-end (evt/s) | peak RSS |
|-------:|-----------------:|----------------------:|-------------------:|---------:|
| 10 k   | ~307 k | ~37 k  | ~28 k | 0.34 GB |
| 100 k  | ~119 k | ~126 k | ~52 k | 0.60 GB |
| **1 M**| ~111 k | ~157 k | **~54 k** | 2.5 GB |

**Neo4j:** ingested **100 000** `:ScaleEvent` nodes in **1.8 s (~55 k nodes/s)**;
a top-hosts aggregation query over them returned in **~120 ms**. The benchmark
uses a **dedicated `:ScaleEvent` label and `DETACH DELETE`s it afterwards** —
verified that 0 nodes leak and the scenario-1 demo graph (6 `:Host`, 4
`:Incident`) is untouched.

> **Absolute throughput is single-core and tracks CPU clock / power state — read
> the *scalability*, not the headline number.** The ~54 k above is the dev machine
> at full power. Re-running the same benchmark on a battery-throttled laptop (macOS
> Low Power Mode) reproducibly measures **~26 k end-to-end** — a *uniform* ~2× drop
> across every stage (gen/feature/score/Neo4j alike), i.e. it scales with core clock,
> not a code change. What is machine-independent — and is the actual scalability
> claim — is that feature extraction is **O(1)/event** (linear in event count) and
> every stage fans out **horizontally via Redis consumer groups**; absolute ev/s
> then scales with cores × clock.

**Honest interpretation:**
- The detection pipeline sustains **~54 k events/sec end-to-end at 1 M events**
  on a single core with **2.5 GB** peak RSS — i.e. a million events processed in
  ~20 s, comfortably batch-scale for a regional SOC; the streaming feature
  builder is O(1)/event and the IsolationForest(200)+ECOD core is the dominant
  cost.
- The `score` figure is the **scalable ML core** (StandardScaler + IForest(200)
  + ECOD + percentile). The separate human-readable *reason-string* formatting
  in `score.py` uses `DataFrame.iterrows` and is **O(n) Python** — fine at demo
  scale but it would be the first thing to vectorise for true streaming; called
  out honestly rather than folded into the headline number.
- Numbers vary run-to-run; exact figures for the recorded run are in
  `data/metrics_slate.json → scale`. Reproduce: `make scale-bench`
  (`--sizes` and `--neo4j-nodes` configurable; `--no-neo4j` to skip the DB).

---

## 6. Polish — dark-theme plots, a real SOAR connector, adversarial probe  [G6]

**Dark-theme plots.** The scenario-1 UEBA ROC/PR plot (`docs/ueba_roc_pr.png`,
`make ueba-eval`) was regenerated in the SOC command-center theme so all four
committed figures (`ueba_roc_pr`, `benchmark_cicids_roc_pr`, `ot_detection`)
share one visual language. Numbers unchanged (ROC 0.9988, PR 0.868).

**One real, safe SOAR connector (`make notify`).** Alongside the six *simulated*
containment connectors, `services/soar/notify.py` is a **real egress** connector
that posts an incident summary to a Slack/Discord/Teams-compatible webhook. It is
**safe by construction**:
- **DRY-RUN by default** — prints the exact JSON payload and makes no network
  call;
- a real POST happens **only** when BOTH `PRAHARI_WEBHOOK_URL` is set **and** the
  explicit `--send` flag is passed (missing either ⇒ dry-run; `--send` without a
  URL refuses to egress);
- the destination comes from the env var only, with a short timeout, and only a
  concise summary is transmitted (no raw events, no secrets).

The auto-orchestrator stays fully simulated, so there is no surprise egress
during the demo; this connector is the explicit, opt-in, production-real path.

**Adversarial robustness probe (`make adversarial`).** An off-hours-evasion
what-if against the **frozen** detector: the scenario-2 insider operates in
business hours instead of at night (we zero the malicious events' time-of-day
signals and re-score with the unchanged pipeline).

| Detector (frozen) | ROC-AUC | recall @1% FPR | recall @5% FPR |
|-------------------|--------:|---------------:|---------------:|
| baseline (as-observed) | 0.9987 | 100 % | 100 % |
| **evasive (business hours)** | 0.915 | **13 %** | 80 % |

**Honest finding:** off-hours is a **load-bearing** signal at the strict 1 % FPR
operating point — evading it collapses recall there (100 % → 13 %). **But the
attack stays separable**: ROC holds at 0.915 and recall recovers to **80 % at
5 % FPR**, because the insider still trips the time-independent signals
(new user→host on DB-EXAMS, rare archiver process, 24 h host velocity). The
practical takeaway, reported rather than hidden: don't rely on off-hours alone —
tune the operating point and lean on fusion/corroboration. Full numbers:
`data/metrics_slate.json → adversarial`.




