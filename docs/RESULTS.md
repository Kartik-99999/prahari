# PRAHARÍ — Evaluation Results

> **Honesty first (per §1.8 of the submission brief).** Two classes of result are
> reported separately and must never be conflated:
> 1. **Controlled-scenario** metrics — on PRAHARÍ's own synthetic, labelled
>    scenario (13 malicious / 2128 events). Near-perfect numbers reflect a clean,
>    self-built scenario; they are **not** benchmark results.
> 2. **Public-benchmark** metrics — real, held-out detection on **CIC-IDS-2017**,
>    reported below *whatever the number is*.

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
