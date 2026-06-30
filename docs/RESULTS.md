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

## 2. Controlled synthetic scenario (for reference)

The full closed-loop metrics (UEBA ROC-AUC 0.9988, fusion 13/13 recall,
attribution 92.3 %, SOAR 75 % automation, MTTD 1.66 d, tamper-evident audit) are
in `data/metrics_slate.json` and reproduced via `make loop-summary`. These are
**controlled-scenario** results — see the caveat at the top.
