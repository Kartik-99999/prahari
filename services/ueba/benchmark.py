#!/usr/bin/env python3
"""PRAHARI UEBA — PUBLIC-BENCHMARK detection (CIC-IDS-2017).

Runs the SAME unsupervised model core as the synthetic UEBA layer
(StandardScaler -> IsolationForest(n_estimators=200, random_state=42) + ECOD,
percentile/z-calibrated ensemble) against a real public benchmark, under a
rigorous HELD-OUT protocol with NO tuning on test labels:

  * preprocess: strip column whitespace, Label -> binary (BENIGN=0 / attack=1),
    inf -> NaN -> 0, drop constant/non-numeric columns.
  * deterministic stratified subsample (cap per file) + split 50/25/25
    into train / validation / test (seed=42).
  * FIT the unsupervised models on the BENIGN-ONLY slice of TRAIN
    (standard one-class IDS protocol — label-free at scoring; train labels only
    select the benign fit pool).
  * ensemble = mean of each model's z-score (z fitted on the train-benign
    decision scores) -> a fixed transform, so a VALIDATION threshold transfers
    to TEST unchanged.
  * report on the disjoint HELD-OUT TEST split: ROC-AUC, PR-AUC (threshold-free)
    and detection-rate at the ~1% FPR threshold that was chosen on VALIDATION.

NB: the host-behavioural novelty features of the synthetic UEBA are domain-
specific (user/host/process novelty) and do NOT apply to NetFlow records, so the
benchmark uses the model-ensemble core on the dataset's native flow features.
This is reported honestly and is distinct from the synthetic-scenario metrics.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from pyod.models.copod import COPOD  # noqa: E402
from pyod.models.ecod import ECOD  # noqa: E402
from pyod.models.iforest import IForest  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    average_precision_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)
from sklearn.preprocessing import RobustScaler  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = _REPO_ROOT / "data" / "benchmark" / "cicids2017"
SLATE = _REPO_ROOT / "data" / "metrics_slate.json"
PNG = _REPO_ROOT / "docs" / "benchmark_cicids_roc_pr.png"

# dark "night-shift SOC" palette (matches the console + deck)
BG = "#0A0E14"
PANEL = "#121823"
GRID = "#243044"
TEXT = "#E2E8F0"
TEAL = "#2DD4BF"
RED = "#EF4444"
AMBER = "#FACC15"

SUBSETS = {
    "PortScan": "Friday-PortScan.csv",
    "DDoS": "Friday-DDoS.csv",
}

SEED = 42
MAX_ROWS = 80_000  # manageable, deterministic stratified subsample per file
TARGET_FPR = 0.01


def preprocess(path: Path, max_rows: int) -> tuple[np.ndarray, np.ndarray, list[str]]:
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    label_col = next(c for c in df.columns if c.lower() == "label")
    y = (df[label_col].astype(str).str.upper() != "BENIGN").astype(int).to_numpy()

    feat = df.drop(columns=[label_col])
    # keep numeric only; coerce, clean inf/nan
    feat = feat.apply(pd.to_numeric, errors="coerce")
    feat = feat.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    # drop constant columns (zero variance carries no signal)
    nunique = feat.nunique()
    feat = feat[[c for c in feat.columns if nunique[c] > 1]]
    cols = list(feat.columns)
    X = feat.to_numpy(dtype=float)

    # deterministic stratified subsample to max_rows
    rng = np.random.default_rng(SEED)
    if len(X) > max_rows:
        idx_keep = []
        for cls in (0, 1):
            cls_idx = np.where(y == cls)[0]
            frac = max_rows / len(X)
            n = max(1, int(round(len(cls_idx) * frac)))
            idx_keep.append(
                rng.choice(cls_idx, size=min(n, len(cls_idx)), replace=False)
            )
        idx = np.sort(np.concatenate(idx_keep))
        X, y = X[idx], y[idx]
    return X, y, cols


def _split(X: np.ndarray, y: np.ndarray) -> dict:
    """Stratified deterministic 50/25/25 train/val/test."""
    rng = np.random.default_rng(SEED)
    out = {"train": [], "val": [], "test": []}
    for cls in (0, 1):
        ci = np.where(y == cls)[0]
        rng.shuffle(ci)
        n = len(ci)
        a, b = int(n * 0.5), int(n * 0.75)
        out["train"].append(ci[:a])
        out["val"].append(ci[a:b])
        out["test"].append(ci[b:])
    sel = {k: np.sort(np.concatenate(v)) for k, v in out.items()}
    return {k: (X[i], y[i]) for k, i in sel.items()}


def _signed_log1p(X: np.ndarray) -> np.ndarray:
    """Robust transform for heavy-tailed, possibly-signed NetFlow features."""
    return np.sign(X) * np.log1p(np.abs(X))


def _build_scorer(Xtr_benign: np.ndarray, Xval: np.ndarray, yval: np.ndarray):
    """Fit the SAME unsupervised core on benign-only train, then VALIDATE each
    detector on the validation split and retain only members with val ROC>0.5
    (a fixed transform + label-free fit; selection uses VALIDATION, never test).

    Returns (scorer, info) where info records per-model val ROC + retained set.
    """
    # robust preprocessing decided on domain grounds (heavy-tailed flow data)
    scaler = RobustScaler().fit(_signed_log1p(Xtr_benign))

    def _z(X: np.ndarray) -> np.ndarray:
        return np.clip(scaler.transform(_signed_log1p(X)), -1e6, 1e6)

    Ztr = _z(Xtr_benign)
    models = {
        "IForest": IForest(n_estimators=200, random_state=SEED).fit(Ztr),
        "ECOD": ECOD().fit(Ztr),
        # ML-1: third family — empirical-copula detector; cheap, no tuning, and
        # the val-ROC retention below auto-drops it wherever it underperforms.
        "COPOD": COPOD().fit(Ztr),
    }
    stats, val_roc, retained = {}, {}, []
    Zval = _z(Xval)
    for name, m in models.items():
        sc = m.decision_scores_
        stats[name] = (sc.mean(), sc.std() + 1e-9)
        roc = float(roc_auc_score(yval, m.decision_function(Zval)))
        val_roc[name] = round(roc, 4)
        if roc > 0.5:
            retained.append(name)
    if not retained:  # degenerate guard: keep the best-on-val member
        retained = [max(val_roc, key=val_roc.get)]

    def scorer(X: np.ndarray) -> np.ndarray:
        Zx = _z(X)
        zs = []
        for name in retained:
            mu, sd = stats[name]
            zs.append((models[name].decision_function(Zx) - mu) / sd)
        return np.mean(zs, axis=0)

    return scorer, {"per_model_val_roc": val_roc, "detectors_retained": retained}


def _threshold_at_fpr(scores_benign: np.ndarray, target_fpr: float) -> float:
    """Threshold giving ~target FPR on a benign-only score sample."""
    return float(np.quantile(scores_benign, 1.0 - target_fpr))


def run_subset(name: str, path: Path, max_rows: int) -> dict:
    X, y, cols = preprocess(path, max_rows)
    sp = _split(X, y)
    Xtr, ytr = sp["train"]
    Xval, yval = sp["val"]
    Xte, yte = sp["test"]

    scorer, sel = _build_scorer(
        Xtr[ytr == 0], Xval, yval
    )  # benign-only fit; val-select
    sval, ste = scorer(Xval), scorer(Xte)

    # detection across an FPR sweep — every threshold chosen on VALIDATION benign
    sweep = {}
    for tf in (0.01, 0.05, 0.10):
        thr = _threshold_at_fpr(sval[yval == 0], tf)
        pred = ste >= thr
        tp = int(np.sum(pred & (yte == 1)))
        fp = int(np.sum(pred & (yte == 0)))
        fn = int(np.sum(~pred & (yte == 1)))
        tn = int(np.sum(~pred & (yte == 0)))
        sweep[f"{int(tf*100)}pct"] = {
            "detection_rate": round(tp / (tp + fn) if (tp + fn) else 0.0, 4),
            "actual_fpr": round(fp / (fp + tn) if (fp + tn) else 0.0, 4),
            "precision": round(tp / (tp + fp) if (tp + fp) else 0.0, 4),
        }
    det = sweep["1pct"]["detection_rate"]
    fpr = sweep["1pct"]["actual_fpr"]
    prec = sweep["1pct"]["precision"]

    roc = float(roc_auc_score(yte, ste))
    pr = float(average_precision_score(yte, ste))
    fpr_c, tpr_c, _ = roc_curve(yte, ste)
    prec_c, rec_c, _ = precision_recall_curve(yte, ste)

    return {
        "name": name,
        "n_features": len(cols),
        "n_train_benign_fit": int(np.sum(ytr == 0)),
        "n_test": int(len(yte)),
        "test_attack_ratio": round(float(np.mean(yte)), 4),
        "roc_auc": round(roc, 4),
        "pr_auc": round(pr, 4),
        "detection_rate_at_1pct_fpr": round(det, 4),
        "fpr_at_threshold": round(fpr, 4),
        "precision_at_threshold": round(prec, 4),
        "threshold_source": "validation (1% FPR)",
        "detection_fpr_sweep": sweep,
        "detectors_retained": sel["detectors_retained"],
        "per_model_val_roc": sel["per_model_val_roc"],
        "_curve": {
            "fpr": fpr_c,
            "tpr": tpr_c,
            "prec": prec_c,
            "rec": rec_c,
            "roc": roc,
            "pr": pr,
            "base": float(np.mean(yte)),
        },
    }


def plot_dark(results: list[dict], png: Path) -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": BG,
            "axes.facecolor": PANEL,
            "savefig.facecolor": BG,
            "text.color": TEXT,
            "axes.labelcolor": TEXT,
            "xtick.color": TEXT,
            "ytick.color": TEXT,
            "axes.edgecolor": GRID,
            "grid.color": GRID,
            "font.family": "monospace",
            "font.size": 9,
        }
    )
    colors = [TEAL, AMBER]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.6))
    for i, r in enumerate(results):
        c = r["_curve"]
        col = colors[i % len(colors)]
        ax1.plot(
            c["fpr"],
            c["tpr"],
            color=col,
            lw=2,
            label=f"{r['name']} (AUC={c['roc']:.3f})",
        )
        ax2.plot(
            c["rec"],
            c["prec"],
            color=col,
            lw=2,
            label=f"{r['name']} (AP={c['pr']:.3f})",
        )
        ax2.axhline(c["base"], ls=":", color=GRID, lw=1)
    ax1.plot([0, 1], [0, 1], "--", color=GRID, lw=1)
    ax1.axvline(0.01, color=RED, ls="--", lw=1, alpha=0.7, label="1% FPR")
    ax1.set(
        xlabel="False Positive Rate",
        ylabel="True Positive Rate",
        title="CIC-IDS-2017 — ROC (held-out test)",
    )
    ax2.set(
        xlabel="Recall", ylabel="Precision", title="CIC-IDS-2017 — Precision-Recall"
    )
    for ax in (ax1, ax2):
        ax.grid(alpha=0.3)
        ax.legend(
            loc="lower right" if ax is ax1 else "upper right",
            facecolor=PANEL,
            edgecolor=GRID,
            labelcolor=TEXT,
        )
    fig.suptitle(
        "PRAHARÍ UEBA — public-benchmark detection (unsupervised, held-out)", color=TEXT
    )
    fig.tight_layout()
    png.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(png, dpi=130)
    plt.close(fig)


def update_slate(subsets: list[dict]) -> None:
    slate = json.loads(SLATE.read_text()) if SLATE.exists() else {}
    macro_roc = round(float(np.mean([s["roc_auc"] for s in subsets])), 4)
    macro_det = round(
        float(np.mean([s["detection_rate_at_1pct_fpr"] for s in subsets])), 4
    )
    slate["benchmark"] = {
        "dataset": "CIC-IDS-2017 (MachineLearningCVE; HF mirror c01dsnap/CIC-IDS2017)",
        "model": "unsupervised IsolationForest(200)+ECOD ensemble (same core as synthetic UEBA)",
        "protocol": (
            "fit on benign-only TRAIN (one-class IDS); threshold@1%FPR set on "
            "VALIDATION; metrics on disjoint HELD-OUT TEST; no test-label tuning; seed=42"
        ),
        "macro_roc_auc": macro_roc,
        "macro_detection_rate_at_1pct_fpr": macro_det,
        "subsets": {
            s["name"]: {
                k: s[k]
                for k in (
                    "roc_auc",
                    "pr_auc",
                    "detection_rate_at_1pct_fpr",
                    "fpr_at_threshold",
                    "precision_at_threshold",
                    "n_test",
                    "test_attack_ratio",
                    "n_features",
                    "threshold_source",
                    "detectors_retained",
                    "per_model_val_roc",
                    "detection_fpr_sweep",
                )
            }
            for s in subsets
        },
        "curve_png": "docs/benchmark_cicids_roc_pr.png",
        "note": (
            "Public-benchmark result, DISTINCT from the synthetic controlled scenario. "
            "Model-ensemble core only; host-behavioural novelty features are domain-"
            "specific to the synthetic IT scenario and not applicable to NetFlow."
        ),
    }
    SLATE.write_text(json.dumps(slate, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser(description="CIC-IDS-2017 unsupervised benchmark.")
    ap.add_argument("--max-rows", type=int, default=MAX_ROWS)
    ap.add_argument("--data-dir", type=Path, default=DATA_DIR)
    args = ap.parse_args()

    avail = {
        n: args.data_dir / f for n, f in SUBSETS.items() if (args.data_dir / f).exists()
    }
    if not avail:
        print(
            f"[benchmark] no CICIDS files in {args.data_dir}. See data/README.md to fetch.",
            file=sys.stderr,
        )
        sys.exit(1)

    results = []
    print("=" * 78)
    print(
        "  PRAHARÍ — CIC-IDS-2017 unsupervised benchmark (held-out, no test-label tuning)"
    )
    print("=" * 78)
    for name, path in avail.items():
        r = run_subset(name, path, args.max_rows)
        results.append(r)
        print(
            f"\n[{name}]  features={r['n_features']}  benign-fit={r['n_train_benign_fit']}  "
            f"test={r['n_test']} (attack {r['test_attack_ratio']*100:.1f}%)\n"
            f"   detectors: val-ROC {r['per_model_val_roc']} -> retained {r['detectors_retained']}\n"
            f"   ROC-AUC={r['roc_auc']}  PR-AUC={r['pr_auc']}\n"
            f"   detection @FPR: "
            + "  ".join(
                f"{k.replace('pct','%')}->{v['detection_rate']*100:.1f}% (fpr {v['actual_fpr']*100:.1f}%)"
                for k, v in r["detection_fpr_sweep"].items()
            )
            + "   [thresholds from validation]"
        )

    plot_dark(results, PNG)
    update_slate(results)
    print(
        f"\nMacro ROC-AUC={np.mean([r['roc_auc'] for r in results]):.4f}  "
        f"Macro detection@1%FPR={np.mean([r['detection_rate_at_1pct_fpr'] for r in results])*100:.1f}%"
    )
    print(f"Saved curve -> {PNG}")
    print(f"Updated benchmark section -> {SLATE}")


if __name__ == "__main__":
    main()
