#!/usr/bin/env python3
"""Prahari UEBA evaluation — the ONLY module that reads ground truth.

Joins the unsupervised anomaly scores (services/ueba/score.py) with the
ground-truth manifest (data/ground_truth.json) by event_id and reports how well
the behavioural weak-signal layer separates the 13 malicious events from the
2115 benign ones — BEFORE any graph fusion.

Outputs:
  * a metrics table at 3 operating points (≈1% FPR, max-F1, and full-recall):
    detection_rate (recall), FPR, precision, F1
  * ROC-AUC and PR-AUC
  * docs/ueba_roc_pr.png (ROC + PR curves)
  * the TOP-20 events by anomaly_score with gt_malicious flag + reasons
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    average_precision_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCORES = _REPO_ROOT / "data" / "ueba_scores.csv"
DEFAULT_GT = _REPO_ROOT / "data" / "ground_truth.json"
DEFAULT_PNG = _REPO_ROOT / "docs" / "ueba_roc_pr.png"


def load(scores_csv: Path, gt_json: Path) -> pd.DataFrame:
    df = pd.read_csv(scores_csv)
    gt = json.loads(gt_json.read_text())
    malicious_ids = {e["event_id"] for e in gt["events"]}
    stage_by_id = {e["event_id"]: e["attack_stage"] for e in gt["events"]}
    tech_by_id = {e["event_id"]: e["mitre_technique"] for e in gt["events"]}
    df["gt_malicious"] = df["event_id"].isin(malicious_ids)
    df["gt_stage"] = df["event_id"].map(stage_by_id)
    df["gt_technique"] = df["event_id"].map(tech_by_id)
    return df


def metrics_at(y_true: np.ndarray, y_score: np.ndarray, thr: float) -> dict:
    pred = y_score >= thr
    tp = int(np.sum(pred & y_true))
    fp = int(np.sum(pred & ~y_true))
    fn = int(np.sum(~pred & y_true))
    tn = int(np.sum(~pred & ~y_true))
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "threshold": thr,
        "detection_rate": recall,
        "FPR": fpr,
        "precision": precision,
        "F1": f1,
        "TP": tp,
        "FP": fp,
    }


def pick_operating_points(y_true: np.ndarray, y_score: np.ndarray) -> dict[str, dict]:
    thresholds = np.unique(y_score)
    grid = [metrics_at(y_true, y_score, t) for t in thresholds]

    # max-F1
    max_f1 = max(grid, key=lambda m: m["F1"])

    # ≈1% FPR: highest recall among points with FPR <= 0.01
    le = [m for m in grid if m["FPR"] <= 0.01]
    fpr1 = (
        max(le, key=lambda m: (m["detection_rate"], -m["threshold"])) if le else grid[0]
    )

    # full recall: lowest FPR among points achieving detection_rate == 1.0
    full = [m for m in grid if m["detection_rate"] >= 0.999]
    full_recall = min(full, key=lambda m: m["FPR"]) if full else max_f1

    return {"≈1% FPR": fpr1, "max-F1": max_f1, "full-recall": full_recall}


def save_curves(
    y_true: np.ndarray, y_score: np.ndarray, roc_auc: float, pr_auc: float, png: Path
) -> None:
    fpr, tpr, _ = roc_curve(y_true, y_score)
    prec, rec, _ = precision_recall_curve(y_true, y_score)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))
    ax1.plot(fpr, tpr, color="#c0392b", lw=2, label=f"ROC (AUC={roc_auc:.3f})")
    ax1.plot([0, 1], [0, 1], "--", color="gray", lw=1)
    ax1.set(xlabel="False Positive Rate", ylabel="True Positive Rate", title="UEBA ROC")
    ax1.legend(loc="lower right")
    ax1.grid(alpha=0.3)
    ax2.plot(rec, prec, color="#2c3e50", lw=2, label=f"PR (AP={pr_auc:.3f})")
    base = y_true.mean()
    ax2.axhline(base, ls="--", color="gray", lw=1, label=f"baseline={base:.3f}")
    ax2.set(xlabel="Recall", ylabel="Precision", title="UEBA Precision-Recall")
    ax2.legend(loc="upper right")
    ax2.grid(alpha=0.3)
    fig.suptitle("Prahari UEBA — behavioural weak-signal layer (unsupervised)")
    fig.tight_layout()
    png.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(png, dpi=120)
    plt.close(fig)


def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate UEBA scores vs ground truth.")
    ap.add_argument("--scores", type=Path, default=DEFAULT_SCORES)
    ap.add_argument("--ground-truth", type=Path, default=DEFAULT_GT)
    ap.add_argument("--png", type=Path, default=DEFAULT_PNG)
    args = ap.parse_args()

    df = load(args.scores, args.ground_truth)
    y_true = df["gt_malicious"].to_numpy()
    y_score = df["anomaly_score"].to_numpy()
    n_mal = int(y_true.sum())
    n_ben = int((~y_true).sum())

    roc_auc = roc_auc_score(y_true, y_score)
    pr_auc = average_precision_score(y_true, y_score)

    print(f"events: {len(df)}  (malicious={n_mal}, benign={n_ben})")
    print(f"ROC-AUC: {roc_auc:.4f}    PR-AUC: {pr_auc:.4f}\n")

    points = pick_operating_points(y_true, y_score)
    print(
        f"{'operating point':<14} {'thresh':>7} {'detection':>10} {'FPR':>8} "
        f"{'precision':>10} {'F1':>7}  {'TP/FP':>8}"
    )
    print("-" * 74)
    for name, m in points.items():
        print(
            f"{name:<14} {m['threshold']:>7.3f} {m['detection_rate']:>10.3f} "
            f"{m['FPR']:>8.4f} {m['precision']:>10.3f} {m['F1']:>7.3f}  "
            f"{str(m['TP'])+'/'+str(m['FP']):>8}"
        )

    save_curves(y_true, y_score, roc_auc, pr_auc, args.png)
    print(f"\nSaved ROC/PR curves -> {args.png}")

    print("\nTOP-20 events by anomaly_score:")
    top = df.sort_values("anomaly_score", ascending=False).head(20)
    print(
        f"{'rank':>4} {'score':>6} {'mal':>4} {'stg':>3} {'tech':>6} "
        f"{'activity':>8}  reasons"
    )
    print("-" * 110)
    for i, (_, r) in enumerate(top.iterrows(), 1):
        mal = "YES" if r["gt_malicious"] else "."
        stg = int(r["gt_stage"]) if pd.notna(r["gt_stage"]) else ""
        tech = r["gt_technique"] if pd.notna(r["gt_technique"]) else ""
        reasons = ", ".join(json.loads(r["reasons"]))
        print(
            f"{i:>4} {r['anomaly_score']:>6.3f} {mal:>4} {str(stg):>3} {tech:>6} "
            f"{r['activity']:>8}  {reasons}"
        )

    # how many of the 13 malicious land in the top-K
    ranked = df.sort_values("anomaly_score", ascending=False).reset_index(drop=True)
    for k in (13, 20, 30):
        hit = int(ranked.head(k)["gt_malicious"].sum())
        print(f"  malicious in top-{k}: {hit}/{n_mal}")


if __name__ == "__main__":
    main()
