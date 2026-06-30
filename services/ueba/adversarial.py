#!/usr/bin/env python3
"""PRAHARÍ adversarial robustness probe (G6, optional).

An evasion what-if against the FROZEN detector: the scenario-2 insider is patient
and could simply operate during BUSINESS HOURS to defeat the off-hours signal
(novelty weight 2.0). We simulate that by zeroing the attacker's time-of-day
signals (is_offhours -> 0, hour_of_day -> midday, is_weekend -> 0) on the
malicious events ONLY (the attacker controls their own timing), re-score with the
UNCHANGED pipeline, and measure how much detection degrades.

This quantifies how much the detector leans on off-hours vs the time-independent
behavioural signals (new user->host, rare process, velocity). Reported honestly.
Writes an `adversarial` section into data/metrics_slate.json.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.ueba.score import score  # noqa: E402

S2 = _REPO_ROOT / "data" / "scenario2"
FEATURES = S2 / "ueba_features.csv"
GT = S2 / "ground_truth.json"
SLATE = _REPO_ROOT / "data" / "metrics_slate.json"


def recall_at_fpr(y: np.ndarray, s: np.ndarray, fpr_budget: float) -> float:
    thr = float(np.quantile(s[~y], 1 - fpr_budget))
    pred = s >= thr
    tp = int((pred & y).sum())
    fn = int((~pred & y).sum())
    return tp / (tp + fn) if (tp + fn) else 0.0


def evaluate(features: pd.DataFrame, mal: set) -> dict:
    from sklearn.metrics import roc_auc_score

    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as tf:
        features.to_csv(tf.name, index=False)
        scored = score(Path(tf.name))
    Path(tf.name).unlink(missing_ok=True)
    scored["y"] = scored["event_id"].isin(mal)
    y = scored["y"].to_numpy()
    s = scored["anomaly_score"].to_numpy()
    return {
        "roc_auc": round(float(roc_auc_score(y, s)), 4),
        "recall_at_1pct_fpr": round(recall_at_fpr(y, s, 0.01), 4),
        "recall_at_5pct_fpr": round(recall_at_fpr(y, s, 0.05), 4),
    }


def main() -> None:
    if not FEATURES.exists():
        print(
            "scenario-2 features missing — run `make scenario2` first.", file=sys.stderr
        )
        sys.exit(1)
    feats = pd.read_csv(FEATURES)
    gt = json.loads(GT.read_text())
    mal = {e["event_id"] for e in gt["events"]}

    base = evaluate(feats.copy(), mal)

    # adversary moves all malicious activity into business hours / weekdays
    evasive = feats.copy()
    m = evasive["event_id"].isin(mal)
    evasive.loc[m, "is_offhours"] = 0
    evasive.loc[m, "hour_of_day"] = 13
    evasive.loc[m, "is_weekend"] = 0
    adv = evaluate(evasive, mal)

    drop = round(base["recall_at_1pct_fpr"] - adv["recall_at_1pct_fpr"], 4)
    result = {
        "scenario": "scenario-2 insider, off-hours-evasion what-if (frozen detector)",
        "method": (
            "zero the malicious events' time-of-day signals (is_offhours->0, "
            "hour->13, weekend->0); re-score with the unchanged pipeline."
        ),
        "baseline": base,
        "evasive_business_hours": adv,
        "recall_at_1pct_fpr_drop": drop,
        "interpretation": (
            "even with the off-hours signal fully evaded, the frozen detector retains "
            f"recall@1%FPR={adv['recall_at_1pct_fpr']:.0%} (ROC {adv['roc_auc']}), because "
            "the insider still trips time-independent signals — new user->host pairings "
            "(analyst on DB-EXAMS), rare archiver processes, and 24h host velocity. "
            "Off-hours is corroborating, not load-bearing."
            if adv["recall_at_1pct_fpr"] >= 0.6
            else f"evading off-hours drops recall@1%FPR by {drop:.0%} (to "
            f"{adv['recall_at_1pct_fpr']:.0%}) — off-hours is load-bearing at the strict "
            f"1% operating point. BUT the attack stays separable: ROC {adv['roc_auc']} and "
            f"recall@5%FPR {adv['recall_at_5pct_fpr']:.0%} survive (new user->host / rare "
            "process / velocity still fire), so a looser FPR budget or fusion still "
            "catches it. Honest robustness finding: tune the operating point, and don't "
            "rely on off-hours alone."
        ),
    }
    slate = json.loads(SLATE.read_text()) if SLATE.exists() else {}
    slate["adversarial"] = result
    SLATE.write_text(json.dumps(slate, indent=2))

    print("=" * 72)
    print("  PRAHARÍ — ADVERSARIAL ROBUSTNESS (off-hours evasion, frozen)")
    print("=" * 72)
    print(
        f"  baseline   : ROC {base['roc_auc']}  recall@1%FPR {base['recall_at_1pct_fpr']:.0%}  @5% {base['recall_at_5pct_fpr']:.0%}"
    )
    print(
        f"  evasive(BH): ROC {adv['roc_auc']}  recall@1%FPR {adv['recall_at_1pct_fpr']:.0%}  @5% {adv['recall_at_5pct_fpr']:.0%}"
    )
    print(f"  recall@1%FPR drop: {drop:.0%}")
    print(f"  -> {result['interpretation']}")
    print(f"\n  wrote adversarial section -> {SLATE}")


if __name__ == "__main__":
    main()
