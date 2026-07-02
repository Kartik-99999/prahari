#!/usr/bin/env python3
"""Prahari UEBA scoring — UNSUPERVISED anomaly scoring + graph write-back.

Pipeline (no labels, no severity — see the integrity guardrail below):
  1. Load behavioural features (services/ueba/features.py).
  2. GUARDRAIL: assert the model matrix contains neither `severity` nor any
     `gt_*`/label column, and print the final feature-column list.
  3. Standardize the numeric matrix, fit two UNSUPERVISED pyod detectors —
     IsolationForest and ECOD — and calibrate each model's outlier score to
     [0,1] by percentile rank.  model_ensemble = mean(IF_pct, ECOD_pct).
  4. Compute an interpretable novelty_score = capped weighted sum of the
     boolean novelty/flag features.
  5. anomaly_score = 0.5*model_ensemble + 0.5*novelty_score  (documented).
  6. Build a per-event "reasons" list (top contributing behavioural features).
  7. Write anomaly_score + anomaly_reasons back onto every Neo4j relationship
     matching each event_id.

Ground truth / severity are NEVER read here.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from pyod.models.ecod import ECOD
from pyod.models.iforest import IForest
from scipy.stats import rankdata
from sklearn.preprocessing import StandardScaler

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.graph.schema import get_driver  # noqa: E402
from services.ueba.features import (  # noqa: E402
    FEATURE_COLUMNS,
    OT_FEATURE_COLUMNS,
    assert_no_leakage,
)

DEFAULT_FEATURES = _REPO_ROOT / "data" / "ueba_features.csv"
DEFAULT_SCORES = _REPO_ROOT / "data" / "ueba_scores.csv"

# novelty_score weights (the boolean novelty/flag features). External-facing
# signals are weighted highest because no benign traffic is external in this
# environment; off-hours is weaker (some legitimate admin work occurs at night).
NOVELTY_WEIGHTS = {
    "external_auth_src": 3.0,
    "first_external_auth_src": 3.0,
    "external_dst": 3.0,
    "new_external_dst_for_host": 3.0,
    "new_user_host": 2.0,
    "is_offhours": 2.0,
    "new_process_on_host": 1.5,
}
# OT-native novelty (G7): applied ONLY when the feature matrix contains the OT
# columns (i.e. the stream has Modbus traffic) — IT scoring is bit-identical.
# NB `ot_modbus_write` deliberately gets NO novelty weight: benign operator
# writes exist by design, so the flag informs the model ensemble only; novelty
# rewards a NEW writer→PLC pair, which is the behavioural signal.
NOVELTY_WEIGHTS_OT = {
    "ot_new_write_pair": 2.5,
    "ot_write_pair_rarity": 2.0,  # continuous [0,1] — keeps repeat rogue writes warm
}
NOVELTY_CAP = 4.0  # weighted sum at/above this saturates novelty_score to 1.0

MODEL_WEIGHT = 0.5
NOVELTY_WEIGHT = 0.5

# Human-readable reason templates and their display priority (higher first).
REASON_RULES = [
    ("first_external_auth_src", 100, "first-ever external authentication source"),
    ("external_auth_src", 95, "authentication from an external IP"),
    ("ot_new_write_pair", 92, "first Modbus WRITE from this host to this PLC"),
    ("new_external_dst_for_host", 90, "new external destination for host"),
    ("external_dst", 85, "connection to an external IP"),
    ("new_user_host", 70, "new user→host pairing"),
    ("new_process_on_host", 60, "previously-unseen process on host"),
    ("is_offhours", 50, "off-hours activity"),
    ("ot_modbus_write", 40, "Modbus control-plane write"),
    ("is_weekend", 30, "weekend activity"),
]


def percentile_rank(scores: np.ndarray) -> np.ndarray:
    """Calibrate raw outlier scores to [0,1] by average percentile rank."""
    return rankdata(scores, method="average") / len(scores)


def compute_novelty(df: pd.DataFrame) -> np.ndarray:
    raw = np.zeros(len(df))
    weights = dict(NOVELTY_WEIGHTS)
    weights.update({k: v for k, v in NOVELTY_WEIGHTS_OT.items() if k in df.columns})
    for col, w in weights.items():
        if col in df.columns:
            raw = raw + w * df[col].to_numpy()
    return np.minimum(raw / NOVELTY_CAP, 1.0)


def build_reasons(df: pd.DataFrame) -> list[list[str]]:
    reasons: list[list[str]] = []
    for _, row in df.iterrows():
        active = [(prio, text) for col, prio, text in REASON_RULES if row.get(col, 0)]
        if row.get("process_global_rarity", 0) >= 0.5:
            active.append((55, "globally rare process"))
        if row.get("ot_write_pair_rarity", 0) >= 0.2:
            active.append((58, "rare writer→PLC pair (Modbus)"))
        if row.get("distinct_hosts_touched", 0) >= 2:
            active.append(
                (45, f"touched {int(row['distinct_hosts_touched'])} hosts in 24h")
            )
        if row.get("distinct_external_dsts", 0) >= 1:
            active.append(
                (48, f"{int(row['distinct_external_dsts'])} external dst(s) in 24h")
            )
        active.sort(key=lambda x: -x[0])
        top = [text for _, text in active[:4]]
        reasons.append(top or ["statistical outlier (model ensemble only)"])
    return reasons


def score(features_csv: Path) -> pd.DataFrame:
    df = pd.read_csv(features_csv)

    # --- INTEGRITY GUARDRAIL ------------------------------------------------
    # Model columns = the frozen IT set + any OT-native columns the feature
    # builder emitted (present only for Modbus-bearing streams — see features.py).
    model_cols = FEATURE_COLUMNS + [c for c in OT_FEATURE_COLUMNS if c in df.columns]
    assert_no_leakage(model_cols)
    assert_no_leakage(list(df.columns))
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    assert not missing, f"missing feature columns: {missing}"
    print("INTEGRITY GUARDRAIL passed — model inputs contain no severity/gt_/label.")
    print(f"Feature columns ({len(model_cols)}): {model_cols}\n")

    X = df[model_cols].to_numpy(dtype=float)
    Xs = StandardScaler().fit_transform(X)

    iforest = IForest(n_estimators=200, random_state=42)
    iforest.fit(Xs)
    ecod = ECOD()
    ecod.fit(Xs)

    if_pct = percentile_rank(iforest.decision_scores_)
    ecod_pct = percentile_rank(ecod.decision_scores_)
    model_ensemble = (if_pct + ecod_pct) / 2.0

    novelty = compute_novelty(df)
    anomaly = MODEL_WEIGHT * model_ensemble + NOVELTY_WEIGHT * novelty

    out = df[["event_id", "entity", "ts", "activity"]].copy()
    out["if_score"] = if_pct.round(6)
    out["ecod_score"] = ecod_pct.round(6)
    out["model_ensemble"] = model_ensemble.round(6)
    out["novelty_score"] = novelty.round(6)
    out["anomaly_score"] = anomaly.round(6)
    out["reasons"] = [json.dumps(r) for r in build_reasons(df)]
    return out


def write_back(driver, scores: pd.DataFrame) -> int:
    rows = [
        {
            "event_id": r.event_id,
            "score": float(r.anomaly_score),
            "reasons": json.loads(r.reasons),
        }
        for r in scores.itertuples()
    ]
    cypher = """
    UNWIND $rows AS row
    MATCH ()-[r {event_id: row.event_id}]->()
    SET r.anomaly_score = row.score, r.anomaly_reasons = row.reasons
    RETURN count(r) AS updated
    """
    with driver.session() as s:
        rec = s.run(cypher, rows=rows).single()
        return rec["updated"] if rec else 0


def main() -> None:
    ap = argparse.ArgumentParser(description="UEBA unsupervised scoring + write-back.")
    ap.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    ap.add_argument("--out", type=Path, default=DEFAULT_SCORES)
    ap.add_argument("--no-write", action="store_true", help="skip Neo4j write-back")
    args = ap.parse_args()

    scores = score(args.features)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    scores.to_csv(args.out, index=False)
    print(f"Scored {len(scores)} events -> {args.out}")
    print("anomaly_score summary:")
    print(scores["anomaly_score"].describe().round(4).to_string())

    if not args.no_write:
        driver = get_driver()
        try:
            updated = write_back(driver, scores)
        finally:
            driver.close()
        print(
            f"\nWrote anomaly_score + anomaly_reasons onto {updated} Neo4j relationships."
        )


if __name__ == "__main__":
    main()
