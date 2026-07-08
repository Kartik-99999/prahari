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
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from pyod.models.copod import COPOD
from pyod.models.ecod import ECOD
from pyod.models.iforest import IForest
from scipy.stats import rankdata, spearmanr
from sklearn.preprocessing import StandardScaler

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.graph.schema import get_driver  # noqa: E402
from services.ueba.features import (  # noqa: E402
    FEATURE_COLUMNS,
    OT_FEATURE_COLUMNS,
    PEER_FEATURE_COLUMNS,
    SEQ_FEATURE_COLUMNS,
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

# --- ML-1 (opt-in, PRAHARI_ENSEMBLE3=1): third detector family + calibration ---
# Adds COPOD as a third UNSUPERVISED family, a label-free degeneracy guard (a
# detector that disagrees pathologically with the ensemble median or collapses to
# a constant is dropped — motivated by ECOD's val-ROC 0.086 faceplant on the
# CIC-IDS PortScan slice), and percentile calibration WITHIN activity-type
# stratum (network/process/auth/file have different benign tails; a global rank
# lets one activity's heavy tail crowd out the others at strict FPR budgets).
# Default OFF: the frozen, verified 2-family pipeline is bit-identical.
ENSEMBLE3 = os.getenv("PRAHARI_ENSEMBLE3") == "1"
MIN_STRATUM = 50  # strata smaller than this fall back to the global rank
DEGENERACY_MIN_CORR = 0.1  # Spearman vs mean-of-others below this -> drop

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


def stratified_percentile_rank(scores: np.ndarray, strata: pd.Series) -> np.ndarray:
    """Percentile-rank within each activity-type stratum (ML-1).

    Each activity type gets its own [0,1] calibration so no single activity's
    heavy benign tail monopolises the top global percentiles. Strata smaller
    than MIN_STRATUM keep the global rank (too few points to calibrate).
    """
    out = percentile_rank(scores)
    for _, idx in strata.groupby(strata).groups.items():
        if len(idx) >= MIN_STRATUM:
            pos = strata.index.get_indexer(idx)
            out[pos] = rankdata(scores[pos], method="average") / len(pos)
    return out


def _retain_detectors(pcts: dict[str, np.ndarray], raws: dict[str, np.ndarray]) -> list[str]:
    """Label-free degeneracy guard (ML-1, 3+ families only).

    Drop a detector whose raw scores are ~constant or whose percentile scores
    are uncorrelated/anti-correlated (Spearman < DEGENERACY_MIN_CORR) with the
    mean of the other detectors. Never leaves the ensemble empty.
    """
    names = list(pcts)
    retained = []
    for n in names:
        if float(np.std(raws[n])) < 1e-12:
            print(f"[ensemble3] dropping {n}: degenerate (constant scores)")
            continue
        others = [pcts[m] for m in names if m != n]
        corr = spearmanr(pcts[n], np.mean(others, axis=0)).statistic
        if not np.isfinite(corr) or corr < DEGENERACY_MIN_CORR:
            print(f"[ensemble3] dropping {n}: Spearman vs ensemble {corr:.3f}")
            continue
        retained.append(n)
    return retained or ["if"]


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
        if row.get("seq_transition_rarity", 0) >= 0.8:
            active.append((52, "rare behavioural transition for this entity"))
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

    # ML-3: peer-group deviation (post-pass over the full matrix). Opt-in; adds a
    # `peer_deviation` column that scores each event against its entity's PEER
    # GROUP, not just its own history — time-agnostic, so it survives off-hours
    # evasion. Default OFF => column absent => matrix bit-identical.
    if os.getenv("PRAHARI_PEER_FEATURES") == "1":
        from services.ueba.peer import add_peer_features

        df = add_peer_features(df)
        print("[score] ML-3 peer-group deviation feature ENABLED")

    # --- INTEGRITY GUARDRAIL ------------------------------------------------
    # Model columns = the frozen IT set + any OT-native columns the feature
    # builder emitted (present only for Modbus-bearing streams — see features.py).
    model_cols = FEATURE_COLUMNS + [
        c
        for c in OT_FEATURE_COLUMNS + SEQ_FEATURE_COLUMNS + PEER_FEATURE_COLUMNS
        if c in df.columns
    ]
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

    if ENSEMBLE3:
        # ML-1: third family + stratified calibration + degeneracy guard.
        copod = COPOD()
        copod.fit(Xs)
        raws = {
            "if": iforest.decision_scores_,
            "ecod": ecod.decision_scores_,
            "copod": copod.decision_scores_,
        }
        pcts = {
            n: stratified_percentile_rank(r, df["activity"]) for n, r in raws.items()
        }
        retained = _retain_detectors(pcts, raws)
        print(f"[ensemble3] families={list(raws)} retained={retained} (stratified calibration)")
        if_pct, ecod_pct = pcts["if"], pcts["ecod"]
        model_ensemble = np.mean([pcts[n] for n in retained], axis=0)
        copod_pct = pcts["copod"]
    else:
        if_pct = percentile_rank(iforest.decision_scores_)
        ecod_pct = percentile_rank(ecod.decision_scores_)
        model_ensemble = (if_pct + ecod_pct) / 2.0
        copod_pct = None

    novelty = compute_novelty(df)
    anomaly = MODEL_WEIGHT * model_ensemble + NOVELTY_WEIGHT * novelty

    out = df[["event_id", "entity", "ts", "activity"]].copy()
    out["if_score"] = if_pct.round(6)
    out["ecod_score"] = ecod_pct.round(6)
    if copod_pct is not None:
        out["copod_score"] = copod_pct.round(6)
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
