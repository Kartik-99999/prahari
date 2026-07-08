#!/usr/bin/env python3
"""ML-3: peer-group behavioural deviation (opt-in, PRAHARI_PEER_FEATURES=1).

Classic UEBA move: don't just score an entity against its OWN history — score it
against the behaviour of its PEER GROUP. Entities are clustered by their aggregate
behaviour profile (KMeans over the mean standardized feature vector per entity);
each event then gets `peer_deviation` = how far the event's behaviour sits from its
entity's peer-group centroid, percentile-normalised to [0,1].

Why it helps where self-history and time-of-day fail: the adversarial off-hours
evasion (recall@1%FPR collapses to 13%) works by zeroing the `is_offhours` signal —
but a clerk account reaching PostgreSQL, or spawning pg_dump, still deviates hard
from what *other clerk-role accounts* ever do, regardless of the hour. Peer-relative
rarity is time-agnostic.

Deterministic (seeded). No labels, no severity, no lookahead beyond the batch — in
production the peer clusters are recomputed on a rolling window; here the eval batch
IS the window. Post-pass by design; the streaming FeatureBuilder stays O(1)/event.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import rankdata
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.ueba.features import FEATURE_COLUMNS  # noqa: E402

PEER_K = 6  # target peer groups (clamped to the entity count)
SEED = 42


def add_peer_features(df: pd.DataFrame, k: int = PEER_K, seed: int = SEED) -> pd.DataFrame:
    """Return a copy of `df` with a `peer_deviation` column in [0,1]."""
    df = df.copy()
    cols = [c for c in FEATURE_COLUMNS if c in df.columns]
    Xs = StandardScaler().fit_transform(df[cols].to_numpy(dtype=float))

    # per-entity behaviour profile = mean standardized feature vector
    prof = pd.DataFrame(Xs, columns=cols)
    prof["entity"] = df["entity"].to_numpy()
    centroid_by_entity = prof.groupby("entity")[cols].mean()

    kk = min(k, len(centroid_by_entity))
    if kk < 2:  # not enough entities to form peer groups
        df["peer_deviation"] = 0.0
        return df

    km = KMeans(n_clusters=kk, random_state=seed, n_init=10)
    entity_cluster = dict(
        zip(centroid_by_entity.index, km.fit_predict(centroid_by_entity.to_numpy()))
    )
    ev_cluster = df["entity"].map(entity_cluster).to_numpy()

    # peer centroid = mean event-feature vector over ALL events of the cluster's
    # members (the peer group's behavioural centre of mass)
    peer_centroid = {
        c: Xs[ev_cluster == c].mean(axis=0)
        for c in range(kk)
        if (ev_cluster == c).any()
    }
    dev = np.linalg.norm(
        Xs - np.array([peer_centroid[c] for c in ev_cluster]), axis=1
    )
    df["peer_deviation"] = (rankdata(dev, method="average") / len(dev)).round(6)
    return df
