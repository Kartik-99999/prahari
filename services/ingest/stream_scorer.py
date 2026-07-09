#!/usr/bin/env python3
"""PRAHARÍ — streaming UEBA scorer (Phase-2 slice: detection on the wire).

A long-running consumer that scores the ``events:raw`` Redis stream CONTINUOUSLY,
per event, instead of in a batch pass. It:
  1. attaches to ``events:raw`` via a consumer group (replayable, at-least-once);
  2. WARMS UP on the first `--warmup` events, fitting the SAME frozen detector core
     (StandardScaler + IsolationForest(200) + ECOD) on that window;
  3. then scores every subsequent event in O(1) via the already-streaming
     `FeatureBuilder`, calibrating each raw score against the warmup distribution
     and combining with the interpretable novelty term — emitting a live
     `anomaly_score` and an ALERT for anything crossing the threshold.

This is the "runs on the wire, not on a file" capability. The detector is fit once
on the warmup window (a real deployment refits on a rolling window); no labels, no
severity — `assert_no_leakage` holds. Deterministic given the same stream + seed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import numpy as np
import redis
from pyod.models.ecod import ECOD
from pyod.models.iforest import IForest
from sklearn.preprocessing import StandardScaler

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from services.graph.schema import load_host_map  # noqa: E402
from services.ueba.features import FEATURE_COLUMNS, FeatureBuilder  # noqa: E402
from services.ueba.score import (  # noqa: E402
    NOVELTY_CAP,
    NOVELTY_WEIGHTS,
    build_reasons,
)

STREAM = "events:raw"


def _novelty(row: dict) -> float:
    raw = sum(w * float(row.get(c, 0)) for c, w in NOVELTY_WEIGHTS.items())
    return min(raw / NOVELTY_CAP, 1.0)


def _vec(row: dict) -> list[float]:
    return [float(row.get(c, 0.0)) for c in FEATURE_COLUMNS]


def main() -> None:
    ap = argparse.ArgumentParser(description="Streaming UEBA scorer (events:raw).")
    ap.add_argument("--redis-url", default=os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    ap.add_argument("--group", default="stream-score")
    ap.add_argument("--consumer", default="s1")
    ap.add_argument("--warmup", type=int, default=300, help="events to fit on before scoring")
    ap.add_argument("--alert", type=float, default=0.90, help="anomaly_score alert threshold")
    ap.add_argument("--idle-timeout", type=float, default=8.0, help="seconds of silence -> stop")
    args = ap.parse_args()

    r = redis.from_url(args.redis_url, decode_responses=True)
    r.ping()
    try:
        r.xgroup_create(name=STREAM, groupname=args.group, id="0", mkstream=True)
    except redis.ResponseError:
        pass  # group exists

    fb = FeatureBuilder(load_host_map().internal_ips)
    warm_rows: list[dict] = []
    warm_vecs: list[list[float]] = []
    scaler = iforest = ecod = None
    if_sorted = ecod_sorted = None

    scored = alerts = 0
    top: list[tuple] = []
    last_seen = time.time()
    print(f"[stream] warming up on first {args.warmup} events, then scoring live...", file=sys.stderr)

    while True:
        resp = r.xreadgroup(args.group, args.consumer, {STREAM: ">"}, count=200, block=1000)
        if not resp:
            if time.time() - last_seen > args.idle_timeout:
                break
            continue
        for _stream, messages in resp:
            for msg_id, fields in messages:
                last_seen = time.time()
                ev = json.loads(fields["data"])
                row = fb.row(ev)  # O(1) streaming features
                r.xack(STREAM, args.group, msg_id)

                if scaler is None:
                    warm_rows.append(row)
                    warm_vecs.append(_vec(row))
                    if len(warm_vecs) >= args.warmup:
                        X = np.array(warm_vecs, dtype=float)
                        scaler = StandardScaler().fit(X)
                        Xs = scaler.transform(X)
                        iforest = IForest(n_estimators=200, random_state=42).fit(Xs)
                        ecod = ECOD().fit(Xs)
                        if_sorted = np.sort(iforest.decision_scores_)
                        ecod_sorted = np.sort(ecod.decision_scores_)
                        print(f"[stream] fitted on {len(warm_vecs)} events — now scoring on the wire", file=sys.stderr)
                    continue

                xs = scaler.transform([_vec(row)])
                if_raw = float(iforest.decision_function(xs)[0])
                ecod_raw = float(ecod.decision_function(xs)[0])
                if_pct = np.searchsorted(if_sorted, if_raw) / len(if_sorted)
                ecod_pct = np.searchsorted(ecod_sorted, ecod_raw) / len(ecod_sorted)
                model = (if_pct + ecod_pct) / 2.0
                anomaly = 0.5 * model + 0.5 * _novelty(row)
                scored += 1
                top.append((anomaly, row.get("entity"), row.get("activity"), ev.get("event_id")))

                if anomaly >= args.alert:
                    alerts += 1
                    reason = build_reasons(_as_df(row))[0]
                    ts = str(ev.get("timestamp", ""))[:16]
                    print(f"  ⚠ ALERT  {anomaly:.2f}  {ts}  {row.get('entity')}/{row.get('activity')}  — {'; '.join(reason[:2])}")

    _summary(scored, alerts, top, args.alert)


def _as_df(row: dict):
    import pandas as pd

    return pd.DataFrame([row])


def _summary(scored: int, alerts: int, top: list[tuple], thr: float) -> None:
    print("\n" + "=" * 60)
    print("  PRAHARÍ — STREAMING SCORER (events:raw, live)")
    print("=" * 60)
    print(f"  events scored live : {scored}")
    print(f"  ALERTS (anomaly >= {thr}) : {alerts}")
    print("  top-5 anomalies:")
    for a, ent, act, eid in sorted(top, reverse=True)[:5]:
        print(f"    {a:.3f}  {ent}/{act}  {str(eid)[:8]}")


if __name__ == "__main__":
    main()
