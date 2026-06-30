#!/usr/bin/env python3
"""PRAHARÍ scalability benchmark (G5).

Measures end-to-end throughput and memory of the detection pipeline at scale, and
Neo4j ingest + query latency, WITHOUT touching the scenario-1 demo graph (it uses
a dedicated :ScaleEvent label and DETACH DELETEs it afterwards).

Stages measured (events/sec):
  * generate   — synthetic OCSF event stream
  * features   — FROZEN streaming FeatureBuilder (services/ueba/features.py)
  * score      — FROZEN detector core: StandardScaler + IsolationForest(200) +
                 ECOD + percentile calibration (the scalable ML core; the O(n)
                 human-readable reason formatting is excluded and noted)

Also: peak resident memory (RSS), and Neo4j ingest rate + a representative
aggregation-query latency on a bounded :ScaleEvent set.

Deterministic (seeded). Writes a `scale` section into data/metrics_slate.json.
"""

from __future__ import annotations

import argparse
import json
import random
import resource
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
from pyod.models.ecod import ECOD
from pyod.models.iforest import IForest
from scipy.stats import rankdata
from sklearn.preprocessing import StandardScaler

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.ueba.features import (  # noqa: E402
    FEATURE_COLUMNS,
    META_COLUMNS,
    FeatureBuilder,
)

SLATE = _REPO_ROOT / "data" / "metrics_slate.json"

USERS = [f"user.{i:03d}" for i in range(80)]
HOSTS = [f"WS{i:03d}" for i in range(60)] + ["DC01", "DB-EXAMS", "FILESVR", "APPSVR"]
HOST_IP = {h: f"10.20.{i // 250}.{i % 250 + 1}" for i, h in enumerate(HOSTS)}
INTERNAL_IPS = set(HOST_IP.values())
PROCS = [
    "explorer.exe",
    "chrome.exe",
    "powershell.exe",
    "python",
    "java",
    "svchost.exe",
]
ACTS = ["network", "process", "auth", "file"]


def peak_rss_mb() -> float:
    ru = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS reports bytes; Linux reports kilobytes.
    return ru / (1024 * 1024) if sys.platform == "darwin" else ru / 1024


def generate(n: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    base = datetime(2026, 1, 1)
    out = []
    for i in range(n):
        u = rng.choice(USERS)
        h = rng.choice(HOSTS)
        act = rng.choice(ACTS)
        ts = (base + timedelta(seconds=i * 3)).isoformat()
        ev = {
            "event_id": f"se-{i}",
            "timestamp": ts,
            "activity": act,
            "actor": {"user": u, "host": h},
            "src": {"ip": HOST_IP[h], "port": rng.randint(1024, 65535)},
            "dst": {},
            "process": {},
            "file": {},
        }
        if act == "network":
            # ~3% external destinations to exercise the external-flag features
            if rng.random() < 0.03:
                ev["dst"] = {"ip": f"203.0.113.{rng.randint(1, 254)}", "port": 443}
            else:
                ev["dst"] = {
                    "ip": HOST_IP[rng.choice(HOSTS)],
                    "port": rng.choice([445, 389, 5432]),
                }
        elif act == "process":
            ev["process"] = {
                "name": rng.choice(PROCS),
                "pid": rng.randint(100, 9999),
                "cmdline": "",
            }
        elif act == "auth":
            ev["dst"] = {"ip": HOST_IP["DC01"], "port": 88}
        elif act == "file":
            ev["file"] = {"path": f"/data/{u}/f{rng.randint(0, 50)}.dat"}
        out.append(ev)
    return out


def score_core(df: pd.DataFrame) -> np.ndarray:
    """FROZEN detector ML core (excludes O(n) reason-string formatting)."""
    X = df[FEATURE_COLUMNS].to_numpy(dtype=float)
    Xs = StandardScaler().fit_transform(X)
    iforest = IForest(n_estimators=200, random_state=42)
    iforest.fit(Xs)
    ecod = ECOD()
    ecod.fit(Xs)
    if_pct = rankdata(iforest.decision_scores_, method="average") / len(df)
    ecod_pct = rankdata(ecod.decision_scores_, method="average") / len(df)
    return (if_pct + ecod_pct) / 2.0


def bench_size(n: int, seed: int) -> dict:
    t = time.perf_counter()
    events = generate(n, seed)
    gen_s = time.perf_counter() - t

    fb = FeatureBuilder(INTERNAL_IPS)
    t = time.perf_counter()
    rows = [fb.row(e) for e in events]
    feat_s = time.perf_counter() - t
    df = pd.DataFrame(rows, columns=META_COLUMNS + FEATURE_COLUMNS)

    t = time.perf_counter()
    _ = score_core(df)
    score_s = time.perf_counter() - t

    total = gen_s + feat_s + score_s
    return {
        "events": n,
        "generate_evts_per_sec": round(n / gen_s),
        "features_evts_per_sec": round(n / feat_s),
        "score_core_evts_per_sec": round(n / score_s),
        "end_to_end_evts_per_sec": round(n / total),
        "generate_s": round(gen_s, 2),
        "features_s": round(feat_s, 2),
        "score_core_s": round(score_s, 2),
        "peak_rss_mb": round(peak_rss_mb(), 1),
    }


def bench_neo4j(n_nodes: int, seed: int) -> dict:
    """Ingest n_nodes :ScaleEvent into Neo4j, time it + a query, then clean up.

    Uses a DEDICATED label and DETACH DELETEs it so the scenario-1 demo graph is
    untouched. Returns {} if Neo4j is unavailable.
    """
    try:
        from services.graph.schema import get_driver

        driver = get_driver()
    except Exception as e:  # noqa: BLE001
        return {"available": False, "error": str(e)}

    rng = random.Random(seed)
    base = datetime(2026, 1, 1)
    payload = [
        {
            "id": f"sc-{i}",
            "host": rng.choice(HOSTS),
            "user": rng.choice(USERS),
            "ts": (base + timedelta(seconds=i)).isoformat(),
            "score": round(rng.random(), 4),
        }
        for i in range(n_nodes)
    ]
    out: dict = {"available": True, "nodes": n_nodes}
    try:
        with driver.session() as s:
            s.run("MATCH (n:ScaleEvent) DETACH DELETE n")  # clean slate
            s.run(
                "CREATE INDEX scaleevent_id IF NOT EXISTS FOR (n:ScaleEvent) ON (n.id)"
            )
            t = time.perf_counter()
            B = 5000
            for i in range(0, n_nodes, B):
                s.run(
                    "UNWIND $rows AS r CREATE (n:ScaleEvent) SET n = r",
                    rows=payload[i : i + B],
                )
            ingest_s = time.perf_counter() - t
            out["ingest_s"] = round(ingest_s, 2)
            out["ingest_nodes_per_sec"] = round(n_nodes / ingest_s)

            # representative aggregation query (top hosts by mean score)
            t = time.perf_counter()
            rec = s.run(
                "MATCH (n:ScaleEvent) RETURN n.host AS host, count(*) AS c, "
                "avg(n.score) AS m ORDER BY m DESC LIMIT 10"
            ).data()
            out["query_ms"] = round((time.perf_counter() - t) * 1000, 1)
            out["query_rows"] = len(rec)
    finally:
        with driver.session() as s:
            s.run(
                "MATCH (n:ScaleEvent) DETACH DELETE n"
            )  # cleanup — leave demo graph pristine
        driver.close()
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="PRAHARÍ scalability benchmark.")
    ap.add_argument(
        "--sizes", default="10000,100000,1000000", help="comma-separated event counts"
    )
    ap.add_argument("--neo4j-nodes", type=int, default=100000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--no-neo4j", action="store_true")
    args = ap.parse_args()

    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    print("=" * 84)
    print("  PRAHARÍ — SCALABILITY BENCHMARK")
    print("=" * 84)
    print(
        f"  {'events':>10} {'gen/s':>10} {'feat/s':>10} {'score/s':>10} "
        f"{'e2e/s':>10} {'peakRSS_MB':>11}"
    )
    print("  " + "-" * 70)
    rows = []
    for n in sizes:
        r = bench_size(n, args.seed)
        rows.append(r)
        print(
            f"  {r['events']:>10,} {r['generate_evts_per_sec']:>10,} "
            f"{r['features_evts_per_sec']:>10,} {r['score_core_evts_per_sec']:>10,} "
            f"{r['end_to_end_evts_per_sec']:>10,} {r['peak_rss_mb']:>11.1f}"
        )

    neo = {} if args.no_neo4j else bench_neo4j(args.neo4j_nodes, args.seed)
    if neo.get("available"):
        print(
            f"\n  Neo4j: ingested {neo['nodes']:,} :ScaleEvent nodes in "
            f"{neo['ingest_s']}s ({neo['ingest_nodes_per_sec']:,}/s); "
            f"aggregation query {neo['query_ms']} ms (cleaned up)."
        )
    elif neo:
        print(
            f"\n  Neo4j: unavailable ({neo.get('error', '')[:60]}) — compute metrics still valid."
        )

    section = {
        "note": (
            "synthetic OCSF stream through the FROZEN feature + detector core; "
            "score throughput is the ML core (StandardScaler+IForest(200)+ECOD+"
            "percentile), excluding the O(n) reason-string formatting. Single "
            "process, no GPU."
        ),
        "host_platform": sys.platform,
        "sizes": rows,
        "neo4j": neo,
    }
    slate = json.loads(SLATE.read_text()) if SLATE.exists() else {}
    slate["scale"] = section
    SLATE.write_text(json.dumps(slate, indent=2))
    print(f"\n  wrote scale section -> {SLATE}")


if __name__ == "__main__":
    main()
