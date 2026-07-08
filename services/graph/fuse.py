#!/usr/bin/env python3
"""Prahari graph fusion — weak-signal correlation via personalized PageRank.

Builds an event-similarity graph (networkx) over all events:
  * nodes  = events (event_id)
  * edge   = two events SHARE an entity (user / host / process / file / external
             IP) AND |Δt| ≤ 48h
  * weight = sum(entity_rarity(shared entities)) × temporal_decay(|Δt|)
             where entity_rarity = IDF = log(N / df(entity)) so sharing a rare
             entity (DB-EXAMS, an external C2 IP) weighs far more than sharing a
             busy workstation, and temporal_decay = exp(-|Δt| / 24h).

Then runs personalized PageRank whose teleport/restart vector is ∝ each event's
UEBA anomaly_score. This diffuses "anomaly heat": events connected to many/strong
anomalies rise (recovering weak-but-connected malicious events) while isolated
benign novelty — high anomaly but few/no anomalous neighbours — stays low.

The resulting fused_score is calibrated to [0,1] by percentile rank (comparable
to anomaly_score) and written back onto every Neo4j edge by event_id.

`build_similarity_graph()` and `load_event_data()` are reused by incidents.py.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

import networkx as nx
import pandas as pd
from scipy.stats import rankdata

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.graph.schema import get_driver, load_host_map  # noqa: E402

DEFAULT_EVENTS = _REPO_ROOT / "data" / "events.jsonl"
DEFAULT_SCORES = _REPO_ROOT / "data" / "ueba_scores.csv"

WINDOW = timedelta(hours=48)  # max |Δt| for an edge
DECAY_TAU_HOURS = 24.0  # temporal decay constant
PR_ALPHA = 0.85  # PageRank damping
MAX_ENTITY_EVENTS = 1500  # safety bound on per-entity pairing

# Entity kinds used to build the similarity graph. We deliberately EXCLUDE the
# user pivot: user behaviour is already captured in the UEBA anomaly_score
# (new_user_host, user_host_rarity), and connecting events by shared user would
# drag a compromised account's unrelated benign activity (e.g. admin.it's normal
# work on its home workstation) into the incident. Host / src-host / process /
# file / external-IP co-occurrence gives clean structural correlation, and the
# user identity is still recorded in incident metadata.
GRAPH_KINDS = frozenset({"host", "process", "file", "extip"})


def active_graph_kinds() -> frozenset:
    """Entity kinds for the similarity graph.

    ML-4 insider-aware fusion (PRAHARI_INSIDER_FUSION=1): add the USER pivot. For
    an external-C2 APT the extip anchor already threads the campaign, so the user
    pivot is excluded (it drags a compromised account's benign activity in). But a
    pure INSIDER attack has NO external anchor — its malicious events share little
    structural surface, which caps fusion recall (28/45 on scenario-2). Adding the
    user pivot reconnects an insider's own dispersed actions. Opt-in so the frozen
    scenario-1 fusion is untouched by default.
    """
    if os.getenv("PRAHARI_INSIDER_FUSION") == "1":
        return frozenset(GRAPH_KINDS | {"user"})
    return GRAPH_KINDS


def graph_entities(entities: dict) -> dict:
    """Project entities onto the kinds used for the similarity graph."""
    kinds = active_graph_kinds()
    return {eid: {e for e in es if e[0] in kinds} for eid, es in entities.items()}


def load_event_data(
    events_path: Path = DEFAULT_EVENTS, scores_path: Path = DEFAULT_SCORES
) -> tuple[pd.DataFrame, dict]:
    """Return (events_df, entities) — entities maps event_id -> set[(kind, value)].

    Reads only behavioural/structural fields (no labels). anomaly_score comes
    from the UEBA scores CSV.
    """
    hm = load_host_map()
    scores = pd.read_csv(scores_path).set_index("event_id")["anomaly_score"].to_dict()

    recs = []
    entities: dict[str, set] = {}
    with events_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            eid = e["event_id"]
            actor = e.get("actor") or {}
            user, host = actor.get("user"), actor.get("host")
            proc = e.get("process") or {}
            fil = e.get("file") or {}
            src_ip = (e.get("src") or {}).get("ip")
            dst_ip = (e.get("dst") or {}).get("ip")

            ent: set = set()
            if user:
                ent.add(("user", user))
            if host:
                ent.add(("host", host))
            # source host (remote/lateral origin) links movement back to its origin
            src_host = hm.resolve_host(src_ip)
            if src_host and src_host != host:
                ent.add(("host", src_host))
            if e["activity"] == "process" and proc.get("name"):
                ent.add(("process", f"{host}|{proc.get('pid')}|{proc.get('name')}"))
            if e["activity"] == "file" and fil.get("path"):
                ent.add(("file", f"{host}|{fil.get('path')}"))
            for ip in (src_ip, dst_ip):
                if ip and not hm.is_internal(ip):
                    ent.add(("extip", ip))

            entities[eid] = ent
            recs.append(
                {
                    "event_id": eid,
                    "ts": e["timestamp"],
                    "activity": e["activity"],
                    "user": user,
                    "host": host,
                    "anomaly_score": float(scores.get(eid, 0.0)),
                }
            )
    df = pd.DataFrame(recs)
    df["ts_dt"] = pd.to_datetime(df["ts"])
    df = df.sort_values("ts_dt").reset_index(drop=True)
    return df, entities


def compute_idf(entities: dict[str, set], n_events: int) -> dict[tuple, float]:
    df_count: dict[tuple, int] = defaultdict(int)
    for ent in entities.values():
        for e in ent:
            df_count[e] += 1
    return {e: math.log(n_events / c) for e, c in df_count.items()}


def build_similarity_graph(
    df: pd.DataFrame, entities: dict[str, set], idf: dict[tuple, float]
) -> nx.Graph:
    """Event-similarity graph: shared-entity edges within 48h, IDF×decay weighted."""
    # inverted index: entity -> [(ts, event_id)] sorted by ts
    index: dict[tuple, list] = defaultdict(list)
    ts_by_eid = dict(zip(df["event_id"], df["ts_dt"]))
    for eid, ent in entities.items():
        t = ts_by_eid[eid]
        for e in ent:
            index[e].append((t, eid))
    for lst in index.values():
        lst.sort(key=lambda x: x[0])

    pair_idf: dict[tuple, float] = defaultdict(float)
    pair_dt: dict[tuple, float] = {}
    for entity, lst in index.items():
        if len(lst) > MAX_ENTITY_EVENTS:
            continue  # ubiquitous entity: uninformative + avoids edge blow-up
        w = idf[entity]
        for j in range(len(lst)):
            tj, ej = lst[j]
            k = j - 1
            while k >= 0 and (tj - lst[k][0]) <= WINDOW:
                tk, ek = lst[k]
                key = (ej, ek) if ej < ek else (ek, ej)
                pair_idf[key] += w
                if key not in pair_dt:
                    pair_dt[key] = abs((tj - tk).total_seconds()) / 3600.0
                k -= 1

    g = nx.Graph()
    g.add_nodes_from(df["event_id"].tolist())
    for (u, v), shared_idf in pair_idf.items():
        weight = shared_idf * math.exp(-pair_dt[(u, v)] / DECAY_TAU_HOURS)
        if weight > 0:
            g.add_edge(u, v, weight=weight)
    return g


def run_fusion(g: nx.Graph, df: pd.DataFrame) -> pd.DataFrame:
    eps = 1e-9
    teleport = {r.event_id: float(r.anomaly_score) + eps for r in df.itertuples()}
    # Personalized PageRank: anomaly-seeded heat diffusion.
    pr = nx.pagerank(
        g,
        alpha=PR_ALPHA,
        personalization=teleport,
        weight="weight",
        max_iter=300,
        tol=1e-10,
    )
    # Uniform PageRank: structural baseline (pure centrality, no anomaly signal).
    base = nx.pagerank(g, alpha=PR_ALPHA, weight="weight", max_iter=300, tol=1e-10)
    # fused heat = LIFT of personalized over structural baseline. This removes the
    # structural-hub bias (busy benign workstations have high baseline PR, so a
    # high personalized PR there is unremarkable), isolating events that receive
    # disproportionate anomaly heat from their neighbourhood.
    df = df.copy()
    df["raw_pr"] = df["event_id"].map(pr)
    df["base_pr"] = df["event_id"].map(base)
    df["lift"] = df["raw_pr"] / (df["base_pr"] + 1e-15)
    # calibrate to [0,1] by percentile rank (comparable to anomaly_score)
    df["fused_score"] = (
        rankdata(df["lift"].to_numpy(), method="average") / len(df)
    ).round(6)
    return df


def write_back(driver, df: pd.DataFrame) -> int:
    rows = [
        {"event_id": r.event_id, "fused": float(r.fused_score)} for r in df.itertuples()
    ]
    cypher = """
    UNWIND $rows AS row
    MATCH ()-[r {event_id: row.event_id}]->()
    SET r.fused_score = row.fused
    RETURN count(r) AS updated
    """
    with driver.session() as s:
        rec = s.run(cypher, rows=rows).single()
        return rec["updated"] if rec else 0


def main() -> None:
    ap = argparse.ArgumentParser(description="Graph fusion via personalized PageRank.")
    ap.add_argument("--events", type=Path, default=DEFAULT_EVENTS)
    ap.add_argument("--scores", type=Path, default=DEFAULT_SCORES)
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args()

    df, entities = load_event_data(args.events, args.scores)
    gent = graph_entities(entities)
    idf = compute_idf(gent, len(df))
    g = build_similarity_graph(df, gent, idf)
    print(
        f"similarity graph: {g.number_of_nodes()} nodes, "
        f"{g.number_of_edges()} edges"
    )
    fused = run_fusion(g, df)

    # persist fused_score back into the scores CSV (used by incidents.py)
    scores = pd.read_csv(args.scores)
    scores = scores.drop(columns=[c for c in ("fused_score", "raw_pr") if c in scores])
    scores = scores.merge(
        fused[["event_id", "raw_pr", "fused_score"]], on="event_id", how="left"
    )
    scores.to_csv(args.scores, index=False)

    print("fused_score summary:")
    print(fused["fused_score"].describe().round(4).to_string())

    if not args.no_write:
        driver = get_driver()
        try:
            updated = write_back(driver, fused)
        finally:
            driver.close()
        print(f"\nWrote fused_score onto {updated} Neo4j relationships.")


if __name__ == "__main__":
    main()
