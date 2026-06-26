#!/usr/bin/env python3
"""Prahari incident assembly — ranked incidents from fused weak signals.

Takes events whose fused_score ≥ τ, restricts the event-similarity graph to
them, finds connected components, then MERGES components that share a key entity
(user / host / external IP) within the campaign window (so a low-and-slow chain
whose stages are >48h apart is reassembled into a single incident). Each
incident is scored and ranked; the top incident should be the full kill chain.

incident_score (documented):
    sum(member anomaly_score)            # raw corroborated signal mass
  + 2.0 * n_hosts                        # breadth across hosts
  + 1.5 * n_external_dsts                # external (C2/exfil) destinations
  + 5.0 * has_lateral_path               # a :REACHED path exists among its hosts
  + 0.3 * span_days                      # low-and-slow persistence

Persists (:Incident) nodes + (:Incident)-[:INVOLVES]->(entity) edges into Neo4j
and writes data/incidents.json with full detail.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

import networkx as nx
import pandas as pd

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.graph.fuse import (  # noqa: E402
    build_similarity_graph,
    compute_idf,
    graph_entities,
    load_event_data,
)
from services.graph.schema import get_driver  # noqa: E402

DEFAULT_INCIDENTS = _REPO_ROOT / "data" / "incidents.json"

TAU = 0.90  # fused_score threshold for candidate events
CAMPAIGN_WINDOW = timedelta(days=30)  # merge components within this temporal span
KEY_KINDS = {"host", "extip"}  # entities used to merge components
MIN_EVENTS = 2  # drop singleton candidates

# incident_score weights. Structural attack indicators (a lateral :REACHED path,
# external C2/exfil destinations, breadth across hosts) dominate, so a focused
# kill chain outranks a large but shapeless benign cluster. The anomaly term uses
# mass ABOVE a baseline so a big cluster of merely-borderline events can't win on
# count alone.
W_HOSTS, W_EXTDST, W_LATERAL, W_SPAN = 3.0, 4.0, 12.0, 0.2
ANOM_BASELINE = 0.6


def _interval_gap(a1, a2, b1, b2) -> timedelta:
    """Gap between two [start,end] intervals (zero if they overlap)."""
    if a2 < b1:
        return b1 - a2
    if b2 < a1:
        return a1 - b2
    return timedelta(0)


def assemble(df: pd.DataFrame, entities: dict, g: nx.Graph) -> list[dict]:
    ts = dict(zip(df["event_id"], df["ts_dt"]))
    anomaly = dict(zip(df["event_id"], df["anomaly_score"]))

    high = set(df.loc[df["fused_score"] >= TAU, "event_id"])
    sub = g.subgraph(high)
    raw_components = [set(c) for c in nx.connected_components(sub)]

    # key entities + time interval per component
    comp_meta = []
    for comp in raw_components:
        kents: set = set()
        tss = []
        for eid in comp:
            kents |= {e for e in entities[eid] if e[0] in KEY_KINDS}
            tss.append(ts[eid])
        comp_meta.append(
            {"events": comp, "kents": kents, "lo": min(tss), "hi": max(tss)}
        )

    # merge components sharing a key entity within the campaign window
    meta = nx.Graph()
    meta.add_nodes_from(range(len(comp_meta)))
    for i in range(len(comp_meta)):
        for j in range(i + 1, len(comp_meta)):
            if comp_meta[i]["kents"] & comp_meta[j]["kents"]:
                gap = _interval_gap(
                    comp_meta[i]["lo"],
                    comp_meta[i]["hi"],
                    comp_meta[j]["lo"],
                    comp_meta[j]["hi"],
                )
                if gap <= CAMPAIGN_WINDOW:
                    meta.add_edge(i, j)

    incidents = []
    for group in nx.connected_components(meta):
        members: set = set()
        for idx in group:
            members |= comp_meta[idx]["events"]
        if len(members) < MIN_EVENTS:
            continue
        incidents.append(_build_incident(members, df, entities, ts, anomaly))
    incidents.sort(key=lambda x: x["incident_score"], reverse=True)
    for rank, inc in enumerate(incidents, 1):
        inc["id"] = f"INC-{rank:03d}"
    return incidents


def _build_incident(members, df, entities, ts, anomaly) -> dict:
    users, hosts, extips, procs, files = set(), set(), set(), set(), set()
    activities: set = set()
    for eid in members:
        for kind, val in entities[eid]:
            {
                "user": users,
                "host": hosts,
                "extip": extips,
                "process": procs,
                "file": files,
            }[kind].add(val)
    acts = df.loc[df["event_id"].isin(members), "activity"]
    activities = set(acts.unique())
    times = [ts[e] for e in members]
    first, last = min(times), max(times)
    span_days = (last - first).total_seconds() / 86400.0
    has_lateral = _has_lateral(hosts)
    sum_anom = float(sum(anomaly[e] for e in members))
    # mass ABOVE baseline: a large cluster of borderline events contributes little
    anom_mass = float(sum(max(0.0, anomaly[e] - ANOM_BASELINE) for e in members))

    score = (
        anom_mass
        + W_HOSTS * len(hosts)
        + W_EXTDST * len(extips)
        + W_LATERAL * (1 if has_lateral else 0)
        + W_SPAN * span_days
    )
    return {
        "incident_score": round(score, 3),
        "n_events": len(members),
        "first_seen": first.isoformat(),
        "last_seen": last.isoformat(),
        "span_days": round(span_days, 2),
        "users": sorted(users),
        "hosts": sorted(hosts),
        "external_ips": sorted(extips),
        "n_external_dsts": len(extips),
        "activities": sorted(activities),
        "has_lateral_path": has_lateral,
        "sum_anomaly": round(sum_anom, 3),
        "member_event_ids": sorted(members),
    }


_DRIVER = None


def _has_lateral(hosts: set[str]) -> bool:
    """True if a :REACHED path exists among the incident's hosts (Neo4j)."""
    if len(hosts) < 2:
        return False
    global _DRIVER
    if _DRIVER is None:
        _DRIVER = get_driver()
    q = """
    MATCH (a:Host)-[:REACHED]->(b:Host)
    WHERE a.name IN $hosts AND b.name IN $hosts
    RETURN count(*) AS c
    """
    with _DRIVER.session() as s:
        return s.run(q, hosts=list(hosts)).single()["c"] > 0


def persist(driver, incidents: list[dict]) -> None:
    with driver.session() as s:
        s.run("MATCH (i:Incident) DETACH DELETE i")
        for inc in incidents:
            s.run(
                """
                CREATE (i:Incident {
                    id: $id, score: $score, n_events: $n_events,
                    first_seen: datetime($first), last_seen: datetime($last),
                    hosts: $hosts, member_event_ids: $members,
                    has_lateral_path: $lateral, n_external_dsts: $next
                })
                """,
                id=inc["id"],
                score=inc["incident_score"],
                n_events=inc["n_events"],
                first=inc["first_seen"],
                last=inc["last_seen"],
                hosts=inc["hosts"],
                members=inc["member_event_ids"],
                lateral=inc["has_lateral_path"],
                next=inc["n_external_dsts"],
            )
            # link involved entities
            s.run(
                """
                MATCH (i:Incident {id: $id})
                WITH i
                UNWIND $hosts AS hn MATCH (h:Host {name: hn}) MERGE (i)-[:INVOLVES]->(h)
                """,
                id=inc["id"],
                hosts=inc["hosts"],
            )
            if inc["users"]:
                s.run(
                    """
                    MATCH (i:Incident {id: $id})
                    WITH i
                    UNWIND $users AS un MATCH (u:User {name: un}) MERGE (i)-[:INVOLVES]->(u)
                    """,
                    id=inc["id"],
                    users=inc["users"],
                )
            if inc["external_ips"]:
                s.run(
                    """
                    MATCH (i:Incident {id: $id})
                    WITH i
                    UNWIND $ips AS ip MATCH (n:IP {addr: ip}) MERGE (i)-[:INVOLVES]->(n)
                    """,
                    id=inc["id"],
                    ips=inc["external_ips"],
                )


def main() -> None:
    ap = argparse.ArgumentParser(description="Assemble ranked incidents.")
    ap.add_argument("--out", type=Path, default=DEFAULT_INCIDENTS)
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args()

    df, entities = load_event_data()
    # bring in fused_score (written by fuse.py into the scores CSV)
    fused = pd.read_csv(_REPO_ROOT / "data" / "ueba_scores.csv")[
        ["event_id", "fused_score"]
    ]
    df = df.merge(fused, on="event_id", how="left")
    gent = graph_entities(entities)
    idf = compute_idf(gent, len(df))
    g = build_similarity_graph(df, gent, idf)
    incidents = assemble(df, entities, g)

    print(
        f"τ={TAU}  candidate high-fused events: "
        f"{int((df['fused_score'] >= TAU).sum())}"
    )
    print(f"incidents raised: {len(incidents)}\n")
    print(f"{'id':<8}{'score':>8}{'n_ev':>6}{'hosts':>6}{'lat':>5}{'extdst':>7}  span")
    print("-" * 60)
    for inc in incidents[:10]:
        print(
            f"{inc['id']:<8}{inc['incident_score']:>8.2f}{inc['n_events']:>6}"
            f"{len(inc['hosts']):>6}{'Y' if inc['has_lateral_path'] else 'n':>5}"
            f"{inc['n_external_dsts']:>7}  {inc['span_days']}d {inc['hosts']}"
        )

    args.out.write_text(json.dumps(incidents, indent=2))
    print(f"\nWrote {args.out}")

    if not args.no_write:
        driver = get_driver()
        try:
            persist(driver, incidents)
        finally:
            driver.close()
        print(f"Persisted {len(incidents)} Incident nodes + INVOLVES edges to Neo4j.")


if __name__ == "__main__":
    main()
