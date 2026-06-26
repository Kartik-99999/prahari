#!/usr/bin/env python3
"""Cypher query runner for the Prahari provenance graph.

Subcommands:
  stats     node counts by label + relationship counts by type
  killchain malicious edges in temporal order (the reconstructed kill chain)
  lateral   WS03 -> ... -> DB-EXAMS lateral-movement paths (distinct + kill-chain)
  crown     host degree ranking (crown-jewel exposure)
  all       run everything
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.graph.schema import get_driver  # noqa: E402


def _run(session, cypher: str, **params):
    return [r.data() for r in session.run(cypher, **params)]


def _table(rows: list[dict], cols: list[str]) -> None:
    if not rows:
        print("  (no rows)")
        return
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    print("  " + "  ".join(c.ljust(widths[c]) for c in cols))
    print("  " + "  ".join("-" * widths[c] for c in cols))
    for r in rows:
        print("  " + "  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))


def stats(session) -> None:
    print("\n# node counts by label")
    rows = _run(
        session,
        "MATCH (n) RETURN labels(n)[0] AS label, count(*) AS count ORDER BY label",
    )
    _table(rows, ["label", "count"])
    print(f"  total nodes: {sum(r['count'] for r in rows)}")

    print("\n# relationship counts by type")
    rows = _run(
        session,
        "MATCH ()-[r]->() RETURN type(r) AS rel, count(*) AS count ORDER BY rel",
    )
    _table(rows, ["rel", "count"])
    print(f"  total relationships: {sum(r['count'] for r in rows)}")


def killchain(session) -> None:
    print("\n# malicious edges in temporal order (gt_malicious=true)")
    rows = _run(
        session,
        """
        MATCH ()-[r]->() WHERE r.gt_malicious
        RETURN r.gt_attack_stage AS stage, r.gt_technique AS tech,
               type(r) AS rel, toString(r.ts) AS ts
        ORDER BY r.ts
    """,
    )
    _table(rows, ["stage", "tech", "rel", "ts"])
    stages = sorted({r["stage"] for r in rows if r["stage"] is not None})
    print(f"  distinct malicious edges: {len(rows)} | stages present: {stages}")


def lateral(session) -> None:
    print("\n# lateral paths WS03 -> DB-EXAMS (distinct host sequences, *1..3 REACHED)")
    rows = _run(
        session,
        """
        MATCH p=(a:Host {name:'WS03'})-[:REACHED*1..3]->(b:Host {name:'DB-EXAMS'})
        WITH DISTINCT [n IN nodes(p) | n.name] AS hops
        RETURN hops, size(hops) AS len ORDER BY len
    """,
    )
    _table(rows, ["hops", "len"])

    print("\n# kill-chain lateral path (edges all malicious) — hops + times")
    rows = _run(
        session,
        """
        MATCH p=(a:Host {name:'WS03'})-[:REACHED*1..3]->(b:Host {name:'DB-EXAMS'})
        WHERE all(r IN relationships(p) WHERE r.gt_malicious)
        RETURN DISTINCT [n IN nodes(p) | n.name] AS hops,
               [r IN relationships(p) | r.via] AS via,
               [r IN relationships(p) | toString(r.ts)] AS times
    """,
    )
    _table(rows, ["hops", "via", "times"])


def crown(session) -> None:
    print("\n# crown-jewel exposure — host degree ranking")
    rows = _run(
        session,
        """
        MATCH (h:Host)-[r]-()
        RETURN h.name AS host, count(r) AS degree ORDER BY degree DESC
    """,
    )
    _table(rows, ["host", "degree"])


DISPATCH = {"stats": stats, "killchain": killchain, "lateral": lateral, "crown": crown}


def main() -> None:
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    driver = get_driver()
    try:
        with driver.session() as session:
            if which == "all":
                for fn in (stats, killchain, lateral, crown):
                    fn(session)
            elif which in DISPATCH:
                DISPATCH[which](session)
            else:
                print(f"unknown query '{which}'; choose from {list(DISPATCH)} or 'all'")
                sys.exit(2)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
