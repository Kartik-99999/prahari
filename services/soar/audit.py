#!/usr/bin/env python3
"""Prahari tamper-evident audit ledger (Postgres, hash-chained).

Schema: audit_ledger(seq, ts, actor, action, target, decision, rationale,
evidence jsonb, blast_radius, result jsonb, policy_version, model_version,
prev_hash, entry_hash).

  entry_hash = SHA256(canonical_json(ALL fields except entry_hash, INCLUDING
               prev_hash and seq)). Genesis prev_hash = 64 zeros.
  append(entry)      : set prev_hash = last entry_hash, compute entry_hash, insert.
  verify_chain()     : walk by seq; recompute each entry_hash (must match stored)
                       AND prev_hash must equal the previous row's entry_hash.

Append-only is enforced at the DB layer: a BEFORE UPDATE OR DELETE trigger
RAISES, so rows cannot be quietly altered. (TRUNCATE — used for the idempotent
clear+rebuild — does not fire row triggers and is reserved for the pipeline.)
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(_REPO_ROOT / ".env")

GENESIS = "0" * 64
MIGRATION = _REPO_ROOT / "services" / "soar" / "migrations" / "audit_ledger.sql"

DDL = """
CREATE TABLE IF NOT EXISTS audit_ledger (
    seq            BIGSERIAL PRIMARY KEY,
    ts             timestamptz NOT NULL,
    actor          text NOT NULL,
    action         text NOT NULL,
    target         text,
    decision       text,
    rationale      text,
    evidence       jsonb,
    blast_radius   text,
    result         jsonb,
    policy_version text,
    model_version  text,
    prev_hash      text NOT NULL,
    entry_hash     text NOT NULL
);

CREATE OR REPLACE FUNCTION audit_ledger_no_mutate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_ledger is append-only: % on seq % rejected',
        TG_OP, OLD.seq;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_ledger_append_only ON audit_ledger;
CREATE TRIGGER audit_ledger_append_only
    BEFORE UPDATE OR DELETE ON audit_ledger
    FOR EACH ROW EXECUTE FUNCTION audit_ledger_no_mutate();
"""

# fields that go into the hash, in a fixed list (seq + content + prev_hash)
HASH_FIELDS = [
    "seq",
    "ts",
    "actor",
    "action",
    "target",
    "decision",
    "rationale",
    "evidence",
    "blast_radius",
    "result",
    "policy_version",
    "model_version",
    "prev_hash",
]


def get_conn() -> psycopg.Connection:
    return psycopg.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=int(os.getenv("POSTGRES_PORT", "5433")),
        user=os.getenv("POSTGRES_USER", "prahari"),
        password=os.getenv("POSTGRES_PASSWORD", "prahari_dev"),
        dbname=os.getenv("POSTGRES_DB", "prahari"),
    )


def _canon_ts(ts) -> str:
    """Canonical UTC microsecond ISO string (stable across DB round-trip)."""
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def canonical_payload(row: dict) -> dict:
    """Build the exact dict that gets hashed (deterministic across append/verify)."""
    return {
        "seq": int(row["seq"]),
        "ts": _canon_ts(row["ts"]),
        "actor": row["actor"],
        "action": row["action"],
        "target": row.get("target"),
        "decision": row.get("decision"),
        "rationale": row.get("rationale"),
        "evidence": row.get("evidence") or {},
        "blast_radius": row.get("blast_radius"),
        "result": row.get("result") or {},
        "policy_version": row.get("policy_version"),
        "model_version": row.get("model_version"),
        "prev_hash": row["prev_hash"],
    }


def compute_hash(row: dict) -> str:
    payload = canonical_payload(row)
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def build_schema(conn: psycopg.Connection | None = None) -> None:
    own = conn is None
    conn = conn or get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(DDL)
        conn.commit()
    finally:
        if own:
            conn.close()


def clear(conn: psycopg.Connection | None = None) -> None:
    """Idempotent rebuild: TRUNCATE (does not fire the row-level append-only trigger)."""
    own = conn is None
    conn = conn or get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE audit_ledger RESTART IDENTITY")
        conn.commit()
    finally:
        if own:
            conn.close()


def append(entry: dict, conn: psycopg.Connection | None = None) -> dict:
    own = conn is None
    conn = conn or get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT seq, entry_hash FROM audit_ledger ORDER BY seq DESC LIMIT 1"
            )
            last = cur.fetchone()
            prev_hash = last[1] if last else GENESIS
            next_seq = (last[0] + 1) if last else 1
            row = {
                "seq": next_seq,
                "ts": entry.get("ts") or datetime.now(timezone.utc),
                "actor": entry["actor"],
                "action": entry["action"],
                "target": entry.get("target"),
                "decision": entry.get("decision"),
                "rationale": entry.get("rationale"),
                "evidence": entry.get("evidence") or {},
                "blast_radius": entry.get("blast_radius"),
                "result": entry.get("result") or {},
                "policy_version": entry.get("policy_version"),
                "model_version": entry.get("model_version"),
                "prev_hash": prev_hash,
            }
            entry_hash = compute_hash(row)
            cur.execute(
                """
                INSERT INTO audit_ledger
                  (seq, ts, actor, action, target, decision, rationale, evidence,
                   blast_radius, result, policy_version, model_version,
                   prev_hash, entry_hash)
                VALUES (%(seq)s, %(ts)s, %(actor)s, %(action)s, %(target)s,
                   %(decision)s, %(rationale)s, %(evidence)s, %(blast_radius)s,
                   %(result)s, %(policy_version)s, %(model_version)s,
                   %(prev_hash)s, %(entry_hash)s)
                """,
                {
                    **row,
                    "ts": _to_dt(row["ts"]),
                    "evidence": Jsonb(row["evidence"]),
                    "result": Jsonb(row["result"]),
                    "entry_hash": entry_hash,
                },
            )
        conn.commit()
        return {"seq": next_seq, "entry_hash": entry_hash, "prev_hash": prev_hash}
    finally:
        if own:
            conn.close()


def _to_dt(ts):
    if isinstance(ts, str):
        return datetime.fromisoformat(ts)
    return ts


def verify_chain(conn: psycopg.Connection | None = None) -> dict:
    own = conn is None
    conn = conn or get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT seq, ts, actor, action, target, decision, rationale, evidence,
                       blast_radius, result, policy_version, model_version,
                       prev_hash, entry_hash
                FROM audit_ledger ORDER BY seq
                """)
            cols = [d.name for d in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        if own:
            conn.close()

    prev = GENESIS
    for row in rows:
        recomputed = compute_hash(row)
        if recomputed != row["entry_hash"]:
            return {
                "ok": False,
                "broken_seq": row["seq"],
                "reason": "entry_hash mismatch (row contents were altered)",
                "stored_hash": row["entry_hash"][:12],
                "recomputed_hash": recomputed[:12],
            }
        if row["prev_hash"] != prev:
            return {
                "ok": False,
                "broken_seq": row["seq"],
                "reason": "prev_hash does not match previous entry_hash "
                "(row inserted/removed/reordered)",
                "expected_prev": prev[:12],
                "stored_prev": row["prev_hash"][:12],
            }
        prev = row["entry_hash"]
    return {
        "ok": True,
        "entries": len(rows),
        "head_hash": (rows[-1]["entry_hash"][:12] if rows else None),
    }


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Audit ledger build / verify.")
    ap.add_argument("cmd", choices=["build", "verify"], nargs="?", default="verify")
    args = ap.parse_args()
    if args.cmd == "build":
        build_schema()
        MIGRATION.parent.mkdir(parents=True, exist_ok=True)
        MIGRATION.write_text(DDL.strip() + "\n")
        print("audit_ledger schema + append-only trigger applied.")
        print(f"DDL migration written to {MIGRATION}")
    else:
        res = verify_chain()
        print(json.dumps(res, indent=2))
        sys.exit(0 if res["ok"] else 1)


if __name__ == "__main__":
    main()
