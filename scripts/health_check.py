#!/usr/bin/env python3
"""Health check: ping Neo4j, Redis, and Postgres. Exit non-zero on any failure."""

import os
import sys

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

results: list[tuple[str, bool, str]] = []


def check_neo4j() -> tuple[bool, str]:
    try:
        from neo4j import GraphDatabase

        auth_raw = os.getenv("NEO4J_AUTH", "neo4j/prahari_dev")
        user, password = auth_raw.split("/", 1)
        driver = GraphDatabase.driver("bolt://localhost:7687", auth=(user, password))
        with driver.session() as s:
            s.run("RETURN 1").single()
        driver.close()
        return True, "OK"
    except Exception as e:
        return False, str(e)


def check_redis() -> tuple[bool, str]:
    try:
        import redis

        r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        r.ping()
        return True, "OK"
    except Exception as e:
        return False, str(e)


def check_postgres() -> tuple[bool, str]:
    try:
        import psycopg

        conn = psycopg.connect(
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=int(os.getenv("POSTGRES_PORT", "5433")),
            user=os.getenv("POSTGRES_USER", "prahari"),
            password=os.getenv("POSTGRES_PASSWORD", "prahari_dev"),
            dbname=os.getenv("POSTGRES_DB", "prahari"),
        )
        conn.execute("SELECT 1")
        conn.close()
        return True, "OK"
    except Exception as e:
        return False, str(e)


checks = [("Neo4j", check_neo4j), ("Redis", check_redis), ("Postgres", check_postgres)]

print(f"\n{'Service':<12} {'Status':<8} Detail")
print("-" * 50)
any_fail = False
for name, fn in checks:
    ok, detail = fn()
    status = "OK" if ok else "FAIL"
    if not ok:
        any_fail = True
    print(f"{name:<12} {status:<8} {detail}")
print()

sys.exit(1 if any_fail else 0)
