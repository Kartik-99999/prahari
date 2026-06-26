#!/usr/bin/env python3
"""Neo4j schema + scenario host<->IP map for the Prahari provenance graph.

Defines uniqueness constraints / indexes for the entity nodes and loads the
host<->IP mapping from ``packages/scenario/scenario.yaml`` so that src/dst IPs
on events can be resolved to internal Hosts (IPs absent from the map are
treated as external: IP.internal=false).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from neo4j import Driver, GraphDatabase

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(_REPO_ROOT / ".env")

SCENARIO_PATH = _REPO_ROOT / "packages" / "scenario" / "scenario.yaml"

# Uniqueness constraints (each also creates a backing index).
CONSTRAINTS = [
    "CREATE CONSTRAINT host_name IF NOT EXISTS FOR (h:Host) REQUIRE h.name IS UNIQUE",
    "CREATE CONSTRAINT user_name IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE",
    "CREATE CONSTRAINT ip_addr   IF NOT EXISTS FOR (i:IP)   REQUIRE i.addr IS UNIQUE",
    "CREATE CONSTRAINT file_key  IF NOT EXISTS FOR (f:File) REQUIRE f.key IS UNIQUE",
    "CREATE CONSTRAINT proc_key  IF NOT EXISTS FOR (p:Process) REQUIRE p.key IS UNIQUE",
]

# Secondary indexes that help the verification queries.
INDEXES = [
    "CREATE INDEX ip_internal IF NOT EXISTS FOR (i:IP) ON (i.internal)",
]


def get_driver() -> Driver:
    """Build a Neo4j driver from NEO4J_AUTH (user/password)."""
    auth_raw = os.getenv("NEO4J_AUTH", "neo4j/prahari_dev")
    user, password = auth_raw.split("/", 1)
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    return GraphDatabase.driver(uri, auth=(user, password))


def create_schema(driver: Driver) -> None:
    with driver.session() as s:
        for stmt in CONSTRAINTS + INDEXES:
            s.run(stmt)


@dataclass
class HostMap:
    """Resolved host<->IP mapping from the scenario."""

    host_by_ip: dict[str, str] = field(default_factory=dict)
    ip_by_host: dict[str, str] = field(default_factory=dict)
    internal_ips: set[str] = field(default_factory=set)

    def resolve_host(self, ip: str | None) -> str | None:
        """Return the internal Host name for an IP, or None if external/unknown."""
        if not ip:
            return None
        return self.host_by_ip.get(ip)

    def is_internal(self, ip: str | None) -> bool:
        return bool(ip) and ip in self.internal_ips


def load_host_map(scenario_path: Path = SCENARIO_PATH) -> HostMap:
    scn = yaml.safe_load(scenario_path.read_text())
    hm = HostMap()
    for h in scn["hosts"]:
        hm.host_by_ip[h["ip"]] = h["name"]
        hm.ip_by_host[h["name"]] = h["ip"]
        hm.internal_ips.add(h["ip"])  # IPs in the map are internal; all others external
    return hm


def main() -> None:
    """Apply schema and print the loaded host map (sanity CLI)."""
    hm = load_host_map()
    driver = get_driver()
    try:
        create_schema(driver)
    finally:
        driver.close()
    print("Applied constraints:")
    for c in CONSTRAINTS:
        print("  -", c.split("FOR")[0].strip())
    print("Indexes:")
    for i in INDEXES:
        print("  -", i.split("FOR")[0].strip())
    print(
        f"\nHost<->IP map ({len(hm.ip_by_host)} hosts, "
        f"{len(hm.internal_ips)} internal IPs):"
    )
    for host, ip in hm.ip_by_host.items():
        print(f"  {host:<10} {ip}")


if __name__ == "__main__":
    main()
