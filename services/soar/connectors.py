#!/usr/bin/env python3
"""Prahari SOAR containment connectors (MOCKED).

Six realistic-but-simulated containment actions. Each is a no-op that LOGS its
intent and returns a structured result {status, action, target, detail, ts};
nothing is actually changed. Each action also has a blast-radius classifier
(LOW / MEDIUM / HIGH) derived from target criticality read from scenario.yaml,
so the orchestrator's human-in-the-loop gate is meaningful.

Criticality (from scenario.yaml):
  * critical hosts        : domain_controller (DC01), db_server (DB-EXAMS)
  * high-privilege users  : domain_admin (admin.it)
  * everything else       : low

Representative classifications (what makes the gate meaningful):
  block_ip(C2)            -> LOW      (reversible egress block)
  snapshot_vm(*)          -> LOW      (read-only evidence preservation)
  kill_process(WS03)      -> LOW      (workstation)
  reset_credential(clerk) -> LOW      (low-privilege account)
  isolate_host(WS03)      -> MEDIUM   (workstation isolation)
  isolate_host(DB-EXAMS)  -> HIGH     (critical exam-records server)
  disable_user(admin.it)  -> HIGH     (high-privilege account)
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
SCENARIO = _REPO_ROOT / "packages" / "scenario" / "scenario.yaml"

CRITICAL_HOST_ROLES = {"domain_controller", "db_server"}
HIGH_PRIV_USER_ROLES = {"domain_admin"}
LOW, MEDIUM, HIGH = "LOW", "MEDIUM", "HIGH"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AssetContext:
    """Asset criticality loaded from the scenario."""

    def __init__(self, path: Path = SCENARIO) -> None:
        scn = yaml.safe_load(path.read_text())
        self.host_role = {h["name"]: h["role"] for h in scn["hosts"]}
        self.user_role = {u["name"]: u["role"] for u in scn["users"]}
        self.internal_ips = {h["ip"] for h in scn["hosts"]}

    def host_is_critical(self, host: str) -> bool:
        return self.host_role.get(host) in CRITICAL_HOST_ROLES

    def user_is_high_priv(self, user: str) -> bool:
        return self.user_role.get(user) in HIGH_PRIV_USER_ROLES

    def describe(self, target: str) -> str:
        if target in self.host_role:
            crit = "critical" if self.host_is_critical(target) else "standard"
            return f"host {target} ({self.host_role[target]}, {crit})"
        if target in self.user_role:
            priv = "high-privilege" if self.user_is_high_priv(target) else "standard"
            return f"user {target} ({self.user_role[target]}, {priv})"
        if target in self.internal_ips:
            return f"internal IP {target}"
        return f"external IP {target}"


_ASSETS: AssetContext | None = None


def assets() -> AssetContext:
    global _ASSETS
    if _ASSETS is None:
        _ASSETS = AssetContext()
    return _ASSETS


def classify_blast_radius(action: str, target: str) -> str:
    a = assets()
    if action == "block_ip":
        return LOW  # egress block, reversible
    if action == "snapshot_vm":
        return LOW  # read-only evidence preservation
    if action == "kill_process":
        return MEDIUM if a.host_is_critical(target) else LOW
    if action == "isolate_host":
        return HIGH if a.host_is_critical(target) else MEDIUM
    if action == "disable_user":
        return HIGH if a.user_is_high_priv(target) else MEDIUM
    if action == "reset_credential":
        return MEDIUM if a.user_is_high_priv(target) else LOW
    return MEDIUM  # unknown action -> conservative


# --- the six mocked actions (simulated no-ops) ------------------------------


def _result(action: str, target: str, detail: str) -> dict:
    rec = {
        "status": "simulated",
        "action": action,
        "target": target,
        "detail": detail,
        "ts": _now(),
        "blast_radius": classify_blast_radius(action, target),
    }
    print(f"[connector] (SIMULATED) {action} -> {target} :: {detail}")
    return rec


def isolate_host(target: str, **_) -> dict:
    return _result(
        "isolate_host",
        target,
        f"network-isolate {assets().describe(target)} (quarantine VLAN)",
    )


def disable_user(target: str, **_) -> dict:
    return _result(
        "disable_user",
        target,
        f"disable account {assets().describe(target)} in directory",
    )


def block_ip(target: str, **_) -> dict:
    return _result(
        "block_ip", target, f"add egress deny rule for {assets().describe(target)}"
    )


def snapshot_vm(target: str, **_) -> dict:
    return _result(
        "snapshot_vm",
        target,
        f"capture forensic disk+memory snapshot of {assets().describe(target)}",
    )


def kill_process(
    target: str, *, pid: int | None = None, name: str | None = None, **_
) -> dict:
    what = name or (f"pid {pid}" if pid else "process")
    return _result(
        "kill_process", target, f"terminate {what} on {assets().describe(target)}"
    )


def reset_credential(target: str, **_) -> dict:
    return _result(
        "reset_credential",
        target,
        f"force credential reset for {assets().describe(target)}",
    )


REGISTRY = {
    "isolate_host": isolate_host,
    "disable_user": disable_user,
    "block_ip": block_ip,
    "snapshot_vm": snapshot_vm,
    "kill_process": kill_process,
    "reset_credential": reset_credential,
}

_ACTION_META = {
    "isolate_host": ("host", "Network-isolate a host into a quarantine VLAN."),
    "disable_user": ("user", "Disable a user account in the directory."),
    "block_ip": ("ip", "Add an egress deny rule for an IP (sever C2/exfil)."),
    "snapshot_vm": ("host", "Capture a forensic disk+memory snapshot (evidence)."),
    "kill_process": ("host", "Terminate a malicious process on a host."),
    "reset_credential": ("user", "Force a credential reset for a user."),
}


def list_available_actions() -> list[dict]:
    """Metadata for every connector (for the planner's tool surface)."""
    out = []
    for name, (target_kind, desc) in _ACTION_META.items():
        out.append(
            {
                "action": name,
                "target_kind": target_kind,
                "description": desc,
                "blast_radius_rule": _blast_rule_doc(name),
            }
        )
    return out


def _blast_rule_doc(action: str) -> str:
    return {
        "isolate_host": "HIGH on critical hosts (DC01/DB-EXAMS), else MEDIUM",
        "disable_user": "HIGH on high-privilege users (domain_admin), else MEDIUM",
        "block_ip": "LOW (reversible egress block)",
        "snapshot_vm": "LOW (read-only evidence preservation)",
        "kill_process": "MEDIUM on critical hosts, else LOW",
        "reset_credential": "MEDIUM on high-privilege users, else LOW",
    }[action]


def execute(action: str, target: str, **kw) -> dict:
    if action not in REGISTRY:
        return {
            "status": "error",
            "action": action,
            "target": target,
            "detail": f"unknown action '{action}'",
            "ts": _now(),
            "blast_radius": MEDIUM,
        }
    return REGISTRY[action](target, **kw)


def main() -> None:
    print("Available SOAR connectors:\n")
    for m in list_available_actions():
        print(
            f"  {m['action']:<16} target={m['target_kind']:<5} "
            f"blast: {m['blast_radius_rule']}"
        )
    print("\nExample classifications:")
    for action, target in [
        ("block_ip", "203.0.113.66"),
        ("snapshot_vm", "DB-EXAMS"),
        ("kill_process", "WS03"),
        ("isolate_host", "WS03"),
        ("isolate_host", "DB-EXAMS"),
        ("disable_user", "admin.it"),
        ("reset_credential", "exam.clerk"),
    ]:
        print(f"  {action}({target}) -> {classify_blast_radius(action, target)}")


if __name__ == "__main__":
    main()
