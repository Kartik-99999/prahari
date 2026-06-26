#!/usr/bin/env python3
"""Prahari SOAR response-planner.

Given the top incident + its ATT&CK attribution (techniques, kill_chain,
next_moves) + asset context, produces an ORDERED containment playbook:
  [{action, target, rationale, blast_radius, gate}]

Runs as an agent (anthropic SDK tool use) when ANTHROPIC_API_KEY is set, with a
graceful deterministic fallback otherwise. The model only proposes
{action, target, rationale}; blast_radius and the gate are computed
AUTHORITATIVELY by the connector classifier + gate policy so the model cannot
weaken a gate. Ground truth (gt_*) never reaches the model.

Gate policy (documented): gate = auto if blast_radius in {LOW, MEDIUM}; HIGH
requires a human approver.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dotenv import load_dotenv  # noqa: E402

from services.soar import connectors  # noqa: E402

load_dotenv(_REPO_ROOT / ".env")

INCIDENTS = _REPO_ROOT / "data" / "incidents.json"
ATTRIBUTION = _REPO_ROOT / "data" / "attribution_report.json"
PLAYBOOK = _REPO_ROOT / "data" / "response_playbook.json"

DEFAULT_MODEL = os.getenv("PRAHARI_AGENT_MODEL", "claude-sonnet-4-6")
MAX_TOOL_TURNS = 8


def gate_for(blast_radius: str) -> str:
    """auto if LOW/MEDIUM, human if HIGH."""
    return "human" if blast_radius == connectors.HIGH else "auto"


# ---------------------------------------------------------------------------
# gt-free context (shared by tools + fallback)
# ---------------------------------------------------------------------------


def _incident() -> dict:
    inc = json.loads(INCIDENTS.read_text())[0]
    return {
        "incident_id": inc["id"],
        "score": inc["incident_score"],
        "hosts": inc["hosts"],
        "users": inc["users"],
        "external_ips": inc["external_ips"],
        "activities": inc["activities"],
        "first_seen": inc["first_seen"],
        "last_seen": inc["last_seen"],
        "has_lateral_path": inc["has_lateral_path"],
    }


def _attribution() -> dict:
    if not ATTRIBUTION.exists():
        return {"techniques": [], "kill_chain": [], "next_moves": []}
    a = json.loads(ATTRIBUTION.read_text()).get("attribution", {})
    return {
        "techniques": [
            {
                "technique_id": t["technique_id"],
                "technique_name": t.get("technique_name"),
                "tactic": t.get("tactic"),
            }
            for t in a.get("techniques", [])
        ],
        "kill_chain": a.get("kill_chain", []),
        "next_moves": a.get("next_moves", []),
    }


def _asset_context() -> dict:
    a = connectors.assets()
    inc = _incident()
    out = {"hosts": {}, "users": {}, "external_ips": inc["external_ips"]}
    for h in inc["hosts"]:
        out["hosts"][h] = {
            "role": a.host_role.get(h),
            "critical": a.host_is_critical(h),
        }
    for u in inc["users"]:
        out["users"][u] = {
            "role": a.user_role.get(u),
            "high_privilege": a.user_is_high_priv(u),
        }
    return out


def annotate(playbook: list[dict]) -> list[dict]:
    """Attach authoritative blast_radius + gate to each step."""
    out = []
    for step in playbook:
        br = connectors.classify_blast_radius(step["action"], step["target"])
        out.append(
            {
                "action": step["action"],
                "target": step["target"],
                "rationale": step.get("rationale", ""),
                "blast_radius": br,
                "gate": gate_for(br),
            }
        )
    return out


# ---------------------------------------------------------------------------
# Deterministic fallback planner
# ---------------------------------------------------------------------------


def _pick(hosts: list[str], critical: bool) -> list[str]:
    a = connectors.assets()
    return [h for h in hosts if a.host_is_critical(h) == critical]


def fallback_playbook() -> list[dict]:
    inc = _incident()
    a = connectors.assets()
    crit_hosts = _pick(inc["hosts"], True)  # DC01, DB-EXAMS
    work_hosts = _pick(inc["hosts"], False)  # WS03
    c2 = inc["external_ips"][0] if inc["external_ips"] else "203.0.113.66"
    db = (
        "DB-EXAMS"
        if "DB-EXAMS" in crit_hosts
        else (crit_hosts[0] if crit_hosts else "DB-EXAMS")
    )
    foothold = (
        "WS03" if "WS03" in work_hosts else (work_hosts[0] if work_hosts else "WS03")
    )
    low_users = [
        u
        for u in inc["users"]
        if not a.user_is_high_priv(u) and a.user_role.get(u) not in ("service_account",)
    ]
    hp_users = [u for u in inc["users"] if a.user_is_high_priv(u)]
    clerk = (
        "exam.clerk"
        if "exam.clerk" in low_users
        else (low_users[0] if low_users else "exam.clerk")
    )
    admin = (
        "admin.it"
        if "admin.it" in hp_users
        else (hp_users[0] if hp_users else "admin.it")
    )

    pb = [
        {
            "action": "snapshot_vm",
            "target": db,
            "rationale": "Preserve forensic evidence on the crown-jewel exam-records "
            "server before containment — counters predicted next-move T1070 "
            "(indicator removal).",
        },
        {
            "action": "snapshot_vm",
            "target": foothold,
            "rationale": "Preserve evidence on the phishing foothold (T1566) host.",
        },
        {
            "action": "block_ip",
            "target": c2,
            "rationale": f"Sever the C2/exfil channel to {c2} (mitigates T1071 C2 and "
            "T1041 exfiltration; blocks predicted further exfil).",
        },
        {
            "action": "kill_process",
            "target": foothold,
            "rationale": "Terminate the PowerShell beacon spawned by the phishing macro "
            "(T1566 / T1059) on the foothold host.",
        },
        {
            "action": "reset_credential",
            "target": clerk,
            "rationale": f"Revoke the phished {clerk} credentials reused for off-hours "
            "logon (T1078 valid accounts).",
        },
        {
            "action": "isolate_host",
            "target": foothold,
            "rationale": "Contain the compromised foothold workstation (T1566 initial "
            "access).",
        },
        {
            "action": "isolate_host",
            "target": db,
            "rationale": "Contain the exam-records database server that staged and "
            "exfiltrated data (T1560 / T1041) — critical asset.",
        },
        {
            "action": "disable_user",
            "target": admin,
            "rationale": f"Disable the compromised high-privilege account {admin} used "
            "for lateral movement (T1021) and likely persistence (T1078).",
        },
    ]
    return pb


# ---------------------------------------------------------------------------
# Live agent (tool use)
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "get_incident",
        "description": "Top incident summary (hosts, users, "
        "external IPs, timeframe) — no ground truth.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_attribution",
        "description": "The incident's ATT&CK attribution: "
        "techniques, kill_chain, predicted next_moves.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_asset_context",
        "description": "Criticality of the involved hosts "
        "and users (critical hosts, high-privilege users).",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "list_available_actions",
        "description": "The containment connectors "
        "available and their blast-radius rules.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "submit_playbook",
        "description": "Submit the FINAL ordered containment "
        "playbook and finish. Order matters (evidence first, then sever C2, then "
        "contain). Each step needs a rationale tying it to a technique/next-move.",
        "input_schema": {
            "type": "object",
            "properties": {
                "playbook": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "action": {"type": "string"},
                            "target": {"type": "string"},
                            "rationale": {"type": "string"},
                        },
                        "required": ["action", "target", "rationale"],
                    },
                }
            },
            "required": ["playbook"],
        },
    },
]

SYSTEM = """You are Prahari's SOC response planner. Build an ORDERED containment \
playbook for ONE incident using ONLY the available connectors.

Investigate with the tools (get_incident, get_attribution, get_asset_context, \
list_available_actions), then design a playbook that:
- preserves forensic evidence (snapshots) BEFORE disruptive containment,
- severs the C2/exfil channel early,
- ties each action's rationale to a specific ATT&CK technique or predicted \
next-move it mitigates,
- uses only these actions: isolate_host, disable_user, block_ip, snapshot_vm, \
kill_process, reset_credential.
Do NOT set blast_radius or gates yourself — the platform computes those. When \
done, call submit_playbook exactly once with the ordered steps."""


def live_playbook(model: str) -> tuple[list[dict], list, dict]:
    import anthropic

    client = anthropic.Anthropic()
    dispatch = {
        "get_incident": lambda: _incident(),
        "get_attribution": lambda: _attribution(),
        "get_asset_context": lambda: _asset_context(),
        "list_available_actions": lambda: connectors.list_available_actions(),
    }
    messages = [
        {
            "role": "user",
            "content": "Plan the containment response for the top incident. Start by "
            "calling get_incident and get_attribution.",
        }
    ]
    trace, usage, final = (
        [],
        {"input_tokens": 0, "output_tokens": 0, "api_calls": 0},
        None,
    )
    for _ in range(MAX_TOOL_TURNS):
        resp = client.messages.create(
            model=model, max_tokens=4096, system=SYSTEM, tools=TOOLS, messages=messages
        )
        usage["api_calls"] += 1
        usage["input_tokens"] += resp.usage.input_tokens
        usage["output_tokens"] += resp.usage.output_tokens
        messages.append({"role": "assistant", "content": resp.content})
        if resp.stop_reason != "tool_use":
            break
        results = []
        for b in resp.content:
            if getattr(b, "type", None) != "tool_use":
                continue
            trace.append({"tool": b.name})
            if b.name == "submit_playbook":
                final = (b.input or {}).get("playbook", [])
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": b.id,
                        "content": "Playbook recorded.",
                    }
                )
            else:
                out = dispatch[b.name]() if b.name in dispatch else {"error": "unknown"}
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": b.id,
                        "content": json.dumps(out)[:12000],
                    }
                )
        messages.append({"role": "user", "content": results})
        if final is not None:
            break
    if final is None:
        raise RuntimeError("planner did not call submit_playbook")
    return final, trace, usage


# ---------------------------------------------------------------------------


def plan() -> dict:
    key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    model = DEFAULT_MODEL
    if key:
        try:
            raw, trace, usage = live_playbook(model)
            mode = "live"
        except Exception as e:  # noqa: BLE001
            print(
                f"[planner] LIVE failed ({e}); deterministic fallback.", file=sys.stderr
            )
            raw, trace, usage, mode = fallback_playbook(), [], {}, "fallback"
    else:
        print(
            "[planner] MODE=FALLBACK — planner agent disabled (no ANTHROPIC_API_KEY). "
            "Using deterministic playbook."
        )
        raw, trace, usage, mode = fallback_playbook(), [], {}, "fallback"

    steps = annotate(raw)
    result = {
        "mode": mode,
        "model": model if mode == "live" else None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident_id": _incident()["incident_id"],
        "gate_policy": "auto if blast_radius in {LOW, MEDIUM}; HIGH requires human approval",
        "tool_trace": trace,
        "usage": usage,
        "playbook": steps,
    }
    PLAYBOOK.write_text(json.dumps(result, indent=2))
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="Plan the SOAR containment response.")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.parse_args()
    r = plan()
    print(f"[planner] mode={r['mode']}  steps={len(r['playbook'])}  -> {PLAYBOOK}")
    print(f"[planner] gate policy: {r['gate_policy']}\n")
    print(f"  {'#':<3}{'action':<17}{'target':<16}{'blast':<8}{'gate':<7}rationale")
    print("  " + "-" * 92)
    for i, s in enumerate(r["playbook"], 1):
        print(
            f"  {i:<3}{s['action']:<17}{s['target']:<16}{s['blast_radius']:<8}"
            f"{s['gate']:<7}{s['rationale'][:48]}"
        )


if __name__ == "__main__":
    main()
