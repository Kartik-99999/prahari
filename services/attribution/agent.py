#!/usr/bin/env python3
"""Prahari live Claude ATT&CK attribution agent.

A tool-using agent that investigates the top incident, maps its events to MITRE
ATT&CK, characterises the campaign, and predicts next moves. Runs in two modes:

  LIVE      ANTHROPIC_API_KEY present -> drives Claude (messages API + tool use).
  FALLBACK  key missing/empty -> NO API call; reuses the deterministic mapper's
            technique output and emits a templated narrative/next-moves so the
            task still completes and a report is still produced.

INTEGRITY: the incident data handed to the model NEVER contains ground truth
(no gt_* anywhere) and excludes the synthetic `severity` proxy and the
deterministic `inferred_technique` (so the agent reasons independently).
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

from services.attribution.attack_kb import get_kb  # noqa: E402
from services.attribution.rag import retrieve  # noqa: E402
from services.graph.schema import get_driver  # noqa: E402

load_dotenv(_REPO_ROOT / ".env")

EVENTS = _REPO_ROOT / "data" / "events.jsonl"
SCORES = _REPO_ROOT / "data" / "ueba_scores.csv"
INCIDENTS = _REPO_ROOT / "data" / "incidents.json"
REPORT = _REPO_ROOT / "data" / "attribution_report.json"

DEFAULT_MODEL = os.getenv("PRAHARI_AGENT_MODEL", "claude-sonnet-4-6")
MAX_TOOL_TURNS = 10
SAFE_REL_PROPS = ("activity", "ts", "dst_port", "anomaly_score", "fused_score", "via")

# ----------------------------------------------------------------------------
# gt-free data access (shared by tools + fallback)
# ----------------------------------------------------------------------------


def _load_events() -> dict[str, dict]:
    out = {}
    with EVENTS.open() as f:
        for line in f:
            line = line.strip()
            if line:
                e = json.loads(line)
                out[e["event_id"]] = e
    return out


def _reasons_and_scores() -> dict[str, dict]:
    import csv

    out: dict[str, dict] = {}
    with SCORES.open() as f:
        for row in csv.DictReader(f):
            try:
                reasons = json.loads(row.get("reasons") or "[]")
            except Exception:  # noqa: BLE001
                reasons = []
            out[row["event_id"]] = {
                "ueba_reasons": reasons,
                "anomaly_score": round(float(row.get("anomaly_score", 0) or 0), 3),
                "fused_score": round(float(row.get("fused_score", 0) or 0), 3),
            }
    return out


def _top_incident() -> dict:
    return json.loads(INCIDENTS.read_text())[0]


def _is_internal(ip: str | None, host_ips: set[str]) -> bool:
    return bool(ip) and ip in host_ips


def gt_free_events(incident_id: str | None = None) -> list[dict]:
    """Behavioural facts for the incident's events — NO gt_, NO severity, NO
    deterministic inferred_technique."""
    from services.graph.schema import load_host_map

    hm = load_host_map()
    events = _load_events()
    extra = _reasons_and_scores()
    inc = _top_incident()
    rows = []
    for eid in inc["member_event_ids"]:
        e = events[eid]
        proc = e.get("process") or {}
        fil = e.get("file") or {}
        src_ip = (e.get("src") or {}).get("ip")
        dst_ip = (e.get("dst") or {}).get("ip")
        rows.append(
            {
                "event_id": eid,
                "timestamp": e["timestamp"],
                "activity": e["activity"],
                "user": (e.get("actor") or {}).get("user"),
                "host": (e.get("actor") or {}).get("host"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": (e.get("dst") or {}).get("port"),
                "process_name": proc.get("name"),
                "cmdline": proc.get("cmdline"),
                "file_path": fil.get("path"),
                "external_dst": bool(dst_ip) and not hm.is_internal(dst_ip),
                "external_auth_src": e["activity"] == "auth"
                and bool(src_ip)
                and not hm.is_internal(src_ip),
                **extra.get(eid, {}),
            }
        )
    rows.sort(key=lambda r: r["timestamp"])
    return rows


def incident_summary() -> dict:
    inc = _top_incident()
    return {
        "incident_id": inc["id"],
        "score": inc["incident_score"],
        "n_events": inc["n_events"],
        "first_seen": inc["first_seen"],
        "last_seen": inc["last_seen"],
        "span_days": inc["span_days"],
        "hosts": inc["hosts"],
        "users": inc["users"],
        "external_ips": inc["external_ips"],
        "activities": inc["activities"],
        "has_lateral_path": inc["has_lateral_path"],
    }


# ----------------------------------------------------------------------------
# Tools
# ----------------------------------------------------------------------------


def tool_search_attack_kb(query: str) -> list[dict]:
    return retrieve(query, k=5)


def tool_get_incident_events(incident_id: str) -> list[dict]:
    return gt_free_events(incident_id)


def tool_get_graph_context(entity_name: str) -> dict:
    driver = get_driver()
    q = """
    MATCH (n) WHERE n.name = $e OR n.addr = $e
    OPTIONAL MATCH (n)-[r]-(m)
    RETURN labels(n)[0] AS nlabel, coalesce(n.name, n.addr) AS nname,
           type(r) AS rel, labels(m)[0] AS mlabel,
           coalesce(m.name, m.addr) AS mname, properties(r) AS props
    LIMIT 60
    """
    try:
        with driver.session() as s:
            recs = list(s.run(q, e=entity_name))
    finally:
        driver.close()
    edges = []
    for r in recs:
        if not r["rel"]:
            continue
        # strip ground truth and any prior attribution from edge props
        props = {k: v for k, v in (r["props"] or {}).items() if k in SAFE_REL_PROPS}
        edges.append(
            {"rel": r["rel"], "to_label": r["mlabel"], "to": r["mname"], "props": props}
        )
    return {
        "entity": entity_name,
        "label": recs[0]["nlabel"] if recs else None,
        "neighbours": edges[:40],
    }


def tool_lookup_technique(technique_id: str) -> dict:
    t = get_kb().technique_by_id(technique_id)
    if not t:
        return {"technique_id": technique_id, "found": False}
    return {
        "technique_id": t.id,
        "name": t.name,
        "tactics": t.tactics,
        "description": t.description[:600],
        "detection": t.detection[:400],
        "mitigations": t.mitigations,
    }


TOOL_DISPATCH = {
    "search_attack_kb": lambda a: tool_search_attack_kb(a["query"]),
    "get_incident_events": lambda a: tool_get_incident_events(a.get("incident_id", "")),
    "get_graph_context": lambda a: tool_get_graph_context(a["entity_name"]),
    "lookup_technique": lambda a: tool_lookup_technique(a["technique_id"]),
}

TOOLS = [
    {
        "name": "search_attack_kb",
        "description": "Semantic search over MITRE ATT&CK technique docs and the "
        "threat-intel advisory corpus. Returns top matching "
        "techniques/advisories with ids.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "get_incident_events",
        "description": "Return the incident's member events with behavioural facts "
        "(activity, process, ports, external flags, UEBA reasons, "
        "anomaly/fused scores). No ground truth is included.",
        "input_schema": {
            "type": "object",
            "properties": {"incident_id": {"type": "string"}},
            "required": ["incident_id"],
        },
    },
    {
        "name": "get_graph_context",
        "description": "Return the Neo4j neighbourhood (relationships) of a host, "
        "user, or IP to understand connectivity and lateral movement.",
        "input_schema": {
            "type": "object",
            "properties": {"entity_name": {"type": "string"}},
            "required": ["entity_name"],
        },
    },
    {
        "name": "lookup_technique",
        "description": "Look up full MITRE ATT&CK details (name, tactics, "
        "description, detection, mitigations) for a technique id.",
        "input_schema": {
            "type": "object",
            "properties": {"technique_id": {"type": "string"}},
            "required": ["technique_id"],
        },
    },
    {
        "name": "submit_attribution",
        "description": "Submit the FINAL structured ATT&CK attribution and finish. "
        "Every technique MUST cite event_ids as evidence; if unsure, "
        "lower the confidence rather than invent.",
        "input_schema": {
            "type": "object",
            "properties": {
                "techniques": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "event_ids": {"type": "array", "items": {"type": "string"}},
                            "technique_id": {"type": "string"},
                            "technique_name": {"type": "string"},
                            "tactic": {"type": "string"},
                            "rationale": {"type": "string"},
                            "confidence": {"type": "number"},
                        },
                        "required": [
                            "event_ids",
                            "technique_id",
                            "rationale",
                            "confidence",
                        ],
                    },
                },
                "kill_chain": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "tactic": {"type": "string"},
                            "technique_id": {"type": "string"},
                            "narrative": {"type": "string"},
                        },
                    },
                },
                "campaign_assessment": {
                    "type": "object",
                    "properties": {
                        "summary": {"type": "string"},
                        "threat_profile": {"type": "string"},
                        "advisory_citations": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                },
                "next_moves": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "predicted_technique": {"type": "string"},
                            "tactic": {"type": "string"},
                            "rationale": {"type": "string"},
                            "recommended_defensive_action": {"type": "string"},
                        },
                    },
                },
                "overall_confidence": {"type": "number"},
            },
            "required": [
                "techniques",
                "kill_chain",
                "campaign_assessment",
                "next_moves",
                "overall_confidence",
            ],
        },
    },
]

SYSTEM_PROMPT = """You are Prahari's SOC attribution analyst. Investigate ONE \
security incident and produce a MITRE ATT&CK attribution.

Use the tools to gather evidence: call get_incident_events(incident_id) first to \
see the behavioural facts, search_attack_kb to ground technique choices in ATT&CK \
and threat-intel advisories, get_graph_context to understand host/user/IP \
connectivity and lateral movement, and lookup_technique for technique details.

Rules:
- Map each event to the single most likely ATT&CK technique at PARENT-technique \
granularity (e.g. T1566, not T1566.001). You MAY mention a specific \
sub-technique in the rationale as added insight.
- Every technique you assign MUST cite the supporting event_ids. If the evidence \
is weak, LOWER the confidence rather than invent a technique (cite-or-abstain).
- Characterise the campaign (low-and-slow vs smash-and-grab, target, threat \
profile) and CITE advisory ids returned by search_attack_kb.
- Predict the adversary's likely NEXT moves with recommended defensive actions.
- You have at most 10 tool turns. When done, call submit_attribution exactly once \
with the full structured result. Do not output a final text answer instead of \
calling submit_attribution."""


# ----------------------------------------------------------------------------
# LIVE mode
# ----------------------------------------------------------------------------


def run_live(model: str) -> tuple[dict, list, dict]:
    import anthropic

    client = anthropic.Anthropic()
    summary = incident_summary()
    user_msg = (
        "Investigate and attribute this incident. Start by calling "
        f"get_incident_events('{summary['incident_id']}').\n\n"
        f"Incident summary (no ground truth):\n{json.dumps(summary, indent=2)}"
    )
    messages = [{"role": "user", "content": user_msg}]
    trace: list[dict] = []
    usage = {"input_tokens": 0, "output_tokens": 0, "api_calls": 0}
    final: dict | None = None

    for _turn in range(MAX_TOOL_TURNS):
        resp = client.messages.create(
            model=model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )
        usage["api_calls"] += 1
        usage["input_tokens"] += resp.usage.input_tokens
        usage["output_tokens"] += resp.usage.output_tokens
        messages.append({"role": "assistant", "content": resp.content})

        if resp.stop_reason != "tool_use":
            break

        tool_results = []
        for block in resp.content:
            if getattr(block, "type", None) != "tool_use":
                continue
            args = block.input if isinstance(block.input, dict) else {}
            trace.append({"tool": block.name, "args": _short_args(args)})
            if block.name == "submit_attribution":
                final = args
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": "Attribution recorded. Done.",
                    }
                )
            else:
                try:
                    result = TOOL_DISPATCH[block.name](args)
                except Exception as e:  # noqa: BLE001
                    result = {"error": str(e)}
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result)[:12000],
                    }
                )
        messages.append({"role": "user", "content": tool_results})
        if final is not None:
            break

    if final is None:
        raise RuntimeError("agent did not call submit_attribution within tool-turn cap")
    return final, trace, usage


def _short_args(args: dict) -> dict:
    out = {}
    for k, v in args.items():
        s = v if isinstance(v, str) else json.dumps(v)
        out[k] = s if len(str(s)) <= 80 else str(s)[:77] + "..."
    return out


# ----------------------------------------------------------------------------
# FALLBACK mode (no API key) — reuse deterministic mapper + templated narrative
# ----------------------------------------------------------------------------

TACTIC_ORDER = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def run_fallback() -> tuple[dict, list, dict]:
    kb = get_kb()
    inc = _top_incident()
    inferences = inc.get("event_inferences", {})
    events = _load_events()

    # group deterministic inferred techniques -> techniques[]
    by_tech: dict[str, dict] = {}
    for eid, inf in inferences.items():
        tid = inf.get("inferred_technique")
        if not tid:
            continue
        g = by_tech.setdefault(tid, {"event_ids": [], "confs": [], "rationale": ""})
        g["event_ids"].append(eid)
        g["confs"].append(inf.get("inferred_confidence", 0.0))
        if not g["rationale"]:
            g["rationale"] = inf.get("inferred_rationale", "").split(";")[0]

    techniques = []
    for tid, g in by_tech.items():
        t = kb.technique_by_id(tid)
        techniques.append(
            {
                "event_ids": sorted(g["event_ids"]),
                "technique_id": tid,
                "technique_name": t.name if t else tid,
                "tactic": (t.tactics[0] if t and t.tactics else "unknown"),
                "rationale": "[deterministic mapper — agent disabled, no API key] "
                + g["rationale"],
                "confidence": round(sum(g["confs"]) / len(g["confs"]), 2),
            }
        )

    # kill_chain ordered by earliest event timestamp per technique (behavioural)
    def first_ts(tid: str) -> str:
        return min(events[e]["timestamp"] for e in by_tech[tid]["event_ids"])

    kill_chain = []
    for tid in sorted(by_tech, key=first_ts):
        t = kb.technique_by_id(tid)
        narrative = t.description.split(". ")[0] + "." if t else tid
        kill_chain.append(
            {
                "tactic": (t.tactics[0] if t and t.tactics else "unknown"),
                "technique_id": tid,
                "narrative": f"[{first_ts(tid)[:10]}] {narrative}",
            }
        )

    citations = [
        h["source"]
        for h in retrieve(
            "low and slow apt phishing credential dumping lateral movement archive "
            "exfiltration over c2 targeting exam records database",
            k=4,
        )
        if h.get("source")
    ]

    campaign = {
        "summary": "Low-and-slow targeted intrusion against the State Examinations "
        "Authority: initial phishing foothold on a clerk workstation, "
        "credential theft, multi-day lateral movement to the domain "
        "controller and the exam-records database server, data staging, "
        "and exfiltration over the C2 channel.",
        "threat_profile": "Patient, objective-driven actor (APT-like) prioritising "
        "stealth over speed; campaign spans ~3 weeks with dead-of-"
        "night activity; crown-jewel target is the exam-records DB.",
        "advisory_citations": sorted(set(citations)),
    }

    next_moves = [
        {
            "predicted_technique": "T1070",
            "tactic": "defense-evasion",
            "rationale": "After exfil, the actor typically clears logs/artifacts on "
            "DB-EXAMS and the lateral path to hinder response.",
            "recommended_defensive_action": "Forward and immutably store logs off-host; "
            "alert on event-log clearing; preserve forensic images now.",
        },
        {
            "predicted_technique": "T1486",
            "tactic": "impact",
            "rationale": "Crown-jewel data access can be followed by encryption for "
            "impact (ransomware/extortion) against exam-records.",
            "recommended_defensive_action": "Verify offline backups of exam-records; "
            "restrict write/encrypt tooling on DB-EXAMS.",
        },
        {
            "predicted_technique": "T1078",
            "tactic": "persistence",
            "rationale": "Stolen admin credentials enable durable re-entry via valid "
            "accounts even after the initial foothold is closed.",
            "recommended_defensive_action": "Force credential reset for admin.it and "
            "exam.clerk; enforce MFA; hunt for rogue accounts.",
        },
        {
            "predicted_technique": "T1041",
            "tactic": "exfiltration",
            "rationale": "The established C2 channel may be reused for further staged "
            "exfiltration of additional records.",
            "recommended_defensive_action": "Block the external C2 IP at the egress "
            "perimeter; throttle/inspect outbound from DB-EXAMS.",
        },
    ]

    attribution = {
        "techniques": techniques,
        "kill_chain": kill_chain,
        "campaign_assessment": campaign,
        "next_moves": next_moves,
        "overall_confidence": 0.6,
    }
    trace = [{"tool": "(none)", "args": {"note": "fallback mode — no API calls"}}]
    usage = {"input_tokens": 0, "output_tokens": 0, "api_calls": 0}
    return attribution, trace, usage


# ----------------------------------------------------------------------------
# Persistence
# ----------------------------------------------------------------------------


def persist(attribution: dict, mode: str, model: str, trace: list, usage: dict) -> int:
    # per-event agent_technique (separate from inferred_technique + gt_technique)
    rows = []
    for t in attribution["techniques"]:
        for eid in t["event_ids"]:
            rows.append(
                {
                    "event_id": eid,
                    "tech": t["technique_id"],
                    "conf": float(t.get("confidence", 0.0)),
                }
            )
    driver = get_driver()
    updated = 0
    try:
        with driver.session() as s:
            s.run(
                "MATCH ()-[r]->() WHERE r.agent_technique IS NOT NULL "
                "REMOVE r.agent_technique, r.agent_confidence"
            )
            if rows:
                rec = s.run(
                    """
                    UNWIND $rows AS row
                    MATCH ()-[r {event_id: row.event_id}]->()
                    SET r.agent_technique = row.tech, r.agent_confidence = row.conf
                    RETURN count(r) AS n
                    """,
                    rows=rows,
                ).single()
                updated = rec["n"] if rec else 0
            inc = _top_incident()
            s.run(
                """
                MATCH (i:Incident {id: $id})
                SET i.agent_mode = $mode, i.agent_model = $model,
                    i.agent_overall_confidence = $conf,
                    i.kill_chain = $kc, i.campaign_summary = $summary,
                    i.threat_profile = $profile, i.next_moves = $nm,
                    i.agent_techniques = $techs
                """,
                id=inc["id"],
                mode=mode,
                model=model,
                conf=attribution["overall_confidence"],
                kc=json.dumps(attribution["kill_chain"]),
                summary=attribution["campaign_assessment"]["summary"],
                profile=attribution["campaign_assessment"]["threat_profile"],
                nm=json.dumps(attribution["next_moves"]),
                techs=sorted({t["technique_id"] for t in attribution["techniques"]}),
            )
    finally:
        driver.close()

    REPORT.write_text(
        json.dumps(
            {
                "mode": mode,
                "model": model if mode == "live" else None,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "incident_id": _top_incident()["id"],
                "tool_call_trace": trace,
                "usage": usage,
                "attribution": attribution,
            },
            indent=2,
        )
    )
    return updated


# ----------------------------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the Claude ATT&CK attribution agent.")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--force-fallback", action="store_true")
    args = ap.parse_args()

    key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if key and not args.force_fallback:
        mode = "live"
        print(f"[agent] MODE=LIVE  model={args.model}")
        try:
            attribution, trace, usage = run_live(args.model)
        except Exception as e:  # noqa: BLE001
            print(
                f"[agent] LIVE run failed ({e}); falling back to deterministic.",
                file=sys.stderr,
            )
            mode = "fallback"
            attribution, trace, usage = run_fallback()
    else:
        mode = "fallback"
        print(
            "[agent] MODE=FALLBACK — agent disabled (no ANTHROPIC_API_KEY). "
            "Reusing deterministic mapper output + templated narrative/next-moves."
        )
        attribution, trace, usage = run_fallback()

    updated = persist(attribution, mode, args.model, trace, usage)

    print(
        f"\n[agent] mode={mode}  techniques={len(attribution['techniques'])}  "
        f"next_moves={len(attribution['next_moves'])}  "
        f"agent_technique on {updated} edges"
    )
    print(f"[agent] tool-call trace ({len(trace)}):")
    for i, c in enumerate(trace, 1):
        print(f"   {i}. {c['tool']}  {c['args']}")
    if mode == "live":
        print(
            f"[agent] API calls={usage['api_calls']}  "
            f"input_tokens={usage['input_tokens']}  "
            f"output_tokens={usage['output_tokens']}"
        )
    print(f"[agent] wrote {REPORT}")


if __name__ == "__main__":
    main()
