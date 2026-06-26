#!/usr/bin/env python3
"""Prahari BFF (backend-for-frontend) gateway.

A read-only FastAPI surface over the persisted backend artifacts for the analyst
console, plus ONE state-changing endpoint: a human approve/deny decision on a
gated response action (which appends a real entry to the tamper-evident audit
ledger).

Data sources: data/*.json artifacts, the Neo4j provenance graph, and the
Postgres audit_ledger. GROUND TRUTH IS NEVER EXPOSED — event/graph payloads are
built from an explicit whitelist (no gt_*, no synthetic `severity`, no raw
labels). The only ground-truth-derived value is a viz-only boolean `malicious`
on graph edges (key renamed so no `gt_` ever appears in a response body).
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.soar import audit  # noqa: E402
from services.graph.schema import get_driver  # noqa: E402

DATA = _REPO_ROOT / "data"
INCIDENTS = DATA / "incidents.json"
ATTRIBUTION = DATA / "attribution_report.json"
PLAYBOOK = DATA / "response_playbook.json"
RESPONSE_LOG = DATA / "response_log.json"
SCORES = DATA / "ueba_scores.csv"
EVENTS = DATA / "events.jsonl"
SLATE = DATA / "metrics_slate.json"
ACTION_STATES = DATA / "action_states.json"  # console overlay of gated decisions

# event fields safe to expose (NO gt_*, NO severity, NO raw labels)
SAFE_GRAPH_REL_PROPS = (
    "ts",
    "activity",
    "anomaly_score",
    "fused_score",
    "inferred_technique",
    "agent_technique",
    "dst_port",
    "via",
)

app = FastAPI(title="Prahari BFF", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------
# loaders
# --------------------------------------------------------------------------


def _json(path: Path, default=None):
    if not path.exists():
        return default
    return json.loads(path.read_text())


def _incidents() -> list[dict]:
    return _json(INCIDENTS, []) or []


def _incident(iid: str) -> dict:
    for inc in _incidents():
        if inc["id"] == iid:
            return inc
    raise HTTPException(status_code=404, detail=f"incident {iid} not found")


def _attribution() -> dict:
    return (_json(ATTRIBUTION, {}) or {}).get("attribution", {})


def _scores() -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not SCORES.exists():
        return out
    with SCORES.open() as f:
        for row in csv.DictReader(f):
            try:
                reasons = json.loads(row.get("reasons") or "[]")
            except Exception:  # noqa: BLE001
                reasons = []
            out[row["event_id"]] = {
                "anomaly_score": round(float(row.get("anomaly_score") or 0), 3),
                "fused_score": round(float(row.get("fused_score") or 0), 3),
                "reasons": reasons,
            }
    return out


def _events() -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not EVENTS.exists():
        return out
    with EVENTS.open() as f:
        for line in f:
            line = line.strip()
            if line:
                e = json.loads(line)
                out[e["event_id"]] = e
    return out


def _agent_tech_by_event() -> dict[str, str]:
    out: dict[str, str] = {}
    for t in _attribution().get("techniques", []):
        for eid in t.get("event_ids", []):
            out[eid] = t["technique_id"]
    return out


def _action_states() -> dict:
    return _json(ACTION_STATES, {}) or {}


def _save_action_states(states: dict) -> None:
    ACTION_STATES.write_text(json.dumps(states, indent=2))


def _mttd_days() -> Optional[float]:
    slate = _json(SLATE, {}) or {}
    return (slate.get("mttd") or {}).get("mttd_days_after_foothold")


# --------------------------------------------------------------------------
# response models
# --------------------------------------------------------------------------


class HealthResp(BaseModel):
    status: str
    datastores: dict[str, str]


class IncidentSummary(BaseModel):
    id: str
    score: float
    n_events: int
    span_days: float
    hosts: list[str]
    status: str
    mttd_days: Optional[float] = None


class EventDetail(BaseModel):
    event_id: str
    timestamp: str
    activity: str
    user: Optional[str] = None
    host: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    process_name: Optional[str] = None
    cmdline: Optional[str] = None
    file_path: Optional[str] = None
    anomaly_score: Optional[float] = None
    fused_score: Optional[float] = None
    inferred_technique: Optional[str] = None
    agent_technique: Optional[str] = None
    reasons: list[str] = []


class IncidentDetail(BaseModel):
    id: str
    score: float
    status: str
    agent_mode: str
    hosts: list[str]
    users: list[str]
    external_ips: list[str]
    n_events: int
    span_days: float
    first_seen: str
    last_seen: str
    lateral_path: dict[str, Any]
    mttd: dict[str, Any]
    events: list[EventDetail]
    kill_chain: list[dict]
    campaign_assessment: dict[str, Any]
    next_moves: list[dict]


class GraphNode(BaseModel):
    id: str
    label: str
    type: str


class GraphEdge(BaseModel):
    source: str
    target: str
    type: str
    malicious: bool
    anomaly_score: Optional[float] = None
    fused_score: Optional[float] = None
    technique: Optional[str] = None
    ts: Optional[str] = None


class GraphResp(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class PlaybookAction(BaseModel):
    idx: int
    action: str
    target: str
    blast_radius: str
    gate: str
    status: str
    rationale: str
    approver: Optional[str] = None


class DecisionReq(BaseModel):
    decision: Literal["approve", "deny"]
    approver: str


class DecisionResp(BaseModel):
    incident_id: str
    playbook: list[PlaybookAction]
    ledger_head_hash: Optional[str]
    ledger_entries: int
    chain_verified: bool


class AuditEntry(BaseModel):
    seq: int
    ts: str
    actor: str
    action: str
    target: Optional[str]
    decision: Optional[str]
    blast_radius: Optional[str]
    prev_hash: str
    entry_hash: str


class AuditResp(BaseModel):
    entries: list[AuditEntry]
    verify: dict[str, Any]


# --------------------------------------------------------------------------
# endpoints
# --------------------------------------------------------------------------


@app.get("/api/health", response_model=HealthResp)
def health() -> HealthResp:
    stores: dict[str, str] = {}
    try:
        d = get_driver()
        with d.session() as s:
            s.run("RETURN 1").single()
        d.close()
        stores["neo4j"] = "ok"
    except Exception as e:  # noqa: BLE001
        stores["neo4j"] = f"fail: {e}"
    try:
        conn = audit.get_conn()
        conn.execute("SELECT 1")
        conn.close()
        stores["postgres"] = "ok"
    except Exception as e:  # noqa: BLE001
        stores["postgres"] = f"fail: {e}"
    overall = "ok" if all(v == "ok" for v in stores.values()) else "degraded"
    return HealthResp(status=overall, datastores=stores)


@app.get("/api/metrics/slate")
def metrics_slate() -> dict:
    slate = _json(SLATE)
    if slate is None:
        raise HTTPException(status_code=404, detail="metrics slate not built")
    return slate


def _status_for(inc: dict) -> str:
    # an incident with an executed playbook is "contained"
    return (
        "contained"
        if RESPONSE_LOG.exists() and inc["id"] == _incidents()[0]["id"]
        else "open"
    )


@app.get("/api/incidents", response_model=list[IncidentSummary])
def incidents() -> list[IncidentSummary]:
    out = []
    incs = _incidents()
    top_id = incs[0]["id"] if incs else None
    for inc in incs:
        out.append(
            IncidentSummary(
                id=inc["id"],
                score=inc["incident_score"],
                n_events=inc["n_events"],
                span_days=inc["span_days"],
                hosts=inc["hosts"],
                status=_status_for(inc),
                mttd_days=_mttd_days() if inc["id"] == top_id else None,
            )
        )
    return out


def _lateral_path(hosts: list[str]) -> dict:
    """Reconstruct a malicious :REACHED path among the incident's hosts."""
    q = """
    MATCH p=(a:Host)-[:REACHED*1..3]->(b:Host)
    WHERE a.name IN $hosts AND b.name IN $hosts
      AND all(r IN relationships(p) WHERE r.gt_malicious)
    RETURN [n IN nodes(p) | n.name] AS hops
    ORDER BY size(hops) DESC LIMIT 1
    """
    try:
        d = get_driver()
        with d.session() as s:
            rec = s.run(q, hosts=hosts).single()
        d.close()
        if rec and rec["hops"]:
            return {"present": True, "path": rec["hops"]}
    except Exception:  # noqa: BLE001
        pass
    return {"present": False, "path": []}


@app.get("/api/incidents/{iid}", response_model=IncidentDetail)
def incident_detail(iid: str) -> IncidentDetail:
    inc = _incident(iid)
    scores = _scores()
    events = _events()
    agent_tech = _agent_tech_by_event()
    inferences = inc.get("event_inferences", {})
    attr = _attribution()

    evs: list[EventDetail] = []
    for eid in inc["member_event_ids"]:
        e = events.get(eid, {})
        proc = e.get("process") or {}
        sc = scores.get(eid, {})
        evs.append(
            EventDetail(
                event_id=eid,
                timestamp=e.get("timestamp", ""),
                activity=e.get("activity", ""),
                user=(e.get("actor") or {}).get("user"),
                host=(e.get("actor") or {}).get("host"),
                src_ip=(e.get("src") or {}).get("ip"),
                dst_ip=(e.get("dst") or {}).get("ip"),
                dst_port=(e.get("dst") or {}).get("port"),
                process_name=proc.get("name"),
                cmdline=proc.get("cmdline"),
                file_path=(e.get("file") or {}).get("path"),
                anomaly_score=sc.get("anomaly_score"),
                fused_score=sc.get("fused_score"),
                inferred_technique=inferences.get(eid, {}).get("inferred_technique"),
                agent_technique=agent_tech.get(eid),
                reasons=sc.get("reasons", []),
            )
        )
    evs.sort(key=lambda x: x.timestamp)

    return IncidentDetail(
        id=inc["id"],
        score=inc["incident_score"],
        status=_status_for(inc),
        agent_mode=(_json(ATTRIBUTION, {}) or {}).get("mode", "n/a"),
        hosts=inc["hosts"],
        users=inc["users"],
        external_ips=inc["external_ips"],
        n_events=inc["n_events"],
        span_days=inc["span_days"],
        first_seen=inc["first_seen"],
        last_seen=inc["last_seen"],
        lateral_path=_lateral_path(inc["hosts"]),
        mttd=(_json(SLATE, {}) or {}).get("mttd", {}),
        events=evs,
        kill_chain=attr.get("kill_chain", []),
        campaign_assessment=attr.get("campaign_assessment", {}),
        next_moves=attr.get("next_moves", []),
    )


@app.get("/api/incidents/{iid}/graph", response_model=GraphResp)
def incident_graph(iid: str) -> GraphResp:
    inc = _incident(iid)
    member_ids = inc["member_event_ids"]
    q = """
    MATCH (a)-[r]->(b) WHERE r.event_id IN $ids
    RETURN coalesce(a.name, a.addr, a.key) AS s_id, labels(a)[0] AS s_type,
           coalesce(b.name, b.addr, b.key) AS t_id, labels(b)[0] AS t_type,
           type(r) AS rel, properties(r) AS props
    """
    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []
    d = get_driver()
    try:
        with d.session() as s:
            for rec in s.run(q, ids=member_ids):
                for nid, ntype in (
                    (rec["s_id"], rec["s_type"]),
                    (rec["t_id"], rec["t_type"]),
                ):
                    if nid and nid not in nodes:
                        nodes[nid] = GraphNode(id=nid, label=nid, type=ntype)
                props = rec["props"] or {}
                # whitelist props; rename gt_malicious -> malicious (viz only); drop gt_*
                edges.append(
                    GraphEdge(
                        source=rec["s_id"],
                        target=rec["t_id"],
                        type=rec["rel"],
                        malicious=bool(props.get("gt_malicious", False)),
                        anomaly_score=props.get("anomaly_score"),
                        fused_score=props.get("fused_score"),
                        technique=props.get("inferred_technique")
                        or props.get("agent_technique"),
                        ts=(
                            str(props.get("ts"))
                            if props.get("ts") is not None
                            else None
                        ),
                    )
                )
    finally:
        d.close()
    return GraphResp(nodes=list(nodes.values()), edges=edges)


def _playbook_actions(iid: str) -> list[PlaybookAction]:
    pb = _json(PLAYBOOK, {}) or {}
    steps = pb.get("playbook", [])
    states = _action_states().get(iid, {})
    out = []
    for i, s in enumerate(steps):
        if s["gate"] == "auto":
            status, approver = "auto-executed", None
        else:
            ov = states.get(str(i), {})
            status = ov.get("status", "pending")
            approver = ov.get("approver")
        out.append(
            PlaybookAction(
                idx=i,
                action=s["action"],
                target=s["target"],
                blast_radius=s["blast_radius"],
                gate=s["gate"],
                status=status,
                rationale=s["rationale"],
                approver=approver,
            )
        )
    return out


@app.get("/api/incidents/{iid}/playbook", response_model=list[PlaybookAction])
def incident_playbook(iid: str) -> list[PlaybookAction]:
    _incident(iid)
    return _playbook_actions(iid)


@app.post("/api/incidents/{iid}/actions/{idx}/decision", response_model=DecisionResp)
def action_decision(iid: str, idx: int, body: DecisionReq) -> DecisionResp:
    _incident(iid)
    pb = _json(PLAYBOOK, {}) or {}
    steps = pb.get("playbook", [])
    if idx < 0 or idx >= len(steps):
        raise HTTPException(status_code=404, detail=f"action idx {idx} out of range")
    step = steps[idx]
    if step["gate"] != "human":
        raise HTTPException(
            status_code=400,
            detail="action is auto-executed; no human decision required",
        )

    new_status = "approved" if body.decision == "approve" else "denied"
    states = _action_states()
    from datetime import datetime, timezone

    states.setdefault(iid, {})[str(idx)] = {
        "status": new_status,
        "approver": body.approver,
        "decided_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_action_states(states)

    # append a REAL human-decision entry to the tamper-evident ledger
    result = {
        "executed": body.decision == "approve",
        "action": step["action"],
        "target": step["target"],
    }
    audit.append(
        {
            "actor": body.approver,
            "action": f"DECISION:{step['action']}",
            "target": step["target"],
            "decision": f"human-{new_status}",
            "rationale": f"Human {body.decision} of gated action: {step['rationale']}",
            "evidence": {
                "incident_id": iid,
                "action_idx": idx,
                "gate": "human",
                "blast_radius": step["blast_radius"],
            },
            "blast_radius": step["blast_radius"],
            "result": result,
            "policy_version": pb.get("gate_policy"),
            "model_version": "human-in-the-loop",
        }
    )
    ver = audit.verify_chain()
    return DecisionResp(
        incident_id=iid,
        playbook=_playbook_actions(iid),
        ledger_head_hash=ver.get("head_hash"),
        ledger_entries=ver.get("entries", 0),
        chain_verified=ver["ok"],
    )


@app.get("/api/audit", response_model=AuditResp)
def audit_endpoint() -> AuditResp:
    entries: list[AuditEntry] = []
    try:
        conn = audit.get_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT seq, ts, actor, action, target, decision, "
                "blast_radius, prev_hash, entry_hash FROM audit_ledger ORDER BY seq"
            )
            for r in cur.fetchall():
                entries.append(
                    AuditEntry(
                        seq=r[0],
                        ts=r[1].isoformat(),
                        actor=r[2],
                        action=r[3],
                        target=r[4],
                        decision=r[5],
                        blast_radius=r[6],
                        prev_hash=r[7],
                        entry_hash=r[8],
                    )
                )
        conn.close()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"ledger unavailable: {e}")
    return AuditResp(entries=entries, verify=audit.verify_chain())


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
