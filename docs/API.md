# PRAHARÍ — BFF API Reference

FastAPI on **:8000** (`make api`), CORS for the console on :3000. **Every response is stripped of `gt_*` fields** — the API cannot leak ground truth to the UI (verified: 0/8 endpoints leak; `make api-smoke`).

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | liveness of Neo4j + Postgres |
| GET | `/api/metrics/slate` | the full metrics slate (from `data/metrics_slate.json`) |
| GET | `/api/incidents` | ranked incident list |
| GET | `/api/incidents/{id}` | one incident: status, score, hosts, technique chips, agent mode |
| GET | `/api/incidents/{id}/graph` | nodes + edges for the Cytoscape visualization |
| GET | `/api/incidents/{id}/playbook` | playbook steps with gate status |
| POST | `/api/incidents/{id}/actions/{idx}/decision` | human gate verdict — **appends a real audit-ledger entry** |
| GET | `/api/audit` | ledger entries + live `verify_chain()` result |

## Shapes (abridged, from the live smoke run)

```jsonc
// GET /api/health → 200
{ "neo4j": "ok", "postgres": "ok" }

// GET /api/metrics/slate → 200 (excerpt)
{ "ueba": { "roc_auc": 0.9988, "recall_at_1pct_fpr": 1.0 }, "soar": { "coverage": 0.75 }, … }

// GET /api/incidents → 200 (excerpt)
[ { "id": "INC-001", "score": 34.156, "hosts": ["DB-EXAMS","DC01","WS03"], "lateral": true }, … ]

// GET /api/incidents/INC-001 → 200 (excerpt)
{ "id": "INC-001", "status": "contained", "agent_mode": "fallback|live", "techniques": ["T1566","T1078","T1003","T1021","T1560","T1041","T1071"] }

// GET /api/incidents/INC-001/graph → 200
{ "nodes": [ /* 28 */ ], "edges": [ /* 71, scored by the system's own anomaly values */ ] }

// GET /api/incidents/INC-001/playbook → 200 (excerpt)
{ "actions": [ /* 8 */ ], "gated": [6, 7] }   // 6=isolate DB-EXAMS, 7=disable admin.it

// POST /api/incidents/INC-001/actions/6/decision  {"decision":"approve"} → 200
{ "ledger_entries": 11, "head_hash": "61bed0a17c09…", "verified": true }   // was 10 before

// GET /api/audit → 200 (excerpt)
{ "entries": [ /* seq, actor, action, prev_hash, entry_hash */ ], "verify": { "ok": true } }
```

Notes: the decision endpoint is the only mutating route; it executes the gate verdict and ledger append atomically. `agent_mode` surfaces whether attribution came from the live Claude agent or deterministic fallback — the UI badge reads this, so fallback is never silently presented as live.
