# PRAHARÍ — Setup & Run Guide

## Prerequisites

- **Docker engine** — Docker Desktop *or* colima (`brew install colima && colima start`)
- **Python 3.11+** (dev used 3.14) · **Node 20+** / npm
- ~4 GB free RAM for the three containers

## 1 · Environment

```bash
git clone https://github.com/Kartik-99999/prahari && cd prahari
python3 -m venv .venv && .venv/bin/pip install -e .    # or: uv sync
cp .env.example .env
```

`.env` keys:

| Key | Purpose | Default |
|---|---|---|
| `NEO4J_AUTH` | Neo4j user/pass | `neo4j/prahari_dev` |
| `POSTGRES_*` | audit-ledger DB | port **5433** on host |
| `REDIS_URL` | event bus | `redis://localhost:6379/0` |
| `ANTHROPIC_API_KEY` | **optional** — live Claude agents; empty ⇒ deterministic fallback | empty |
| `PRAHARI_AGENT_MODEL` | agent model | `claude-sonnet-4-6` |

## 2 · Infrastructure

```bash
make up        # neo4j (+APOC,GDS) · redis · postgres(:5433)
make health    # expect: Neo4j OK · Redis OK · Postgres OK   (retry ~15s after cold start)
```

## 3 · The full loop (deterministic, seed 42)

```bash
make graph-load          # replay 2,128-event / 21-day scenario into Redis→Neo4j
make graph-verify        # kill chain + lateral path WS03→DC01→DB-EXAMS present
make ueba-score          # unsupervised scoring (integrity guardrail asserts no leakage)
make ueba-eval           # ROC 0.9988 · 100% recall @ ~1% FPR · writes docs/ueba_roc_pr.png
make fuse                # anomaly-lift fusion (personalized PR / uniform PR)
make incidents           # INC-001 assembled (score ≈4× next)
make attack-kb attack-rag        # ATT&CK STIX KB + Chroma index (233 docs)
make attribute-agent     # Claude agent (LIVE with key, FALLBACK without)
make attribute-eval      # 92.3% technique accuracy, 0 false attributions
make respond             # SOAR planner + orchestrator (6 auto / 2 gated)
make audit-build audit-verify    # hash-chained ledger, verified
make audit-tamper-demo   # rewrite a row → chain breaks at that exact seq
make loop-summary        # the full metrics slate → data/metrics_slate.json
```

## 4 · App

```bash
make api                          # FastAPI BFF on :8000
cd console && npm install && npm run dev   # SOC console on :3000 (header badge should read ● LIVE · BFF)
make api-smoke                    # 8 endpoints, expects all 200 + gt-leak check PASS
```

## 5 · Evaluation suites (all held-out / frozen)

```bash
make ueba-benchmark   # CIC-IDS-2017 public benchmark (fetch CSVs first — see data/README.md)
make scenario2        # generalization: insider attack, frozen thresholds (seed 77)
make ot-demo          # Modbus/SCADA OT attack through the frozen loop (seed 1337)
make scale-bench      # 10k/100k/1M-event throughput + Neo4j latency
make adversarial      # off-hours-evasion robustness probe
make notify           # real webhook connector — DRY-RUN unless PRAHARI_WEBHOOK_URL + --send
```

## Troubleshooting

- **`make health` fails immediately** → containers still warming; retry after ~15 s. If Docker itself is down: `colima start` (or launch Docker Desktop).
- **`colima status` says running but docker fails with `dial unix /var/run/docker.sock: no such file`** → stale colima state (after a force-stop or crash): `colima stop -f && colima start`.
- **Port 5433** → Postgres is published on 5433 deliberately, to coexist with a local Postgres on 5432. Change in `docker-compose.yml` + `.env` together.
- **CIC-IDS-2017 missing** → the CSVs are gitignored; fetch per `data/README.md` (HF mirror `c01dsnap/CIC-IDS2017`), then `make ueba-benchmark`.
- **Agent shows FALLBACK** → run live with `ANTHROPIC_API_KEY` (`make attribute-agent`) **or** key-free via the Claude Code subscription CLI (`make attribute-agent-live`). If the CLI returns 429 "session limit", wait for the stated reset time — the agent retries ×3 then falls back cleanly (deterministic, demo-safe).
- **`make scale-bench` looks ~2× slow** → check macOS **Low Power Mode** / battery; the benchmark is single-core and tracks CPU clock (see `RESULTS.md` §5).
- **Scenario 2 / OT runs "touch" my demo graph?** → they don't: both run `--no-write` throughout; `scale-bench` uses a dedicated `:ScaleEvent` label and DETACH-DELETEs it (leak-checked).
- **Clean slate** → `make down` (containers) · re-run `make graph-load` (idempotent MERGE ingest).
