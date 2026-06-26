# Prahari — AI Cyber-Resilience Platform

Prahari is an AI-powered cyber-resilience platform that ingests and normalises endpoint/network telemetry, runs UEBA behavioural anomaly scoring, correlates events in a graph database, attributes tactics to MITRE ATT&CK via Claude agents, triggers automated SOAR playbook responses, and records every decision in a tamper-evident audit trail — giving SOC teams real-time detection, attribution, and response in a single pane of glass.

## Pipeline

```
Ingest/Normalize → UEBA Anomaly Scoring → Graph Correlation
  → MITRE ATT&CK Attribution (Claude) → SOAR Response → Audit
```

## Prerequisites

- Docker + Docker Compose
- Python 3.11+
- Node.js 18+ / npm
- (Optional) `uv` for faster Python dependency management

## Quickstart

```bash
cp .env.example .env          # fill in ANTHROPIC_API_KEY
make up                        # start Neo4j, Redis, Postgres
make health                    # verify all services are reachable
```

## Development

```bash
make fmt          # ruff + black
make console      # start Next.js dev server (console/)
make down         # stop containers
```

## Structure

```
services/   — Python microservices (ingest, ueba, graph, attribution, soar, api)
packages/   — shared libraries (schema: SecurityEvent contract)
console/    — Next.js operator dashboard
scripts/    — CLI utilities (health_check.py, …)
docs/       — architecture diagrams and ADRs
data/       — gitignored; see data/README.md for dataset fetch instructions
notebooks/  — exploratory analysis
```
