PYTHON := .venv/bin/python
PIP    := .venv/bin/pip
SHELL  := /bin/bash

.PHONY: up down health fmt console generate replay consume spine-test graph-load graph-stats graph-killchain graph-verify ueba-score ueba-eval fuse incidents incidents-eval attack-kb attack-rag attribute-baseline attribute-eval attribute-agent attribute-compare respond soar-eval audit-build audit-verify audit-tamper-demo loop-summary api api-smoke

up:
	docker compose up -d

down:
	docker compose down

health:
	$(PYTHON) scripts/health_check.py

fmt:
	.venv/bin/ruff check --fix .
	.venv/bin/black .

console:
	cd console && npm run dev

# --- synthetic telemetry backbone -------------------------------------------

# Generate events.jsonl + ground_truth.json (no Redis needed).
generate:
	$(PYTHON) -m packages.scenario.generator --seed 42

# Compressed replay (default ~21 days -> ~2 min), clean stream first.
replay:
	$(PYTHON) -m services.ingest.replay --seed 42 --reset

# Drain + validate the stream and print the tally.
consume:
	$(PYTHON) -m services.ingest.consumer

# End-to-end spine proof: reset stream, start consumer in background, run a
# short compressed replay, then the consumer drains, prints the tally, and exits.
spine-test:
	@echo "[spine-test] resetting events:raw + launching consumer..."
	@$(PYTHON) -c "import redis,os; redis.from_url(os.getenv('REDIS_URL','redis://localhost:6379/0')).delete('events:raw')"
	@$(PYTHON) -m services.ingest.consumer --idle-timeout 5 --startup-grace 60 & \
	  CONSUMER_PID=$$!; \
	  sleep 2; \
	  $(PYTHON) -m services.ingest.replay --seed 42 --speed 2000000; \
	  wait $$CONSUMER_PID

# --- Neo4j provenance graph (correlation core) ------------------------------

# Clean reproducible load: clear the stream, wipe the graph, fresh seed=42
# replay, then ingest into Neo4j.
graph-load:
	$(PYTHON) -m services.ingest.replay --seed 42 --speed 1000000 --reset
	$(PYTHON) -m services.graph.ingest --reset

# Node counts by label + relationship counts by type.
graph-stats:
	$(PYTHON) -m services.graph.queries stats

# Malicious edges in temporal order (the reconstructed kill chain).
graph-killchain:
	$(PYTHON) -m services.graph.queries killchain

# All verification queries (counts, kill-chain, lateral path, crown jewel).
graph-verify:
	$(PYTHON) -m services.graph.queries all

# --- UEBA behavioural anomaly scoring ---------------------------------------

# Extract behavioural features -> unsupervised score -> write anomaly_score
# back onto the Neo4j graph. (Run `make graph-load` first.)
ueba-score:
	$(PYTHON) -m services.ueba.features
	$(PYTHON) -m services.ueba.score

# Evaluate scores against ground truth: metrics table, ROC/PR AUC, curve png.
ueba-eval:
	$(PYTHON) -m services.ueba.evaluate

# --- graph fusion + ranked incidents ----------------------------------------

# Diffuse anomaly heat via personalized PageRank; write fused_score to the graph.
fuse:
	$(PYTHON) -m services.graph.fuse

# Assemble + rank incidents from fused weak signals; persist Incident nodes.
incidents:
	$(PYTHON) -m services.graph.incidents

# Incident quality, weak-signal recovery, and MTTD vs ground truth.
incidents-eval:
	$(PYTHON) -m services.graph.evaluate_incidents

# --- ATT&CK attribution (KB + RAG + deterministic mapper) -------------------

# Build/cache the MITRE ATT&CK knowledge base (live STIX, subset fallback).
attack-kb:
	$(PYTHON) -m services.attribution.attack_kb

# Build the threat-intel RAG vector store + run the sanity query.
attack-rag:
	$(PYTHON) -m services.attribution.rag

# Run the deterministic behavioural->ATT&CK mapper; write inferred_technique.
attribute-baseline:
	$(PYTHON) -m services.attribution.mapper

# Technique-level accuracy vs ground truth (gt read here only).
attribute-eval:
	$(PYTHON) -m services.attribution.evaluate

# Run the live Claude attribution agent on the top incident (or fallback if no key).
attribute-agent:
	$(PYTHON) -m services.attribution.agent

# Compare agent vs ground truth vs the deterministic baseline.
attribute-compare:
	$(PYTHON) -m services.attribution.evaluate

# --- SOAR response (planner + orchestrator + blast-radius gates) ------------

# Plan the containment playbook then orchestrate it (auto / human-gated).
respond:
	$(PYTHON) -m services.soar.planner
	$(PYTHON) -m services.soar.orchestrator

# Automation-coverage metric (auto vs human-gated breakdown).
soar-eval:
	$(PYTHON) -m services.soar.evaluate coverage

# --- tamper-evident audit ledger + metrics slate ----------------------------

# Build the audit_ledger schema + append-only trigger (DDL migration).
audit-build:
	$(PYTHON) -m services.soar.audit build

# Verify the hash chain over the ledger.
audit-verify:
	$(PYTHON) -m services.soar.audit verify

# Demonstrate tamper detection (intact -> mutate one row -> chain BROKEN).
audit-tamper-demo:
	$(PYTHON) scripts/audit_tamper_demo.py

# MTTR + consolidated metrics slate + closed-loop breach-prevented counterfactual.
loop-summary:
	$(PYTHON) -m services.soar.evaluate loop

# --- BFF API gateway --------------------------------------------------------

# Run the FastAPI backend-for-frontend (for the analyst console).
api:
	$(PYTHON) -m uvicorn services.api.main:app --port 8000 --reload

# Smoke-test every GET endpoint + one POST decision round-trip.
api-smoke:
	$(PYTHON) scripts/api_smoke.py
