PYTHON := .venv/bin/python
PIP    := .venv/bin/pip
SHELL  := /bin/bash

.PHONY: up down health fmt console generate replay consume spine-test

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
