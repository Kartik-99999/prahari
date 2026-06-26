PYTHON := .venv/bin/python
PIP    := .venv/bin/pip

.PHONY: up down health fmt console

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
