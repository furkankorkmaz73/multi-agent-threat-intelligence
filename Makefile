SHELL := /bin/bash

.PHONY: help setup-python test-python thesis-scenario e2e-system real-cve-export real-benchmark balanced-benchmark run-api run-worker setup-frontend run-frontend build-frontend test-go docker-up docker-worker docker-down clean

help:
	@echo "Available targets:"
	@echo "  setup-python    Install Python dependencies"
	@echo "  test-python     Run Python test suite"
	@echo "  thesis-scenario Run deterministic local thesis scenario"
	@echo "  e2e-system      Run Go -> MongoDB -> Python worker -> FastAPI E2E scenario"
	@echo "  real-cve-export Generate curated CVE model results; set REAL_CVE_FLAGS"
	@echo "  real-benchmark  Run curated KEV/EPSS benchmark; set MODEL_RESULTS and REAL_BENCHMARK_FLAGS"
	@echo "  balanced-benchmark Run expanded balanced benchmark; set BALANCED_FLAGS"
	@echo "  run-api         Start FastAPI on localhost:8000"
	@echo "  run-worker      Run Python worker once for all sources"
	@echo "  setup-frontend  Install frontend dependencies"
	@echo "  run-frontend    Start Vite dashboard"
	@echo "  build-frontend  Build frontend"
	@echo "  test-go         Run Go tests"
	@echo "  docker-up       Start MongoDB, API, and frontend"
	@echo "  docker-worker   Run worker profile"
	@echo "  docker-down     Stop Docker Compose services"
	@echo "  clean           Remove common local caches"

setup-python:
	cd agent-python && python -m pip install -r requirements.txt

test-python:
	cd agent-python && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q -p no:ddtrace

thesis-scenario:
	cd agent-python && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m integration.thesis_scenario --output reports/thesis_scenario_report.json

e2e-system:
	cd agent-python && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python -m integration.e2e_system --output-dir $(HOME)/thesis-artifacts/e2e-system --generated-at 2026-06-10T00:00:00+00:00

real-cve-export:
	cd agent-python && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m evaluation.model_export --output-dir reports/real_benchmark/model_export --cache-dir .cache/real_benchmark $(REAL_CVE_FLAGS)

real-benchmark:
	cd agent-python && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m evaluation.real_benchmark --model-results $(MODEL_RESULTS) --output-dir reports/real_benchmark --cache-dir .cache/real_benchmark $(REAL_BENCHMARK_FLAGS)

balanced-benchmark:
	cd agent-python && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m evaluation.balanced_benchmark --output-dir reports/real_benchmark/balanced $(BALANCED_FLAGS)

run-api:
	cd agent-python && PYTHONPATH=src uvicorn api.app:app --reload --host 127.0.0.1 --port 8000

run-worker:
	cd agent-python && PYTHONPATH=src python src/main.py --source all --run-once

setup-frontend:
	cd agent-python/frontend && npm install

run-frontend:
	cd agent-python/frontend && npm run dev

build-frontend:
	cd agent-python/frontend && npm run build

test-go:
	cd agent-go && go test ./...

docker-up:
	docker compose up --build

docker-worker:
	docker compose --profile worker up --build worker

docker-down:
	docker compose down

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf agent-python/.pytest_cache .pytest_cache agent-python/frontend/dist
