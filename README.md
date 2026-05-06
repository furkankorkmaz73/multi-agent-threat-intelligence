# Multi-Agent Cyber Threat Intelligence & Risk Analysis System

A multi-agent cyber threat intelligence (CTI) prototype that collects signals from CVE/NVD, URLhaus, and Dread-like open-source threat sources, stores them in MongoDB, and produces explainable dynamic risk scores through a Python analysis pipeline.

The project combines:

- Go-based threat intelligence collectors
- MongoDB persistence
- Python analysis and orchestration
- FastAPI service layer
- React/Vite dashboard
- NLP-assisted evidence extraction
- Cross-source correlation
- Graph-based context analysis
- Explainable risk scoring and recommendations

This is intended as an academic/prototype-grade CTI analysis system. It is suitable for demonstrations and portfolio use, but additional work is required before production use.

---

## Current Status

The project is no longer only a proposal. The current codebase includes:

- Go collectors for external intelligence feeds
- MongoDB-backed persistence
- Python worker for analysis orchestration
- FastAPI API for findings and analysis results
- React/Vite dashboard
- Risk scoring, correlation, graph analysis, reporting, and evaluation modules
- Python tests for the analysis layer and API-related behavior
- Docker Compose development environment
- GitHub Actions CI workflow

The end-to-end flow has been verified locally:

```text
Go collectors
  → MongoDB
  → Python analysis worker
  → FastAPI
  → React dashboard
```

---

## Architecture

```text
Threat Sources
  ├─ NVD / CVE
  ├─ URLhaus
  └─ Dread-like source
        ↓
Go Collectors
        ↓
MongoDB
        ↓
Python Worker / Analysis Pipeline
  ├─ Planner
  ├─ Correlator
  ├─ Graph Builder
  ├─ Risk Engine
  ├─ Critic
  └─ Recommender
        ↓
FastAPI
        ↓
React Dashboard
```

---

## Repository Structure

```text
agent-go/                  Go-based data collection agents
agent-python/src/          Python analysis, API, core, evaluation and reporting modules
agent-python/tests/        Python tests
agent-python/frontend/     React/Vite dashboard
docs/                      Analysis engine and architecture notes
docker-compose.yml         MongoDB + API + frontend development environment
Makefile                   Common setup, test and run commands
.github/workflows/ci.yml   CI workflow for Python, Go and frontend validation
.env.example               Safe environment variable template
```

---

## Security Notice

Do not commit a real `.env` file.

Only `.env.example` should be stored in the repository. Real API keys, database credentials, and connection strings must stay local.

Recommended setup:

```bash
cp .env.example .env
```

Then edit `.env` with your local values:

```text
CVE_KEY=your-nvd-api-key
MONGO_URI=mongodb://localhost:27017
DB_NAME=threat_intel
```

If real keys or database credentials were previously exposed, rotate them before pushing the project publicly.

---

## Requirements

Recommended local tooling:

- Python 3.11+
- Go 1.22+
- Node.js 20+
- Docker and Docker Compose
- MongoDB, either local or Docker-based

---

## Local Setup

### 1. Python API and Worker

```bash
cd agent-python
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the API:

```bash
PYTHONPATH=src uvicorn api.app:app --reload
```

Run the worker once:

```bash
PYTHONPATH=src python src/main.py --source all --run-once
```

---

### 2. Go Collectors

```bash
cd agent-go
go test ./...
```

Fetch a small CVE batch:

```bash
go run ./cmd/agent-go -source cve -limit 20 -mode incremental -days 2
```

Fetch URLhaus records:

```bash
go run ./cmd/agent-go -source urlhaus -limit 50
```

Supported sources:

```text
cve
urlhaus
dread
```

---

### 3. Frontend

```bash
cd agent-python/frontend
npm install
npm run dev
```

The dashboard runs at:

```text
http://localhost:5173
```

By default, the frontend talks to:

```text
http://127.0.0.1:8000
```

To override this, create `agent-python/frontend/.env`:

```text
VITE_API_BASE=http://127.0.0.1:8000
```

---

## Docker Compose

Docker is mainly used to simplify the development/demo environment. It is not mandatory for every component, but it makes MongoDB, the API, and the frontend easier to run consistently.

Start the stack:

```bash
docker compose up --build
```

Expected services:

```text
MongoDB   → http://localhost:27017
API       → http://localhost:8000
Frontend  → http://localhost:5173
```

The API and frontend containers are built from dedicated Dockerfiles, so dependencies are not installed from scratch every time the containers start.

To stop the stack:

```bash
docker compose down
```

To run the optional worker profile:

```bash
docker compose --profile worker up --build worker
```

---

## Recommended Development Mode

For day-to-day development, the most practical setup is hybrid:

```text
Docker:
  - MongoDB

Local:
  - Go collector
  - Python API
  - Python worker
  - React frontend
```

Start only MongoDB:

```bash
docker compose up mongodb
```

Then run the API, worker, frontend, and collectors locally. This keeps development faster while still avoiding local MongoDB installation issues.

---

## Makefile Commands

From the repository root:

```bash
make setup-python
make test-python
make run-api
make run-worker
make setup-frontend
make run-frontend
make build-frontend
make test-go
make docker-up
```

---

## API Examples

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Top analyzed findings:

```bash
curl "http://127.0.0.1:8000/findings/top?limit=10"
```

Manual CVE analysis:

```bash
curl -X POST http://127.0.0.1:8000/analyze/cve \
  -H "Content-Type: application/json" \
  -d '{"_id":"CVE-2026-DEMO","descriptions":[{"value":"remote code execution in vpn appliance"}]}'
```

---

## End-to-End Demo Flow

1. Start MongoDB, API, and frontend:

```bash
docker compose up --build
```

2. In a separate terminal, collect CVE data:

```bash
cd agent-go
go run ./cmd/agent-go -source cve -limit 20 -mode incremental -days 2
```

3. Collect URLhaus records:

```bash
go run ./cmd/agent-go -source urlhaus -limit 50
```

4. Run the Python analysis worker:

```bash
cd ../agent-python
source .venv/bin/activate
PYTHONPATH=src python src/main.py --source all --run-once
```

5. Check API results:

```bash
curl "http://localhost:8000/findings/top?limit=5"
```

6. Open the dashboard:

```text
http://localhost:5173
```

---

## Analysis Engine

The analysis engine is the core value of the project. It is designed to produce explainable prioritization, not a black-box prediction.

The pipeline evaluates several signal groups:

- Base technical severity from CVSS
- NLP-derived vulnerability context
- Source correlation from URLhaus and Dread-like records
- Entity and keyword alignment
- Graph structure and centrality
- Recency and age effects
- Evidence quality and confidence
- Counterfactual score comparisons

The main analysis modules are:

```text
agent-python/src/analysis/
  correlator.py
  graph_builder.py
  keyword_extractor.py
  nlp_features.py
  risk_engine.py
  scoring.py
  semantic_similarity.py
```

The runtime path is:

```text
src/main.py
  → agents/orchestrator.py
    → analysis/risk_engine.py
      → correlator / graph_builder / scoring / nlp_features
```

---

## NLP and Evidence Extraction

The lightweight NLP layer extracts security-relevant entities such as:

- CVE identifiers
- CWE identifiers
- affected products
- versions
- vulnerability types
- impact terms
- exploit/threat terms
- IOCs
- domains
- salient phrases

This extraction is used to reduce raw keyword noise and improve correlation quality.

Example extracted entities:

```text
products:
  - cisco secure firewall
  - remote access ssl vpn

vulnerability types:
  - denial_of_service

impacts:
  - service_disruption
  - initial_access

threat terms:
  - exploit
  - access
```

---

## Evidence-Gated Correlation

Correlation is intentionally conservative.

Retrieved candidates are not automatically treated as accepted evidence. A URLhaus or Dread candidate must pass an evidence gate before it can influence risk scoring, confidence, or graph context.

Accepted evidence may be based on:

- exact CVE match
- strong entity alignment
- high-signal exploit or malware terms
- meaningful lexical overlap
- semantic and temporal support

Rejected candidates remain diagnostic information only. They must not:

- increase the risk score
- create risk-relevant graph edges
- increase confidence
- appear as accepted related evidence

This prevents weak keyword overlap from producing misleading risk increases.

---

## Risk Score Breakdown

The risk engine separates score components for explainability:

```text
base_cvss_component
nlp_context_bonus
urlhaus_correlation_bonus
dread_correlation_bonus
cross_source_bonus
graph_bonus
age_penalty
final_score
```

The model also stores counterfactuals, for example:

```text
score_without_graph
score_without_urlhaus
score_without_dread
score_without_llm_context
```

This makes it easier to explain why a score changed.

---

## Confidence Model

Risk score and confidence are treated separately.

A high score means the item should be prioritized. High confidence means the system has strong evidence for that score.

Confidence is based on evidence quality, including:

- presence of CVSS metadata
- quality of normalized entities
- accepted external evidence
- exact CVE hits
- high-signal terms
- entity overlap
- semantic signal
- graph support

Rejected evidence and generic keyword overlap should not inflate confidence.

---

## Dashboard Analysis Visibility

The dashboard renders the analysis layer directly instead of hiding it in raw JSON.

It includes:

- evidence overview metrics
- score breakdown bars
- NLP entity chips
- source contribution cards
- counterfactual output
- source-level evidence panels

This makes the NLP/correlation/risk-engine behavior visible during demos and manual review.

---

## Tests

Run Python tests:

```bash
cd agent-python
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q -p no:ddtrace
```

or from the repository root:

```bash
make test-python
```

Run a minimal API smoke test while the API is running:

```bash
cd agent-python
python3 scripts/smoke_api.py http://127.0.0.1:8000
```

Some test environments include external pytest plugins such as `ddtrace`, which may slow down test shutdown. The `-p no:ddtrace` flag disables that plugin for the test run.

---

## Validation Status

The Python test suite has been verified after the latest analysis semantics changes.

Latest expected result:

```text
54 passed
```

Go and frontend validation should be run in an internet-enabled environment because they may need to download dependencies:

```bash
make test-go
make setup-frontend
make build-frontend
```

---

## Known Limitations

This is a prototype. Important limitations remain:

- Risk scoring is heuristic and requires real-world validation.
- The current NLP layer is lightweight and rule-based.
- Dread-like source handling depends on available data and ethical/legal constraints.
- URLhaus correlation must be interpreted carefully; weak or rejected candidates should not be treated as confirmed relationships.
- The system does not include authentication, TLS, rate limiting, or production observability.
- The dashboard is intended for demonstration and analyst support, not as a SOC production console.

---

## Possible Improvements

### Short Term

- Split large FastAPI route logic into separate route modules.
- Add date and severity filters to the dashboard.
- Improve API response models for full analysis inspection.
- Add a “re-run analysis” endpoint for selected findings.
- Add seeded demo data for easier showcase setup.

### Medium Term

- Introduce repository interfaces to reduce direct MongoDB coupling.
- Add structured logging and metrics.
- Improve graph scoring with stricter evidence-quality weights.
- Add benchmark datasets for risk model validation.
- Add frontend export and comparison views.

### Long Term

- Add authentication, TLS, and rate limiting.
- Add scheduled ingestion and alerting.
- Tune model weights using real analyst feedback.
- Add production-grade semantic model support.
- Integrate with SIEM/SOAR or ticketing workflows.

---

## Suggested Commit Order

If this project is being pushed to GitHub from the staged versions, a clean commit history would be:

```text
chore: initialize project with safe configuration
chore: add developer tooling and CI
refactor: add NLP-driven evidence analysis
feat: show explainable analysis in dashboard
fix: enforce accepted evidence gating in risk analysis
docs: rewrite README in English
```

---

## License and Ethical Use

This project is for academic, research, and prototype purposes.

When working with third-party intelligence feeds, dark-web-like sources, malware URLs, or threat infrastructure, follow applicable laws, source terms of service, and ethical research practices.

Do not use this project to access, distribute, or interact with malicious infrastructure beyond safe defensive analysis.

---

## Author

Furkan Korkmaz

## Risk Model Recalibration

The CVE risk model now separates risk priority from evidence confidence. CVSS is treated as the severity anchor, accepted URLhaus/Dread evidence contributes to active threat scoring, and missing external corroboration primarily lowers confidence instead of forcing high-severity CVEs into LOW risk.

A diagnostics utility is available for before/after model comparison:

```bash
cd agent-python
PYTHONPATH=src python src/evaluation/model_diagnostics.py --source cve --suffix before
PYTHONPATH=src python src/evaluation/model_diagnostics.py --source cve --suffix after
```

See `docs/analysis_engine_v4.md` for the recalibrated model details.
