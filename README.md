# Multi-Agent Threat Intelligence Platform

An explainable threat intelligence platform for collecting, analyzing, prioritizing, and reviewing CVE and URLhaus intelligence.

The project combines a Go-based collector, a Python analysis engine, MongoDB persistence, FastAPI APIs, and a React analyst console. It demonstrates practical security engineering patterns: multi-source ingestion, explainable risk scoring, evidence-quality confidence, model diagnostics, and analyst-oriented triage workflows.

---

## What This Project Does

This platform collects and analyzes threat intelligence from multiple sources:

- **CVE / NVD** vulnerability intelligence
- **URLhaus** malicious URL / IOC intelligence
- Optional experimental forum-style intelligence records through the Dread pipeline

The system persists raw intelligence records in MongoDB, runs an explainable analysis pipeline, and exposes the results through an analyst console.

The analyst console supports:

- Source-level coverage and health metrics
- Prioritized findings
- CVSS and evidence summaries
- Risk score and risk level
- Confidence score and confidence breakdown
- Primary score drivers
- NLP-extracted entities
- Evidence-quality inspection
- Model diagnostics
- Ad-hoc payload analysis

---

## Current Project Status

This project is currently best described as:

> **MVP+ / portfolio-grade analyst console**

It is not production-ready or SOC-grade yet, but it is beyond a simple demo. The system can collect real intelligence data, persist it, analyze tens of thousands of records, and explain how prioritization decisions were made.

Validated local dataset snapshot:

| Metric | Value |
|---|---:|
| Total records | ~53k |
| CVE records | ~25k |
| URLhaus records | ~28k |
| CVE analyzed coverage | ~99.9% |
| URLhaus records analyzed | ~28k local run |
| Average analyzed CVE risk | ~3.85 / 10 |

---

## Architecture

```text
+-------------------+        +-------------------+
|   Go Collector    |        |  Python Analyzer  |
|-------------------|        |-------------------|
| NVD / CVE fetch   | -----> | Risk scoring      |
| URLhaus fetch     |        | Confidence model  |
| Optional Dread    |        | Correlation       |
+-------------------+        | NLP extraction    |
          |                  | Graph context     |
          v                  +-------------------+
+-------------------+                  |
|      MongoDB      | <----------------+
|-------------------|
| raw intel records |
| analysis results  |
+-------------------+
          |
          v
+-------------------+        +-------------------+
|     FastAPI       | -----> | React Dashboard   |
|-------------------|        |-------------------|
| health/status     |        | Analyst console   |
| findings API      |        | Triage modes      |
| evaluation API    |        | Detail inspector  |
| ad-hoc analysis   |        | Diagnostics view  |
+-------------------+        +-------------------+
```

---

## Repository Layout

```text
.
├── agent-go/
│   ├── cmd/agent-go/              # Go CLI entrypoint
│   └── internal/
│       ├── fetch/                 # CVE, URLhaus, Dread collectors
│       ├── db/                    # MongoDB persistence
│       └── models/                # Collector data models
│
├── agent-python/
│   ├── src/
│   │   ├── analysis/              # Risk engine, correlation, NLP, graph context
│   │   ├── agents/                # Orchestration and optional LLM helper
│   │   ├── api/                   # FastAPI application and schemas
│   │   ├── core/                  # Database and persistence logic
│   │   ├── evaluation/            # Diagnostics and model evaluation utilities
│   │   └── main.py                # Analysis worker entrypoint
│   │
│   ├── tests/                     # Python test suite
│   └── frontend/                  # React analyst console
│
├── docs/                          # Model and engineering documentation
├── docker-compose.yml
├── Makefile
└── README.md
```

---

## Security Configuration

Local development defaults to explicit development authentication:

```text
API_AUTH_MODE=development
API_DEV_ACTOR_ID=local-dev
API_DEV_ROLE=admin
```

For protected deployments, enable API-key authentication and provide keys only through environment variables:

```text
API_AUTH_MODE=api_key
API_KEYS=devkey1:analyst:analyst-1,adminkey1:admin:admin-1
```

Supported roles are `viewer`, `analyst`, `operator`, and `admin`. Health and source discovery remain public; analysis reads, analysis triggers, job/status views, and configuration-sensitive actions are checked through centralized API permissions. Audit events are structured and omit authorization headers, API keys, tokens, passwords, and secret-like fields.

## CI Validation

The GitHub Actions workflow runs:

```bash
cd agent-python && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m pytest -q -p no:ddtrace
cd agent-python/frontend && npm ci && npm test && npm run compile-check && npm run lint && npm run build && npm audit --omit=dev
cd agent-go && GOTOOLCHAIN=go1.24.0 go test ./... && go mod verify
```

It also runs lightweight dependency sanity and tracked-file secret checks without external paid services.

## Thesis Scenario

A deterministic local end-to-end scenario exercises fixture ingestion, worker lifecycle, orchestration, API-compatible result shaping, asset-aware operational risk, and KEV/EPSS evaluation without live MongoDB, OpenAI, network access, or secrets:

```bash
make thesis-scenario
```

The command writes `agent-python/reports/thesis_scenario_report.json`.

## Production-like E2E Scenario

Prerequisites: Docker, Go, and the Python virtualenv under `agent-python/.venv`.

Run the disposable Go -> MongoDB -> Python worker -> FastAPI scenario:

```bash
make e2e-system
```

The scenario uses the dedicated `threat_intel_e2e` MongoDB database, resets only that database, ingests deterministic local fixtures through the Go collector, processes them with the real Python worker, verifies FastAPI health/auth/read paths, and writes `~/thesis-artifacts/e2e-system/e2e_system_report.json`.

Generate thesis-ready tables, charts, and case-study artifacts from existing benchmark outputs:

```bash
cd agent-python
PYTHONPATH=src .venv/bin/python -m evaluation.thesis_reporting \
  --objective-dir ~/thesis-artifacts/objective-evaluation/ \
  --balanced-dir ~/thesis-artifacts/balanced-benchmark/balanced/ \
  --correlation-dir ~/thesis-artifacts/correlation-benchmark/out/ \
  --output-dir ~/thesis-artifacts/thesis-reporting/ \
  --generated-at 2026-06-10T00:00:00+00:00
```

## Real CVE Benchmark

The curated real-data benchmark compares exported CVE model results against CISA KEV and FIRST EPSS data. It requires a JSON model-results export containing analyzed CVE rows with `cve_id` or `entity_id`, `risk_score`, `confidence`, `cvss_score` or `evidence.cvss_score`, and optional feature/evidence fields.

Generate curated CVE model results from local cached official-format NVD data:

```bash
make real-cve-export REAL_CVE_FLAGS="--cve-file .cache/real_benchmark/nvd_curated_cves.json --offline"
```

Generate model results and immediately run the KEV/EPSS benchmark with local official-format files:

```bash
make real-cve-export REAL_CVE_FLAGS="--cve-file .cache/real_benchmark/nvd_curated_cves.json --offline --run-benchmark --kev-file .cache/real_benchmark/cisa_kev.json --epss-file .cache/real_benchmark/first_epss.csv"
```

The model export writes `model_results.json`, `model_results.csv`, `analysis_failures.json`, and `run_metadata.json` under `agent-python/reports/real_benchmark/model_export/`.

Build and evaluate the expanded balanced benchmark from local official-format NVD, KEV, and EPSS files:

```bash
make balanced-benchmark BALANCED_FLAGS="--nvd-file .cache/real_benchmark/nvd_candidates.json --kev-file .cache/real_benchmark/cisa_kev.json --epss-file .cache/real_benchmark/first_epss.csv --model-results reports/real_benchmark/model_export/model_results.json"
```

The balanced runner writes `balanced_benchmark_definition.json`, `benchmark_summary.json`, `benchmark_records.csv`, `baseline_metrics.csv`, `ablation_metrics.csv`, `ablation_records.csv`, `benchmark_diagnostics.json`, and `case_candidates.json` under `agent-python/reports/real_benchmark/balanced/`.

Online refresh:

```bash
make real-benchmark MODEL_RESULTS=reports/model_results.json REAL_BENCHMARK_FLAGS=--refresh
```

Offline cached run:

```bash
make real-benchmark MODEL_RESULTS=reports/model_results.json REAL_BENCHMARK_FLAGS=--offline
```

The runner writes `benchmark_summary.json`, `benchmark_records.csv`, and `baseline_metrics.csv` under `agent-python/reports/real_benchmark/`. Official datasets are cached under `agent-python/.cache/real_benchmark/`; both locations are ignored local outputs.

---

## Core Concepts

### Risk Score

`risk_score` answers:

> How operationally important is this finding?

It is a priority score between `0` and `10`.

Risk score considers different signals depending on the source.

For CVEs:

- CVSS severity
- vulnerability type
- impact context
- exploitation-related NLP signals
- accepted cross-source evidence
- temporal age penalty
- graph context

For URLhaus IOCs:

- malicious feed presence
- online/offline status
- malware-download classification
- payload indicators
- malware family tags
- delivery pattern
- tag density
- graph context

---

### Confidence Score

`confidence` answers:

> How well supported is this risk score by evidence?

Confidence is intentionally separate from risk.

A finding can be:

```text
High risk + medium confidence
```

This means:

```text
The intrinsic severity is high, but external corroboration is limited.
```

The platform stores confidence breakdowns to explain why a confidence value was produced.

For CVEs:

```text
base_confidence
metadata_confidence
entity_confidence
external_evidence_confidence
correlation_confidence
freshness_confidence
penalties
final_confidence
```

For URLhaus:

```text
feed_confidence
status_confidence
threat_label_confidence
tag_confidence
payload_confidence
family_confidence
freshness_confidence
cross_source_confidence
graph_confidence
penalties
final_confidence
```

---

## CVE Risk Model

The CVE risk model was recalibrated to avoid suppressing high-severity vulnerabilities too aggressively.

Key design decisions:

- CVSS is treated as the primary severity anchor.
- Age penalties are capped and do not destroy high technical severity.
- Active external evidence increases priority.
- Missing external corroboration lowers confidence more than it lowers risk.
- NLP extraction contributes exploitability and impact context.
- Risk and confidence are separate outputs.

Example behavior:

```text
CVSS 10 + RCE/buffer overflow + no active external evidence
→ HIGH risk
→ medium confidence
```

This is intentional. It means the vulnerability is technically severe but still needs analyst validation or environment context.

---

## URLhaus IOC Risk Model

URLhaus scoring is source-specific because IOCs are different from CVEs.

The URLhaus model considers:

```text
base_feed_component
threat_type_score
status_score
payload_score
malware_family_score
delivery_pattern_score
tag_density_score
freshness_score
cross_source_score
graph_bonus
```

Example behavior:

```text
online + malware_download + bin.sh + ELF + Mirai/Mozi tags
→ HIGH IOC risk
→ high confidence
```

```text
offline + weak tags + no payload signal
→ LOW IOC risk
```

The model aligns score and level consistently:

```text
0.0 – 3.9   LOW
4.0 – 6.4   MEDIUM
6.5 – 8.4   HIGH
8.5 – 10.0  CRITICAL
```

---

## Optional LLM Support

The project includes optional OpenAI-compatible LLM support.

LLM usage is not required for the pipeline to work.

If `OPENAI_API_KEY` is configured, the Python analyzer can use the LLM helper for:

- CVE structured field extraction
- Dread post classification
- short analyst-style explanation generation

If no API key is configured:

- the LLM client is disabled
- LLM helper functions return empty values
- deterministic NLP, scoring, graph context, and correlation still run normally

Environment variables:

```bash
OPENAI_API_KEY=your_key_here
OPENAI_BASE_URL=
LLM_MODEL=gpt-4o-mini
```

This makes the project:

> **LLM-optional, not LLM-dependent**

---

## Data Sources

### CVE / NVD

The Go collector can fetch CVE records from NVD.

Example:

```bash
cd agent-go
go run ./cmd/agent-go -source cve -mode full -limit 25000
```

Incremental example:

```bash
go run ./cmd/agent-go -source cve -mode incremental -days 30 -limit 500
```

### URLhaus

The Go collector can fetch URLhaus IOC records.

```bash
cd agent-go
go run ./cmd/agent-go -source urlhaus -limit 30000
```

### Dread

A Dread collector path exists, but this source should be treated as optional / experimental in the current project state.

---

## Running With Docker

Start MongoDB, API, and frontend:

```bash
docker compose up -d
```

Check containers:

```bash
docker ps
```

Expected services:

```text
threat-agent-mongodb
threat-agent-api
threat-agent-frontend
```

API:

```text
http://localhost:8000
```

Frontend:

```text
http://localhost:5173
```

---

## Running Locally

### 1. Start MongoDB

```bash
docker compose up -d mongodb
```

Check MongoDB:

```bash
mongosh mongodb://localhost:27017
```

```js
use threat_intel
```

```js
db.cve_intel.countDocuments()
```

---

### 2. Install Python Dependencies

```bash
cd agent-python
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

### 3. Run the API

```bash
cd agent-python
source .venv/bin/activate
PYTHONPATH=src uvicorn api.app:app --reload
```

Health check:

```bash
curl http://localhost:8000/health
```

Status overview:

```bash
curl http://localhost:8000/status/overview
```

---

### 4. Run the Frontend

```bash
cd agent-python/frontend
cp .env.example .env
npm ci
npm run dev
```

Set `VITE_API_BASE` to the FastAPI base URL. When the backend runs with `API_AUTH_MODE=api_key`, enter an API key in the console at runtime. Frontend environment variables are bundled into browser assets, so analyst/operator API keys must not be placed in Vite environment variables. A `viewer` or `analyst` key can read findings; `operator` or `admin` is required for the operational status view. The runtime key is kept in memory only and is sent as `x-api-key`.

Open:

```text
http://localhost:5173
```

Frontend validation:

```bash
npm test
npm run compile-check
npm run lint
npm run build
```

---

## Running the Analysis Worker

### Analyze CVEs

```bash
cd agent-python
source .venv/bin/activate
PYTHONPATH=src python src/main.py --source cve --run-once --batch-size 25000
```

### Analyze URLhaus

```bash
cd agent-python
source .venv/bin/activate
PYTHONPATH=src python src/main.py --source urlhaus --run-once --batch-size 28414
```

---

## Resetting Analysis State

### Reset CVE Analysis

```bash
mongosh mongodb://localhost:27017
```

```js
use threat_intel
```

```js
db.cve_intel.updateMany(
  {},
  {
    $unset: { analysis: "" },
    $set: { processed: false }
  }
)
```

### Reset URLhaus Analysis

```js
db.urlhaus_intel.updateMany(
  {},
  {
    $unset: { analysis: "" },
    $set: { processed: false }
  }
)
```

---

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | API and database health |
| `GET` | `/status/overview` | Source coverage and analysis status |
| `GET` | `/findings/top` | Prioritized findings |
| `GET` | `/findings/{source}/{entity_id}` | Detailed finding inspection |
| `GET` | `/evaluation/cve` | CVE evaluation snapshot |
| `GET` | `/evaluation/cve/diagnostics` | CVE diagnostic rows |
| `POST` | `/analyze/{source}` | Ad-hoc payload analysis |

Example:

```bash
curl "http://localhost:8000/findings/top?mode=needs_review&limit=10"
```

Supported finding modes:

```text
top
recent_high
highest_confidence
active_evidence
needs_review
recent
search
```

---

## Frontend Analyst Console

The frontend is designed as an analyst triage console, not just a static dashboard.

Main views:

```text
Findings
Evaluation
Status
Ad-hoc analysis
```

Finding triage modes:

```text
Top risk
Recent high risk
Needs review
Highest confidence
Active evidence
Recent analyzed
Search
```

The detail inspector shows:

```text
Risk score
Confidence
Primary score drivers
Advanced signals
Confidence breakdown
Evidence quality
NLP entities
Explanations
Recommendations
Full payload
```

The status view uses the existing `/status/overview` API permission and renders a role-specific 403 state when opened with a non-operator key.

---

## Model Diagnostics

Generate diagnostics from persisted MongoDB analysis results:

```bash
cd agent-python
source .venv/bin/activate
PYTHONPATH=src python src/evaluation/model_diagnostics.py --source cve --suffix full_cve
```

URLhaus:

```bash
PYTHONPATH=src python src/evaluation/model_diagnostics.py --source urlhaus --suffix full_urlhaus
```

Diagnostics include:

```text
risk level distribution
risk score buckets
confidence buckets
CVSS buckets
accepted / rejected cross-source evidence summaries
confidence breakdown averages
high-CVSS suppressed examples
low-CVSS boosted examples
```

---

## Testing

### Python Tests

```bash
cd agent-python
source .venv/bin/activate
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q -p no:ddtrace
```

### Go Tests

```bash
cd agent-go
go test ./...
```

### Frontend Build

```bash
cd agent-python/frontend
npm run build
```

---

## Current Limitations

This project is not production-ready yet.

Known limitations:

- No authentication or authorization layer
- MongoDB runs without access control in local development
- API error handling can be improved when MongoDB is unavailable
- No CISA KEV or EPSS integration yet
- No asset inventory or organization-specific exposure context
- No VirusTotal, passive DNS, ASN, or geolocation enrichment
- No campaign clustering for URLhaus IOCs
- Dread pipeline should be treated as experimental
- LLM support is optional and not required for deterministic operation

---

## Roadmap

High-value next steps:

1. **CISA KEV integration**
   - Add known-exploited vulnerability signal.
   - Improve CRITICAL risk decisions.

2. **EPSS integration**
   - Add exploitation probability signal.
   - Improve CVE prioritization quality.

3. **API robustness**
   - Return graceful degraded responses when MongoDB is unavailable.
   - Improve frontend degraded-state handling.

4. **Dashboard charts**
   - Risk distribution
   - Confidence distribution
   - Source coverage
   - URLhaus online/offline split
   - Top malware families

5. **URLhaus enrichment**
   - Domain reputation
   - ASN/geolocation
   - Passive DNS
   - Malware family clustering

6. **CI pipeline**
   - Python tests
   - Go tests
   - Frontend build

---

## Engineering Notes

The system intentionally separates:

```text
risk_score  = operational priority
confidence  = evidence quality
```

This allows the platform to represent cases like:

```text
HIGH risk + MEDIUM confidence
```

That means:

```text
The finding is technically important, but external corroboration or contextual evidence is limited.
```

This is more useful for analyst triage than forcing every high-severity item to have high confidence.

---

## Example Project Summary

> Multi-source threat intelligence platform that collects CVE and URLhaus intelligence, persists it in MongoDB, and runs an explainable risk analysis pipeline. The system separates risk priority from evidence confidence, performs NLP-assisted context extraction, applies evidence-quality gating for cross-source correlations, and exposes findings through an analyst-focused dashboard with risk, confidence, evidence, and model diagnostic views.
