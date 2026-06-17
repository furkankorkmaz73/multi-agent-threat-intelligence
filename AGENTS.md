# AGENTS.md

## Project role

This repository is a threat intelligence analysis prototype with:
- Go-based data collectors under `agent-go/`
- Python analysis, API, worker, and evaluation code under `agent-python/src/`
- React frontend under `agent-python/frontend/`
- Documentation under `docs/`

## Engineering rules

Do not start large rewrites. Prefer small, reviewable patches.

Before editing code:
1. Identify the affected layer:
   - Go collector / CLI
   - Python API/backend
   - Python analysis/worker
   - React frontend
   - docs/evaluation
2. Inspect existing nearby patterns.
3. Reuse existing naming and module structure.
4. State in-scope and out-of-scope changes.

## Hard boundaries

Do not:
- change risk scoring semantics unless explicitly requested
- compute risk scores in the frontend
- call external threat feeds directly from the frontend
- add worker concurrency without lease/heartbeat/stale-job recovery
- add Dread live crawling behavior for demo improvements
- introduce large migrations without tests
- move API calls outside `frontend/src/api.js`
- bypass existing auth/role checks
- store secrets in code or examples

## Frontend rules

- Keep API calls centralized in `agent-python/frontend/src/api.js`.
- Components should format and display backend data, not recalculate analysis results.
- Prefer compact, analyst-console UI.
- Add loading, error, and empty states for new UI paths.

## Backend/API rules

- Keep long-running operations out of request handlers unless they are explicitly bounded.
- Prefer job/status patterns for operational actions.
- Do not introduce unbounded collection scans.
- Add limits, projections, and pagination where applicable.

## Collector rules

- Use chunked bulk writes for large ingestion.
- Preserve Python-owned analysis fields during upserts.
- Log fetch/save durations and counts.
- Respect source rate limits and retry only transient errors.

## Test expectations

After changes, run the relevant tests:
- Python: `cd agent-python && pytest`
- Frontend: `cd agent-python/frontend && npm test -- --run` if dependencies exist
- Go: `cd agent-go && go test ./...` if the local Go version supports the module

If a test cannot be run due to local tooling, state why.