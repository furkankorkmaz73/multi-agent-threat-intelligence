# Demo Hardening Plan

This iteration keeps changes incremental and demo-focused. It improves analyst-console usability, data-loading behavior, collector ingestion metrics, analysis benchmarking, and bounded API query work without changing production risk scoring semantics.

## Guardrails

- Frontend code displays backend-provided risk, confidence, evidence, and recommendations; it does not calculate risk scores.
- React/browser code does not call NVD, URLhaus, Dread, MongoDB, or external threat feeds directly.
- Dread crawler behavior and worker concurrency are unchanged.
- Go collector upserts must preserve Python-owned analysis fields such as `analysis`, `analysis_history`, `job_lifecycle`, `job_lifecycle_history`, `analyzed_at`, and `processed`.
- API and worker changes should stay bounded, observable, and testable.

## Demo Scope

- Compact analyst-console UI with clear loading, empty, and error states.
- Safer frontend request behavior with lazy loading where practical.
- Chunked collector writes with fetch/save timing logs.
- Bounded Python analysis benchmark metrics.
- Local API query improvements that avoid unbounded cursor materialization.

## Out of Scope

- Risk score formula or weight changes.
- New EPSS or KEV ingestion.
- Frontend feed ingestion or direct database access.
- Worker parallelism or a new queue lifecycle model.
- Large migrations or new frontend frameworks.
