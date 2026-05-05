# Analysis Engine v3: Evidence-Gated Scoring

This revision fixes the main semantic issue found during live pipeline testing: weak retrieved candidates must not be treated as accepted cross-source evidence.

## Key changes

- Correlation scoring now separates retrieved candidates from accepted matches.
- `related_urlhaus_count` and `related_dread_count` now count accepted evidence only.
- Rejected candidates remain visible through match statistics, but they no longer create graph edges or score contributions.
- Graph cross-source edges are built only from accepted evidence summaries.
- Confidence is recalibrated around evidence quality rather than raw candidate volume.
- Generic keywords and stopwords are filtered more aggressively to reduce noisy CVE/IOC joins.

## Expected behavior

When URLhaus candidates are retrieved but rejected:

- `candidate_urlhaus_count > 0`
- `related_urlhaus_count == 0`
- `urlhaus_correlation_bonus == 0`
- no `correlated_urlhaus` graph edges are produced
- graph bonus remains zero unless accepted cross-source evidence exists
- confidence is lower because no external corroboration was accepted

## Rationale

Candidate retrieval is intentionally broad. It should support evidence discovery, not automatically raise risk. Risk and confidence should only increase when a correlation gate accepts the candidate based on exact CVE evidence, entity alignment, high-signal overlap, strong lexical support, or semantic/temporal support.
