# Analysis Engine v2

This update focuses on the analysis layer, which is the core value of the project.

## Why the old version needed revision

The previous implementation worked, but it was too heuristic-heavy:

- Keyword extraction was mostly token filtering.
- Correlation could add score from weak matches.
- Semantic similarity existed, but it was not tied tightly enough to security entities.
- The score was harder to explain because lexical, semantic, graph and LLM signals were mixed together.

## New design

The new analysis flow is:

```text
CVE / URLhaus / Dread record
        ↓
Lightweight NLP feature extraction
        ↓
Entity-aware retrieval terms
        ↓
Cross-source evidence gating
        ↓
Transparent scoring components
        ↓
Graph/context refinement
        ↓
Final risk score + explanation + evidence breakdown
```

## NLP extraction

The new `analysis.nlp_features` module extracts:

- CVE identifiers
- CWE identifiers
- affected products
- versions
- vulnerability types
- attacker impacts
- threat terms
- URLs / domains
- salient phrases
- normalized keywords

This keeps the system explainable while giving it an NLP layer stronger than raw keyword matching.

## Correlation logic

A candidate match must now pass at least one evidence gate:

- exact CVE match
- entity alignment
- high-signal exploit/malware/access terminology
- lexical overlap
- semantic + temporal support

Accepted matches are scored with lexical, semantic, temporal and entity components. Diminishing returns are applied so many weak candidates cannot overpower a smaller number of strong matches.

## Scoring changes

CVE scoring now separates:

- `base_cvss_component`
- `nlp_context_bonus`
- `urlhaus_correlation_bonus`
- `dread_correlation_bonus`
- `cross_source_bonus`
- `graph_bonus`
- `age_penalty`
- `final_score`

API responses also include `evidence.nlp_entities` for dashboard rendering and debugging.

## Current validation

Python tests:

```text
52 passed
```

The new tests cover NLP feature extraction, entity overlap, hybrid semantic scoring and existing risk/correlation behavior.
