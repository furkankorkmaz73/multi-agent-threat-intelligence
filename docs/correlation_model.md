# Correlation Model

CVE-IOC correlation is evidence-gated. Retrieval candidates are not automatically accepted evidence. Each candidate is classified as:

| Decision | Meaning |
| --- | --- |
| `accepted` | strong enough to affect risk, confidence, and graph context |
| `manual_review` | visible diagnostically, but not used as verified evidence |
| `rejected` | visible diagnostically, but excluded from scoring |

## Evidence Gates

Exact CVE references are the strongest accepted signal. Generic keyword overlap is not enough for acceptance.

URLhaus records are IOC artifacts, so they require stronger support than ordinary text overlap. Accepted URLhaus evidence normally needs exact CVE reference, strong entity alignment with meaningful support, high-signal exploit/malware terms, or semantic plus temporal support.

Dread records are stricter because they are optional experimental intelligence. Dread candidates require exact CVE references or stronger combined support from high-signal terms, entity alignment, temporal proximity, and semantic/lexical evidence.

Rejected and manual-review candidates do not increase:

- `risk_score`
- graph bonus
- confidence
- accepted evidence counts

## Provenance

Every correlation decision carries provenance and evidence types. Thesis-ready decision rows include:

```text
source_identifier
target_identifier
source
lexical_score
semantic_score
temporal_score
entity_score
shared_term_count
exact_cve
high_signal_term_hits
decision
primary_reason
final_confidence
```

LLM output must not be treated as verified evidence. LLM-derived fields may support explanation or context, but accepted correlation evidence must come from deterministic gates and explicit provenance.
