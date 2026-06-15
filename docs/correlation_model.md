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

Dread records are stricter because they are optional experimental intelligence. A standalone non-exact Dread mention is not accepted as verified evidence, even when it contains high-signal exploit terminology. Exact CVE references in Dread can be accepted, but their confidence is explicitly capped. Non-exact Dread support is routed to `manual_review` unless stronger corroborating evidence is available elsewhere in the scenario.

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
evidence_source
evidence_reliability
dread_evidence_present
dread_only_evidence
corroborated_dread_evidence
manual_review_reason
confidence_cap_reason
```

LLM output must not be treated as verified evidence. LLM-derived fields may support explanation or context, but accepted correlation evidence must come from deterministic gates and explicit provenance.
