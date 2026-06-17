# Correlation Model

CVE-IOC correlation is evidence-gated. Retrieval candidates are not automatically accepted evidence. Each candidate is classified as:

| Decision | Meaning |
| --- | --- |
| `accepted` | strong enough to affect risk, confidence, and graph context |
| `manual_review` | visible diagnostically, but not used as verified evidence |
| `rejected` | signal-bearing candidate with insufficient support, excluded from scoring |

Raw retrieval candidates are not evidence. Candidates with no usable signal are counted as `ignored_low_signal` rather than `rejected`. This keeps URLhaus candidate-volume diagnostics separate from evidence-gate failures.

URLhaus retrieval also applies a conservative prefilter before querying the database. Generic vulnerability words such as `remote`, `code`, `execution`, `service`, and broad protocol/platform terms are not used as standalone URLhaus lookup terms. The provider prefers explicit CVE identifiers, meaningful product/vendor tokens, and known exploit or malware terms. If no strong URLhaus retrieval term remains, the provider returns no candidates instead of issuing a broad query. `ignored_low_signal_count` is therefore a downstream safety net, not the primary retrieval strategy.

## Evidence Gates

Exact CVE references are the strongest accepted signal. Generic keyword overlap is not enough for acceptance.

URLhaus records are IOC artifacts, so they require stronger support than ordinary text overlap. Accepted URLhaus evidence normally needs exact CVE reference, strong entity alignment with meaningful support, high-signal exploit/malware terms with enough shared terms and temporal support, or semantic plus temporal support. URLhaus match stats include accepted, manual-review, rejected, and ignored candidate counts plus reason-code distributions so noisy IOC retrievals can be audited without treating every retrieval hit as evidence.

Dread records are stricter because they are optional experimental intelligence. Dread candidates are weak chatter / early-warning indicators only in CVE scoring. A Dread-only mention, including an exact CVE mention, is routed to `manual_review` or `rejected` and is not accepted as verified exploitation evidence.

False-positive controls are deterministic. Keyword-only URLhaus candidates, stale external records outside the temporal support window, unrelated product/vendor overlap, and IOC mentions without vulnerability context are preserved diagnostically but are not accepted evidence.

Rejected and manual-review candidates do not increase:

- `risk_score`
- graph bonus
- confidence
- accepted evidence counts

Ignored low-signal candidates also do not increase confidence penalties, graph support, `correlation_signal`, or URLhaus source contributions. They are retained only for retrieval-quality analytics. Manual-review and rejected Dread candidates remain visible in diagnostics but do not increase risk, graph support, accepted evidence counts, or `patch_now`-style recommendations.

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
evidence_gate_passed
evidence_gate_reason
rejection_reason
accepted_evidence_count
rejected_evidence_count
manual_review_evidence_count
false_positive_control
```

LLM output must not be treated as verified evidence. LLM-derived fields may support explanation or context, but accepted correlation evidence must come from deterministic gates and explicit provenance.
