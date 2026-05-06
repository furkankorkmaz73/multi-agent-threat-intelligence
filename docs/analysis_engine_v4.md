# Analysis Engine v4: Risk Model Recalibration

This revision separates **risk priority** from **evidence confidence**.

The previous CVE scoring model was too suppressive: high-CVSS vulnerabilities could fall into LOW risk when no accepted external evidence was found. That behavior mixed two different concepts:

- `risk_score`: how urgent or severe the finding is for prioritization
- `confidence`: how reliable the supporting evidence is

External evidence should increase risk and confidence when accepted, but missing external evidence should mainly reduce confidence. It should not erase high technical severity.

## New scoring structure

CVE risk scoring is now organized around explicit components:

```text
final_risk =
  severity_score
+ exploitability_score
+ active_threat_score
+ graph_bonus
+ recentness_bonus
- age_penalty
```

The persisted `feature_breakdown` now includes:

```text
severity_score
exploitability_score
active_threat_score
temporal_score
raw_age_penalty
age_penalty
final_score
```

## Severity anchor

CVSS is the primary severity anchor. The default CVSS multiplier was raised so severe CVEs are not pushed into LOW risk solely because no URLhaus or Dread evidence exists.

```text
BASE_CVSS_MULTIPLIER=0.72
```

## Age penalty

Age remains useful, but it is now capped more conservatively:

```text
AGE_PENALTY_90_PLUS=0.15
AGE_PENALTY_365_PLUS=0.45
AGE_PENALTY_1825_PLUS=0.75
AGE_PENALTY_3650_PLUS=1.0
```

If accepted external evidence exists, the effective age penalty is reduced. Old vulnerabilities with active threat evidence should remain actionable.

## Exploitability and context

The NLP context score was expanded to better represent exploitability and operational context:

- remote code execution
- authentication bypass
- privilege escalation
- initial access
- takeover
- credential theft
- exploit / zero-day / malware terminology
- exposed or security-critical product contexts such as VPNs, firewalls, gateways, and identity systems

NLP still remains capped; it cannot dominate the score without severity or accepted external evidence.

## Active threat evidence

Accepted URLhaus and Dread evidence contributes to `active_threat_score`. Rejected candidates remain diagnostic only and must not increase risk, graph bonus, or confidence.

## Confidence remains separate

Confidence continues to represent evidence reliability. A high-CVSS vulnerability without external corroboration may now be HIGH risk with medium confidence, which is more accurate than forcing it into LOW risk.

## Calibration tests

The following behaviors are now covered by tests:

- CVSS 9.8 with no external evidence is not LOW.
- Old CVSS 9.8 with no external evidence is not LOW.
- CVSS 9.8 with accepted URLhaus evidence has high confidence.
- Low-CVSS findings without evidence stay LOW.
- Rejected URLhaus candidates do not create graph/correlation risk.

## Diagnostics

`src/evaluation/model_diagnostics.py` generates before/after model reports from MongoDB analysis results:

```bash
cd agent-python
PYTHONPATH=src python src/evaluation/model_diagnostics.py --source cve --suffix before
PYTHONPATH=src python src/evaluation/model_diagnostics.py --source cve --suffix after
```

Outputs:

```text
report_outputs/model_diagnostics_cve_before.json
report_outputs/model_diagnostics_cve_before.md
report_outputs/model_diagnostics_cve_after.json
report_outputs/model_diagnostics_cve_after.md
```

Use this to compare distribution shifts after recalibration.

## v7 Confidence Calibration Note

The confidence score represents reliability of the risk assessment, not certainty about a record's administrative status. Invalid, rejected, or reserved CVE records are assigned low risk and low confidence because they do not contain actionable vulnerability evidence.

Additional guardrails were added for metadata-poor CVE records:

- CVSS missing or zero with no accepted external evidence is capped to low/medium confidence.
- Invalid or rejected CVE records no longer appear as high-confidence LOW findings.
- Accepted URLhaus/Dread evidence remains the main path to high confidence.
- High technical severity can still produce high risk, but without corroborating evidence confidence remains moderate.

This keeps the model distinction clear:

```text
risk_score = prioritization / severity-driven urgency
confidence = reliability of the evidence supporting that prioritization
```

## v8 URLhaus Evidence Quality Note

URLhaus correlation is now stricter than prose-like sources because IOC records are dominated by URL paths, file names, tags, and infrastructure artifacts. Generic URL/path overlap or vulnerability-type overlap is not enough to promote a retrieved candidate into accepted evidence.

Accepted URLhaus evidence should have at least one strong corroborating signal, such as:

- exact CVE identifier reference
- meaningful non-generic shared term
- high-signal malware or exploit term overlap
- domain or threat-term entity alignment
- semantic support plus meaningful shared context

The following patterns are rejected or kept diagnostic-only:

- `entity_alignment` with no meaningful shared terms
- generic URL/path tokens such as `index.php`, `api`, `token`, `raw`, `refs`, `zip`, or `github`
- offline IOC artifacts that only overlap through broad vulnerability/impact labels such as DoS or crash

This prevents weak URLhaus candidates from inflating `related_urlhaus_count`, confidence, or active threat evidence.

## v9 Confidence Breakdown Note

Confidence is now stored with a component-level breakdown so analysts can see why a risk assessment is more or less reliable. The top-level `confidence` value remains a single normalized number, but `confidence_breakdown` explains the contribution of each evidence family.

Main components:

- `base_confidence`: stable floor for analyzable CVE records
- `metadata_confidence`: CVSS availability/version, description length, publication date, and severity metadata quality
- `entity_confidence`: NLP/entity extraction quality, including products, vulnerability types, impacts, threat terms, CVE IDs, keywords, and optional LLM fields
- `external_evidence_confidence`: accepted URLhaus/Dread evidence, exact CVE hits, high-signal malware/exploit terms, meaningful shared terms, and semantic signal
- `correlation_confidence`: graph/correlation support after evidence has passed the acceptance gate
- `freshness_confidence`: small boost for recent CVE records
- `penalties`: missing CVSS, weak text, no accepted external evidence, stale records without activity, and weak/generic entity extraction

The intended behavior is:

```text
High CVSS + good intrinsic context + no external evidence
→ high/medium risk, medium confidence

High CVSS + accepted high-quality external evidence
→ high risk, high confidence

Missing CVSS + no accepted external evidence
→ low confidence

Rejected or invalid CVE record
→ low risk, low confidence
```

This makes confidence auditable without changing the calibrated v6/v8 risk score distribution.

### v9.1 Generic URLhaus term filtering

The confidence breakdown exposed that URLhaus correlations based only on broad platform/CMS terms such as `windows` or `wordpress` could still be treated as accepted evidence. v9.1 treats these low-specificity terms as correlation noise for URLhaus matching. Entity-alignment-only URLhaus evidence is also down-weighted in confidence unless it is supported by exact CVE references, high-signal malware/exploit overlap, or stronger shared context.
