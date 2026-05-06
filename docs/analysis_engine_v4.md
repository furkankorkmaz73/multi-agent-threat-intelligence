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
