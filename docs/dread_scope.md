# Dread Scope

Dread is optional experimental intelligence in this project. It is not the core contribution and is disabled by default.

Default configuration:

```text
DREAD_ENABLED=false
DREAD_ONION_URL=
DREAD_REQUEST_TIMEOUT_SECONDS=90
```

No onion URL is hardcoded. Live Dread crawling is not required for tests, demos, benchmarks, or thesis artifact generation.

## Safety And Ethics

Dread content can be illegal, harmful, inaccurate, fabricated, or operationally sensitive. Collection may create legal, ethical, and safety obligations depending on jurisdiction and institutional policy. This project treats Dread as optional research input and does not require live dark-web access.

## Data Quality

Dread posts are difficult to reproduce and verify. Posts can be deleted, edited, misleading, or intentionally deceptive. Attribution is weak. A post mentioning a product or keyword is not verified exploitation evidence.

## Scoring Treatment

Dread-only evidence normally produces low or medium confidence unless corroborated by stronger evidence such as exact CVE references, URLhaus IOC evidence, EPSS likelihood, or CISA KEV listing. Rejected or manual-review Dread candidates remain diagnostic and do not increase risk, graph bonus, or confidence.

## Reproducibility

The thesis workflow uses deterministic fixtures and local benchmark exports. The command below does not perform live Dread crawling:

```bash
make thesis-artifacts
```
