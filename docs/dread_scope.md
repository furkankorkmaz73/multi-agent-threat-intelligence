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

## Bounded Evidence Treatment

Dread is not treated as ground truth. The reliability order used by the deterministic model is:

```text
CISA KEV / exact CVE match / URLhaus IOC > EPSS probability > structured correlation > Dread mention > keyword-only match
```

Dread-only evidence routes to manual review or weak diagnostic state. It is capped to low confidence and cannot create CRITICAL risk, `patch_now`, or confirmed-exploitation claims by itself. Rejected or manual-review Dread candidates remain diagnostic and do not increase risk, graph bonus, or confidence.

Stronger evidence such as CISA KEV, EPSS, or accepted URLhaus IOC evidence should carry the operational priority. Dread can explain early-warning chatter around that context, but the deterministic CVE scorer does not count Dread candidates as accepted evidence.

## Reproducibility

The thesis workflow uses deterministic fixtures and local benchmark exports. The command below does not perform live Dread crawling:

```bash
make thesis-artifacts
```
