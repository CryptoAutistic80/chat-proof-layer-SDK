# Post-Market Monitoring Scenario

Checked-in source fixtures for the advisory `post_market_monitoring_v1` completeness path.

Scenario:

- system: `claims-assistant`
- model: `claims-model-v2`
- version: `2026.03`
- role: `provider`
- workflow: `post_market_monitoring`

These files are source-first structured evidence payloads for a passing monitoring and
incident-response bundle. Tests mutate the passing fixture in memory for warn/fail cases
rather than checking in separate broken variants.
