# Provider Governance Scenario

Checked-in source fixtures for the advisory `provider_governance_v1` completeness path.

Scenario:

- system: `hiring-assistant`
- model: `hiring-model-v3`
- version: `2026.03`
- role: `provider`
- workflow: `provider_governance`

These files are source-first structured evidence payloads for a passing provider-side
governance bundle. Tests mutate the passing fixture in memory for warn/fail cases rather
than checking in separate broken variants.
