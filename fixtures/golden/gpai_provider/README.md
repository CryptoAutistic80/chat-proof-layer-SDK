# GPAI Provider Scenario

Checked-in source fixtures for the advisory GPAI provider completeness acceptance path.

Scenario:

- system: `foundation-model-alpha`
- model: `foundation-model-alpha-v5`
- version: `2026.03`
- role: `provider`
- gpai status: `provider`

These files are source-first structured evidence payloads for a passing `gpai_provider_v1`
completeness bundle. Tests mutate the passing fixture in memory for warn/fail cases rather
than checking in separate broken variants.
