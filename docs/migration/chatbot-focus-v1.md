# Chatbot Focus v1 Migration Note

**Effective date:** March 30, 2026.

This note describes the SDK surface transition to a chatbot-first default API while retaining advanced coverage for lifecycle/compliance workflows.

## 1) What moved to advanced

The following non-chat APIs are now considered **advanced** and should be imported from:

- **Python:** `proofsdk.advanced`
- **TypeScript:** `@proof-layer/sdk/advanced`

Moved categories:

- Non-chat evidence builders (risk, governance, conformity, post-market monitoring, incident, FRIA, training, etc.).
- Non-chat tooling helpers (for example, tool-call capture helpers).
- Native/local helper APIs used for low-level bundle operations and completeness-focused workflows.
- Lifecycle/compliance convenience capture methods when used for non-chat workflows.

Default-surface access remains temporarily compatible, but now emits runtime deprecation warnings with explicit advanced import alternatives.

## 2) What remains supported on default surfaces

The default SDK entrypoints remain stable and recommended for chatbot workflows:

- Chat session capture and sealing (`start_chat_session` / `startChatSession`, `capture` for LLM interaction).
- Chat-specific wrappers and integrations.
- Bundle verification and transcript-proof workflows used by chatbot-first onboarding.

This is the **chatbot-first stable** surface and remains the recommended path for new integrations.

## 3) Planned removal timeline

The timeline below reflects the transition phases announced on **March 30, 2026**:

1. **Phase 1 — Deprecation introduced (v1.3.x, starting March 30, 2026)**  
   - Runtime warnings added on default non-chat APIs.  
   - Advanced import alternatives documented.

2. **Phase 2 — Soft migration window (v1.4.x through v1.6.x, April 2026 to September 2026)**  
   - Default non-chat APIs continue working with warnings.  
   - Docs, changelog, and release notes repeatedly point to advanced imports.

3. **Phase 3 — Default-surface removal target (first major after v1, target v2.0.0 on or after October 1, 2026)**  
   - Deprecated non-chat APIs removed from default entrypoints.  
   - Advanced entrypoints remain supported.

> Dates above are planning targets and may be adjusted by release governance. Any timeline change will be published in `CHANGELOG.md` and release notes.

## 4) Quick migration examples

### Python

```python
# Old (deprecated on default surface)
from proofsdk import create_risk_assessment_request

# New
from proofsdk.advanced import create_risk_assessment_request
```

### TypeScript

```ts
// Old (deprecated on default surface)
import { createRiskAssessmentRequest } from "@proof-layer/sdk";

// New
import { createRiskAssessmentRequest } from "@proof-layer/sdk/advanced";
```
