# Release Notes Templates — Chatbot-Focus Transition

Use the template matching the current transition phase.

---

## Phase 1 Template (Deprecation Introduced)

**Release:** `vX.Y.Z`  
**Date:** `YYYY-MM-DD`

### Highlights
- Chatbot-first default surface remains the primary stable path.
- Non-chat default-surface APIs now emit runtime deprecation warnings.

### Deprecated
- Default non-chat imports on:
  - Python: `proofsdk`
  - TypeScript: `@proof-layer/sdk`

### Migration action
- Move non-chat imports to:
  - Python: `proofsdk.advanced`
  - TypeScript: `@proof-layer/sdk/advanced`

### References
- Migration note: `docs/migration/chatbot-focus-v1.md`
- Compatibility matrix: `README.md`

---

## Phase 2 Template (Soft Migration Window)

**Release:** `vX.Y.Z`  
**Date:** `YYYY-MM-DD`

### Highlights
- Deprecated default non-chat APIs remain functional for compatibility.
- Runtime warnings remain active and unchanged.

### Reminder
- This release is inside the soft migration window. Teams should complete advanced-import migration before the first v2 release.

### Migration checklist
- [ ] Replace Python non-chat imports with `proofsdk.advanced`.
- [ ] Replace TypeScript non-chat imports with `@proof-layer/sdk/advanced`.
- [ ] Validate integration tests under warning-free advanced imports.

### References
- Migration note: `docs/migration/chatbot-focus-v1.md`
- Changelog: `CHANGELOG.md`

---

## Phase 3 Template (Removal / Major Release)

**Release:** `v2.0.0`  
**Date:** `YYYY-MM-DD`

### Breaking changes
- Removed deprecated non-chat APIs from default entrypoints.

### Required action
- Import non-chat APIs exclusively from advanced entrypoints:
  - Python: `proofsdk.advanced`
  - TypeScript: `@proof-layer/sdk/advanced`

### Upgrade notes
- Chatbot-first APIs on default entrypoints remain supported.
- Any runtime warning previously seen in v1 should now be treated as a hard migration blocker.

### References
- Migration note: `docs/migration/chatbot-focus-v1.md`
- Changelog: `CHANGELOG.md`
