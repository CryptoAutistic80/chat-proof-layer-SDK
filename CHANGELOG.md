# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project follows Semantic Versioning.

## [Unreleased]

### Changed
- Introduced a chatbot-focus v1 migration note and compatibility matrix clarifying default, advanced, and deprecated API surfaces.

### Deprecated
- Marked non-chat APIs on default Python (`proofsdk`) and TypeScript (`@proof-layer/sdk`) entrypoints as deprecated in favor of advanced imports.
- Added runtime deprecation warnings with explicit advanced import alternatives for default-surface non-chat APIs.

### Documentation
- Added migration guidance at `docs/migration/chatbot-focus-v1.md`.
- Added transition-phase release notes templates at `docs/release/release-notes-template.md`.

## Transition phases (chatbot-focus v1)

### Phase 1: Introduce warnings (v1.3.x)
- Runtime warnings active on default non-chat imports and methods.
- Advanced import paths documented as the primary non-chat surface.

### Phase 2: Soft migration window (v1.4.x - v1.6.x)
- Deprecated default APIs still function, warnings remain active.
- Migration reminders appear in each release note.

### Phase 3: Removal target (v2.0.0+)
- Planned removal of deprecated default non-chat APIs.
- Advanced surfaces continue as supported non-chat path.
