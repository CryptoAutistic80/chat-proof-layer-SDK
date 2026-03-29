# Evidence Bundle v1 Specification

## Scope

This document defines the normative shape and processing rules for `schemas/evidence-bundle-v1.schema.json`.

## Required Fields

A valid bundle MUST include the following top-level fields:

- `schema_version`: semantic version string in the `1.x.y` line.
- `bundle_id`: globally unique bundle identifier.
- `session`: session metadata.
- `turns`: ordered conversational turns.
- `integrity`: canonicalization and hash commitments.
- `signature`: signature metadata and detached signature bytes.
- `provenance`: producer/capture/source traceability metadata.

### Session metadata (required)

`session` MUST contain:

- `session_id`
- `started_at` (RFC3339 timestamp)
- `ended_at` (RFC3339 timestamp)
- `participants[]` (each with required `id` and `role`)
- `context` (required `environment` and `region`)

### Turn ordering + hash chain (required)

Each entry in `turns[]` MUST contain:

- `turn_index` (0-based index)
- `role`
- `content_hash`
- `turn_hash`

`prev_turn_hash` is optional but RECOMMENDED. If present:

- Turn 0 SHOULD set `prev_turn_hash = null`.
- Turn *n > 0* SHOULD set `prev_turn_hash` to turn *n-1* `turn_hash`.

Verifiers MUST treat array order as canonical turn order. Producers MUST NOT reorder turns after hash/signature generation.

### Integrity fields (required)

`integrity` MUST contain:

- `canonicalization`
  - `spec` = `RFC8785-JCS`
  - `normalization` = `UTF-8`
  - `version` (producer-declared canonicalization profile/revision)
- `hash_algorithm` = `SHA-256`
- `bundle_hash` (`sha256:<hex>`)
- `turn_order_hash` (`sha256:<hex>`)

### Signature metadata (required)

`signature` MUST contain:

- `algorithm` (`Ed25519`, `ES256`, or `RS256`)
- `key_id` (stable verifier-resolvable key identifier)
- `signed_at` (RFC3339 signature timestamp)
- `signature_value` (detached signature payload)

Timestamp fields are split by concern:

- Session clock bounds: `session.started_at`, `session.ended_at`
- Capture clock: `provenance.captured_at`
- Signing clock: `signature.signed_at`

### Provenance (required)

`provenance` MUST contain:

- `producer` (`name`, `version`)
- `captured_at`
- `source_refs[]`, each with:
  - `type`
  - `uri`
  - `digest`

## Canonicalization Rules for Deterministic Hashing

For deterministic hashing, producers and verifiers MUST execute the same pipeline:

1. Parse JSON as UTF-8.
2. Apply RFC8785 JSON Canonicalization Scheme (JCS):
   - lexical object key ordering,
   - no insignificant whitespace,
   - normalized numeric/string rendering per RFC8785.
3. Serialize canonical JSON as UTF-8 bytes.
4. Compute SHA-256 digest and encode as `sha256:<lowercase-hex>`.

`turn_order_hash` MUST commit to the ordered list of `turn_hash` values in the exact `turns[]` array order.

## Backward/Forward Compatibility (`schema_version` handling)

`schema_version` is semantic versioning with compatibility policy:

- **Patch (`1.x.y`)**: backward-compatible clarifications/fixes. Verifiers SHOULD accept same-major patch upgrades.
- **Minor (`1.x`)**: backward-compatible additions, typically via optional fields or `extensions` namespace. Verifiers SHOULD ignore unknown fields under `extensions`.
- **Major (`2.x`)**: potentially breaking changes. Verifiers MUST reject unknown major versions unless explicitly configured.

Producer requirements:

- MUST emit the most specific known version.
- MUST preserve existing required semantics for all `1.x.y` variants.

Verifier requirements:

- MUST enforce major-version guardrails.
- SHOULD parse known required fields first, then process optional/extension data.

## Normative Example

A normative example bundle that validates against the schema is provided at:

- `examples/bundles/evidence-bundle-v1.example.json`
