# Proof Bundle Schema

## Status

This document is the normative bundle-format reference for the current implementation.
If code and this document diverge, update both together.

Machine-readable schemas:

- `schemas/evidence_bundle.schema.json`
- `schemas/redacted_bundle.schema.json`
- `docs/proof_bundle.schema.json` is a compatibility wrapper that points at `schemas/evidence_bundle.schema.json`

## Top-Level Bundle Shape

Current bundles are `bundle_version: "1.0"` and contain:

- `bundle_version`
- `bundle_id`
- `created_at`
- `actor`
- `subject`
- `context`
- `items`
- `artefacts`
- `policy`
- `integrity`
- optional `timestamp`
- optional `receipt`

`timestamp` and `receipt` are intentionally outside the signed header so they can be attached after initial sealing.

## Integrity Fields

`integrity` contains:

- `canonicalization = "RFC8785-JCS"`
- `hash = "SHA-256"`
- `header_digest`
- `bundle_root_algorithm`
- `bundle_root`
- `signature`

`signature.value` is an Ed25519 JWS compact string over the UTF-8 bytes of `integrity.bundle_root`.

## Header Projection

`proof_bundle.canonical.json` always stores the exact canonical UTF-8 bytes used to derive `integrity.header_digest`.

### Current Default Projection (`pl-merkle-sha256-v4`)

New bundles use the following canonical header projection:

- `bundle_version`
- `bundle_id`
- `created_at`
- `actor`
- `subject`
- `context`
- `policy`
- `item_count`
- `artefact_count`

This keeps the signed header stable while letting individual evidence items and artefact metadata become separate Merkle leaves for selective disclosure.

### Legacy Projection (`pl-merkle-sha256-v1`)

Legacy bundles are still accepted during verification.
Their canonical header projection contains:

- `bundle_version`
- `bundle_id`
- `created_at`
- `actor`
- `subject`
- `context`
- `items`
- `artefacts`
- `policy`

## Merkle Root Algorithms

### Legacy Verification (`pl-merkle-sha256-v1`)

Legacy bundles use:

`[header_digest, artefact_digest_1, artefact_digest_2, ...]`

where each artefact leaf is the digest of the artefact bytes themselves.

### Current Default (`pl-merkle-sha256-v4`)

New bundles use:

`[header_digest, item_digest_1, item_digest_2, ..., artefact_meta_digest_1, artefact_meta_digest_2, ...]`

where:

- `item_digest_n = sha256(RFC8785({"item_type": item.type, "container_kinds": {...}, "path_digests": {...}}))`
- `container_kinds[path]` records whether an `item.data` JSON Pointer path is an object or array container
- `path_digests[path] = sha256(RFC8785(item.data[path]))` for each scalar / null leaf path
- `artefact_meta_digest_n = sha256(RFC8785(artefact_ref_json))`

Artefact content bytes are still verified separately against each artefact record's `digest` field before trust decisions.

### Compatibility Default (`pl-merkle-sha256-v3`)

Previously issued v3 bundles use the same leaf ordering, but each item leaf commits only the top-level item-data fields:

- `item_digest_n = sha256(RFC8785({"item_type": item.type, "field_digests": {...}}))`
- `field_digests[field_name] = sha256(RFC8785(item.data[field_name]))`

### Compatibility Default (`pl-merkle-sha256-v2`)

Previously issued v2 bundles use the same leaf ordering, but each item leaf is the digest of the full canonicalized item JSON:

- `item_digest_n = sha256(RFC8785(item_json))`

For both algorithms:

1. Parse each `sha256:<hex>` input digest into raw 32 bytes.
2. Leaf hash is `H(0x00 || digest_bytes)`.
3. Parent hash is `H(0x01 || left_hash || right_hash)`.
4. Duplicate the last node when a level has odd width.
5. Encode the final root as `sha256:<hex(root_hash)>`.

The proof format still uses `algorithm = "pl-merkle-sha256-v1"` because the Merkle tree construction itself is unchanged; v1 vs v2 vs v3 vs v4 only changes which digests become leaves.

## Verification Procedure

Implementations must:

1. Parse the package and validate required files.
2. Parse the bundle and validate required fields.
3. Rebuild the canonical header bytes for the bundle's `bundle_root_algorithm`.
4. Recompute `header_digest` and compare.
5. Verify artefact bytes against each recorded artefact digest.
6. Recompute `bundle_root` using the bundle's leaf-layout algorithm and compare.
7. Verify the JWS signature over UTF-8 `integrity.bundle_root` bytes.
8. If requested, verify `timestamp` against UTF-8 `integrity.bundle_root` bytes.
9. If requested, verify `receipt` against UTF-8 `integrity.bundle_root` bytes.

Optional timestamp/receipt trust policy can additionally enforce:

- trust-anchor chaining
- RFC 3161 policy OID matching
- CRL checks
- live OCSP checks
- qualified TSA signer allowlists
- timestamp assurance profiles
- Rekor SET / `logID` verification
- SCITT service-signature / `serviceId` verification

## Bundle Package

Standard full packages are gzip-compressed JSON archives with:

- top-level `format = "pl-bundle-pkg-v1"`
- top-level `files[]` entries containing `name` and `data_base64`

Required members:

- `proof_bundle.json`
- `proof_bundle.canonical.json`
- `proof_bundle.sig`
- `manifest.json`
- `artefacts/<name>` for each artefact

`manifest.json` contains per-file digests and sizes for package-level integrity checks.

## Redacted Bundle Shape

Selective disclosure is currently defined for `pl-merkle-sha256-v2`, `pl-merkle-sha256-v3`, and `pl-merkle-sha256-v4` bundles.

`schemas/redacted_bundle.schema.json` describes the redacted bundle object carried inside a disclosure package. It contains:

- original bundle metadata and `integrity`
- optional `timestamp`
- optional `receipt`
- `total_items`
- `total_artefacts`
- `header_proof`
- `disclosed_items[]`
- `disclosed_artefacts[]`

Each disclosed entry carries either the original item object or a `field_redacted_item` projection plus an inclusion proof.

Leaf indices for v2/v3/v4 disclosure are fixed:

- header leaf: `0`
- item leaf `n`: `1 + n`
- artefact leaf `n`: `1 + total_items + n`

## Disclosure Package

Redacted disclosure packages are gzip-compressed JSON archives with:

- top-level `format = "pl-bundle-disclosure-pkg-v1"`
- `redacted_bundle.json`
- `manifest.json`
- optional `artefacts/<name>` members for any disclosed artefact bytes

Current CLI support is:

- `proofctl disclose --items ... [--artefacts ...] [--redact-field <item_index>:<field-or-json-pointer>]` for item-level disclosure, top-level field redaction on v3 bundles, nested JSON-pointer path redaction on v4 bundles, and optional artefact-byte carry-through
- `proofctl verify` auto-detects and verifies both full packages and disclosure packages

Vault-side redacted pack assembly is implemented through `/v1/packs` with `bundle_format = "disclosure"` and optional named `disclosure_policy` selection.
Those disclosure policies can now also supply `redacted_fields_by_item_type`, using either top-level field names or JSON-pointer paths, which becomes a per-item field/path redaction map in preview responses and pack manifests for v3/v4 bundles.
