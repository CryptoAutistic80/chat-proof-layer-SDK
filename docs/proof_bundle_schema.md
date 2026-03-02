# Proof Bundle Schema (PoC v0.1)

## Status

This document is the normative schema reference for PoC bundle creation and verification.
If implementation behavior diverges from this document, update code and this spec together.
Machine-readable validation schema is in `docs/proof_bundle.schema.json`.

## Conventions

- MUST/SHOULD/MAY are used as RFC 2119 normative terms.
- JSON canonicalization uses RFC 8785.
- Hash algorithm is SHA-256 only in PoC.

## Top-Level Bundle Shape

```json
{
  "bundle_version": "0.1",
  "bundle_id": "01JMBQ3Q7V0T9E0XH1MG6G4X3E",
  "created_at": "2026-03-01T14:12:09Z",
  "actor": {},
  "subject": {},
  "model": {},
  "inputs": {},
  "outputs": {},
  "trace": {},
  "artefacts": [],
  "policy": {},
  "integrity": {},
  "timestamp": null,
  "receipt": null
}
```

## Canonical Header Projection

The canonical header projection is the exact object below (field names and values), derived from the bundle before signing:

- `bundle_version`
- `bundle_id`
- `created_at`
- `actor`
- `subject`
- `model`
- `inputs`
- `outputs`
- `trace`
- `artefacts`
- `policy`

Excluded from canonical header projection:

- `integrity`
- `timestamp`
- `receipt`

Rationale: this avoids circular dependencies when deriving integrity fields.

## Integrity Field Semantics

`integrity` MUST include:

- `canonicalization`: fixed string `RFC8785-JCS`
- `hash`: fixed string `SHA-256`
- `header_digest`: SHA-256 of canonical header bytes, format `sha256:<64-lower-hex>`
- `bundle_root_algorithm`: fixed string `pl-merkle-sha256-v1`
- `bundle_root`: Merkle root digest string, format `sha256:<64-lower-hex>`
- `signature` object:
  - `format`: fixed string `JWS`
  - `alg`: fixed string `EdDSA`
  - `kid`: issuer key identifier
  - `value`: JWS compact string

## Merkle Root Algorithm (`pl-merkle-sha256-v1`)

Input digest order MUST be:

`[header_digest, artefact_digest_1, artefact_digest_2, ...]`

Each input digest is parsed into raw 32 bytes before tree construction.

Algorithm:

1. Leaf hash: `H(0x00 || digest_bytes)`
2. Parent hash: `H(0x01 || left_hash || right_hash)`
3. If node count is odd at any level, duplicate the last node
4. Final root encoded as `sha256:<hex(root_hash)>`

## Signature Input

Signature payload bytes MUST be the UTF-8 bytes of `integrity.bundle_root` exactly.

Verification MUST compare against the exact same UTF-8 byte sequence.

## Field Constraints

### Common Formats

- `bundle_id`: ULID (26 chars, Crockford Base32 uppercase)
- `created_at`: RFC 3339 UTC timestamp (`...Z`)
- Digest strings: `^sha256:[0-9a-f]{64}$`
- `kid`: non-empty ASCII string <= 128 chars

### `artefacts[]`

Each artifact entry MUST include:

- `name`: relative filename, no path traversal segments
- `digest`: `sha256:<64-lower-hex>`
- `size`: non-negative integer bytes
- `content_type`: MIME-like string

The artifact list order MUST be stable and used consistently for Merkle input ordering.

### Numeric Value Rule

Values represented as JSON numbers SHOULD stay in interoperable precision ranges across Rust/Node/Python implementations.
Large/edge-case numbers MUST be covered by cross-language fixtures.

## Bundle Package (`bundle.pkg`)

`bundle.pkg` is a gzip-compressed JSON container with:

- top-level `format = "pl-bundle-pkg-v1"`
- top-level `files[]` entries containing:
  - `name`
  - `data_base64`

Required file names in `files[]`:

- `proof_bundle.json`
- `proof_bundle.canonical.json` (canonical header bytes rendered as UTF-8 JSON)
- `proof_bundle.sig` (JWS compact)
- `artefacts/<name>` entries (one per artifact)
- `manifest.json`

`manifest.json` MUST include per-file digests and sizes for package-level integrity checks.

## Verification Procedure

Implementations MUST execute, in order:

1. Parse and validate schema/required fields.
2. Rebuild canonical header projection and canonicalize.
3. Recompute `header_digest` and compare with recorded value.
4. Recompute artifact digests and compare.
5. Recompute `bundle_root` and compare.
6. Verify JWS signature over UTF-8 `bundle_root` bytes using issuer public key.
7. Report optional checks (timestamp/receipt) as skipped if absent.

Any required check failure MUST produce an invalid result.

## Minimal Example (illustrative)

```json
{
  "bundle_version": "0.1",
  "bundle_id": "01JMBQ3Q7V0T9E0XH1MG6G4X3E",
  "created_at": "2026-03-01T14:12:09Z",
  "actor": { "issuer": "proof-layer-local", "app_id": "demo", "env": "dev", "signing_key_id": "kid-dev-01" },
  "subject": { "request_id": "req_9f3c2a", "thread_id": "thr_17a1", "user_ref": "hmac_sha256:9b2e..." },
  "model": { "provider": "anthropic", "model": "claude-sonnet-4-6", "parameters": { "temperature": 0.7, "max_tokens": 1024 } },
  "inputs": { "messages_commitment": "sha256:2f3c..." },
  "outputs": { "assistant_text_commitment": "sha256:91fe..." },
  "trace": { "otel_genai_semconv_version": "1.0.0", "trace_commitment": "sha256:77ab..." },
  "artefacts": [
    { "name": "prompt.json", "digest": "sha256:2f3c...", "size": 412, "content_type": "application/json" },
    { "name": "response.json", "digest": "sha256:91fe...", "size": 890, "content_type": "application/json" }
  ],
  "policy": { "redactions": [], "encryption": { "enabled": false } },
  "integrity": {
    "canonicalization": "RFC8785-JCS",
    "hash": "SHA-256",
    "header_digest": "sha256:2f3c...",
    "bundle_root_algorithm": "pl-merkle-sha256-v1",
    "bundle_root": "sha256:5b12...",
    "signature": { "format": "JWS", "alg": "EdDSA", "kid": "kid-dev-01", "value": "eyJ..." }
  },
  "timestamp": null,
  "receipt": null
}
```
