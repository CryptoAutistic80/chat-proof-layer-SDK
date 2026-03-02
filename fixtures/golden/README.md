# Golden Fixtures

Deterministic fixture inputs for CLI/service integration and cross-language verification.

## Files

- `capture.json`: Proof capture payload for `proofctl create --input`.
- `prompt.json`: Prompt artifact fixture.
- `response.json`: Response artifact fixture.
- `expected_digests.json`: Expected SHA-256 digest strings for artifact bytes.

## Generate and verify a bundle

```bash
cargo run -p proofctl -- keygen --out ./keys
cargo run -p proofctl -- create \
  --input ./fixtures/golden/capture.json \
  --artefact prompt.json=./fixtures/golden/prompt.json \
  --artefact response.json=./fixtures/golden/response.json \
  --key ./keys/signing.pem \
  --bundle-id PLFIXEDGOLDEN000000000000000001 \
  --created-at 2026-03-02T00:00:00Z \
  --signing-kid kid-dev-01 \
  --out ./fixtures/golden/bundle.pkg

cargo run -p proofctl -- verify \
  --in ./fixtures/golden/bundle.pkg \
  --key ./keys/verify.pub
```

## Notes

- `header_digest`, `bundle_root`, and `signature` remain stable only when all integrity inputs are pinned (capture bytes, artefact bytes, signing key, `bundle_id`, `created_at`, and `signing_kid`).
- Artifact digest values in `expected_digests.json` should stay stable unless fixture file bytes change.
