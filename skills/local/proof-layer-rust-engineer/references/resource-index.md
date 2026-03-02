# Resource Index

Use this file as a quick lookup for standards, crate docs, API references, and compliance context relevant to `proof-layer-poc-plan.md`.

## Standards and Specifications

### Canonicalization and Crypto

- RFC 8785 JSON Canonicalization Scheme (JCS): https://www.rfc-editor.org/rfc/rfc8785
- RFC 8785 reference implementations and vectors: https://github.com/cyberphone/json-canonicalization
- FIPS 180-4 Secure Hash Standard: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
- FIPS 186-5 Digital Signature Standard: https://csrc.nist.gov/pubs/fips/186-5/final
- RFC 3161 Time-Stamp Protocol: https://www.ietf.org/rfc/rfc3161.txt

### Transparency and Receipts

- SCITT architecture draft (current reference): https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
- IETF SCITT working drafts and repos: https://github.com/ietf-scitt
- RFC 9162 Certificate Transparency v2: https://www.rfc-editor.org/rfc/rfc9162

### Provenance Models

- C2PA specification 2.3: https://c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html
- W3C PROV-DM: https://www.w3.org/TR/prov-dm/

## Rust Core and API Stack

### Canonicalization

- `serde_json_canonicalizer` docs: https://docs.rs/serde_json_canonicalizer/latest/serde_json_canonicalizer/

Note: this crate coerces arbitrary-precision numbers to doubles before serialization. Document this behavior in architecture/spec notes and cross-language tests.

### Signing

- `ed25519-dalek` docs: https://docs.rs/ed25519-dalek/
- `ed25519-dalek` crate: https://crates.io/crates/ed25519-dalek

Guidance: prefer stable `2.2.x` and strict verification routines.

### IDs

- `ulid` crate: https://crates.io/crates/ulid
- `rusty_ulid`: https://github.com/huxi/rusty_ulid

### Service and Persistence

- `axum` docs: https://docs.rs/axum/latest/axum/
- `sqlx` docs: https://docs.rs/sqlx/latest/sqlx/
- Axum + SQLite tutorial (secondary): https://medium.com/@mikecode/axum-build-a-restful-api-with-sqlite-database-crud-4c8c2ef36455

### CLI and Workspace

- `clap` docs: https://docs.rs/clap
- `clap` derive tutorial: https://docs.rs/clap/latest/clap/_derive/_tutorial/index.html
- Cargo workspaces (Rust Book): https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html
- Cargo monorepo setup guide (secondary): https://earthly.dev/blog/cargo-workspace-crates/

## SDK Interop References

### Node

- `@anthropic-ai/sdk` npm: https://www.npmjs.com/package/@anthropic-ai/sdk
- Anthropic TypeScript SDK repo: https://github.com/anthropics/anthropic-sdk-typescript
- `json-canonicalize` npm: https://www.npmjs.com/package/json-canonicalize

### Python

- Anthropic Python SDK: https://github.com/anthropics/anthropic-sdk-python
- `rfc8785` PyPI implementation: https://pypi.org/project/rfc8785/

## Provider API References

- Anthropic Messages examples: https://docs.anthropic.com/en/api/messages-examples
- Anthropic Messages API reference: https://docs.claude.com/en/api/messages
- Anthropic streaming docs: https://docs.anthropic.com/en/api/messages-streaming
- Anthropic API overview: https://docs.anthropic.com/claude/reference/getting-started-with-the-api
- OpenAI reproducible outputs cookbook (`seed`, `system_fingerprint`): https://developers.openai.com/cookbook/examples/reproducible_outputs_with_the_seed_parameter/

## OpenTelemetry GenAI Conventions

- Overview: https://opentelemetry.io/docs/specs/semconv/gen-ai/
- GenAI spans: https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/
- GenAI agent spans: https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/
- GenAI events: https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-events/
- GenAI attributes registry: https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/
- Raw semconv source: https://github.com/open-telemetry/semantic-conventions/blob/main/docs/gen-ai/gen-ai-spans.md
- OTel GenAI blog: https://opentelemetry.io/blog/2024/otel-generative-ai/

Note: `gen_ai.prompt` and `gen_ai.completion` are deprecated in recent semconv versions. Prefer `gen_ai.input.messages` and `gen_ai.output.messages`.

## Regulatory and Evidence Context

- EU AI Act Article 12 record-keeping: https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-12
- eIDAS Article 41 timestamps: https://www.legislation.gov.uk/eur/2014/910/article/41
- GDPR Article 5 storage limitation: https://www.legislation.gov.uk/eur/2016/679/article/5
- GDPR Article 32 security controls: https://www.legislation.gov.uk/eur/2016/679/article/32
- NCSC logging and monitoring: https://www.ncsc.gov.uk/collection/10-steps/logging-and-monitoring
- NIST IR 8387 digital evidence preservation: https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8387.pdf

## Practical Implementation Notes

- Treat SCITT drafts as architecture guidance rather than normative final standards.
- Keep bundle verification offline-capable by design.
- Maintain cross-language test vectors early to avoid JCS/JWS drift.
- Phrase claims as cryptographically verifiable evidence artifacts rather than legal proof.
