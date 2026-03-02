# AI Output Proof Layer — Resource List

## Standards & Specifications

### Cryptography & Canonicalisation

- **RFC 8785 — JSON Canonicalization Scheme (JCS)** — the authoritative spec for deterministic JSON hashing
  https://www.rfc-editor.org/rfc/rfc8785

- **RFC 8785 — reference implementations (multi-language)** — cyberphone's repo including Python, Node, Java, Rust test vectors
  https://github.com/cyberphone/json-canonicalization

- **FIPS 180-4 — Secure Hash Standard (SHA-256/512)**
  https://csrc.nist.gov/pubs/fips/180-4/upd1/final

- **FIPS 186-5 — Digital Signature Standard (EdDSA/ECDSA)**
  https://csrc.nist.gov/pubs/fips/186-5/final

- **RFC 3161 — Time-Stamp Protocol (TSP)**
  https://www.ietf.org/rfc/rfc3161.txt

### Transparency & Receipts

- **IETF SCITT Architecture (draft-22, current)** — the signed statements + transparency service + receipt model your v1 receipt layer maps to
  https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/

- **IETF SCITT GitHub org** — working group drafts including COSE Merkle tree proofs and SCRAPI
  https://github.com/ietf-scitt

- **RFC 9162 — Certificate Transparency v2** — the canonical append-only log with Merkle inclusion proofs (conceptual anchor)
  https://www.rfc-editor.org/rfc/rfc9162

### Provenance

- **C2PA Technical Specification v2.3** — the media provenance model (assertions + claim + signature + bindings) that is a direct conceptual template for your Proof Bundle
  https://c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html

- **W3C PROV-DM** — domain-agnostic provenance modelling (entities, activities, agents)
  https://www.w3.org/TR/prov-dm/

---

## Rust Core

### Canonicalisation

- **`serde_json_canonicalizer` crate** — drop-in RFC 8785 for Rust/serde_json
  https://docs.rs/serde_json_canonicalizer/latest/serde_json_canonicalizer/

### Signing

- **`ed25519-dalek` docs.rs** — current stable (2.2.x), constant-time, `verify_strict()` available
  https://docs.rs/ed25519-dalek/

- **`ed25519-dalek` crates.io** — version history, features list
  https://crates.io/crates/ed25519-dalek

### IDs

- **`ulid` crate** — the recommended ULID implementation for bundle IDs
  https://crates.io/crates/ulid

- **`rusty_ulid`** — alternative with chrono/time support and a CLI binary
  https://github.com/huxi/rusty_ulid

### Service & API

- **`axum` docs.rs** — macro-free routing, Tower middleware ecosystem
  https://docs.rs/axum/latest/axum/

- **Axum + SQLite/SQLx tutorial** — practical CRUD with async SQLite pool
  https://medium.com/@mikecode/axum-build-a-restful-api-with-sqlite-database-crud-4c8c2ef36455

- **SQLx docs** — async, compile-time checked queries, SQLite/Postgres/MySQL
  https://docs.rs/sqlx/latest/sqlx/

### CLI

- **`clap` docs.rs** — derive-macro argument parsing, subcommands
  https://docs.rs/clap

- **`clap` derive tutorial** — official step-by-step derive API guide
  https://docs.rs/clap/latest/clap/_derive/_tutorial/index.html

### Monorepo / Workspace

- **Cargo Workspaces — The Rust Book** — official canonical reference
  https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html

- **Earthly — Monorepos with Cargo Workspaces** — practical setup guide
  https://earthly.dev/blog/cargo-workspace-crates/

---

## Node SDK

- **`@anthropic-ai/sdk` npm** — TypeScript SDK, streaming, MCP helpers
  https://www.npmjs.com/package/@anthropic-ai/sdk

- **Anthropic TypeScript SDK GitHub** — source, streaming examples, tool use patterns
  https://github.com/anthropics/anthropic-sdk-typescript

- **`json-canonicalize` npm** — RFC 8785 for Node; use `canonicalizeEx` with `undefinedInArrayToNull: false` for strict compliance
  https://www.npmjs.com/package/json-canonicalize

---

## Python SDK

- **Anthropic Python SDK GitHub** — official, pip installable
  https://github.com/anthropics/anthropic-sdk-python

- **`rfc8785` PyPI** — Trail of Bits pure-Python RFC 8785 implementation, no dependencies
  https://pypi.org/project/rfc8785/

---

## Provider API Reference

- **Anthropic Messages API examples** — request/response structure, stateless conversation pattern, usage fields
  https://docs.anthropic.com/en/api/messages-examples

- **Anthropic Messages API reference** — full parameter docs, stop_reason, usage, streaming
  https://docs.claude.com/en/api/messages

- **Anthropic streaming docs** — SSE, SDK accumulation, multi-content blocks
  https://docs.anthropic.com/en/api/messages-streaming

- **Anthropic API overview** — endpoint list, rate limits, Batches/Files/Token Count APIs
  https://docs.anthropic.com/claude/reference/getting-started-with-the-api

- **OpenAI reproducible outputs cookbook** — `system_fingerprint` and `seed` parameter for capture metadata
  https://developers.openai.com/cookbook/examples/reproducible_outputs_with_the_seed_parameter/

---

## OpenTelemetry / GenAI Conventions

- **OTel GenAI semantic conventions overview** — entry point, links to spans, events, metrics, agent spans, provider-specific
  https://opentelemetry.io/docs/specs/semconv/gen-ai/

- **GenAI client spans** — `gen_ai.operation.name`, `gen_ai.request.model`, `gen_ai.input.messages`, tool call spans
  https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/

- **GenAI agent spans** — agentic operation modelling, `gen_ai.data_source.id`, tool execution
  https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/

- **GenAI events** — input/output events, `gen_ai.input.messages`, `gen_ai.output.messages` (replaces deprecated `gen_ai.prompt`/`gen_ai.completion`)
  https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-events/

- **GenAI attributes registry** — full attribute list with descriptions and example values
  https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/

- **GenAI spans GitHub source** — raw markdown, useful for implementing attribute names correctly
  https://github.com/open-telemetry/semantic-conventions/blob/main/docs/gen-ai/gen-ai-spans.md

- **OTel for GenAI blog (2024)** — Python instrumentation walkthrough, `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT` env var
  https://opentelemetry.io/blog/2024/otel-generative-ai/

---

## Regulatory & Compliance Context

- **EU AI Act — Article 12 Record-Keeping** — the "why now" for the proof layer
  https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-12

- **eIDAS Article 41** — electronic timestamps shall not be denied legal effect; qualified timestamps
  https://www.legislation.gov.uk/eur/2014/910/article/41

- **GDPR Article 5** — storage limitation principle
  https://www.legislation.gov.uk/eur/2016/679/article/5

- **GDPR Article 32** — encryption and pseudonymisation as appropriate security measures
  https://www.legislation.gov.uk/eur/2016/679/article/32

- **NCSC — Logging and Monitoring** — logging as foundational security control
  https://www.ncsc.gov.uk/collection/10-steps/logging-and-monitoring

- **NIST IR 8387 — Digital Evidence Preservation** — chain-of-custody, integrity, documentation
  https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8387.pdf

---

## Practical Notes

### OTel deprecation alert
`gen_ai.prompt` and `gen_ai.completion` span attributes are deprecated as of v1.38.0. Use `gen_ai.input.messages` and `gen_ai.output.messages` instead — this affects how you map captures to OTel in the SDK.

### `serde_json_canonicalizer` number handling
It converts arbitrary-precision numbers to doubles before serialising. Document this explicitly in your canonicalisation spec — it is a known edge case that will come up in cross-language test vectors.

### `ed25519-dalek` version
Use 2.2.x (stable), not the 3.x pre-releases. `verify_strict()` is the safe default — avoids the underspecified validation gotchas documented in the library.

### SCITT draft status
Now at version 22 (October 2025). The architecture is stable enough to design against for your v1 receipt layer, but treat it as reference architecture not a finalised spec.
