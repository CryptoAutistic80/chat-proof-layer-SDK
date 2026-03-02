# AI Output Proof Layer — PoC Sprint Plan

> **Goal:** Build a working, demoable proof-of-concept that a design partner can see, touch, and understand — not a polished product, but a credible technical foundation.

---

## What We're Building

A horizontal infrastructure layer that wraps any AI provider call and produces a **Proof Bundle** — a cryptographically sealed, independently verifiable record of exactly what was asked, what happened, and what was returned. Generic by design: no vertical framing, no domain assumptions. Plugs beneath any AI stack.

**Demo deliverables:**
- `proofctl` CLI — seal a run, verify a bundle, inspect its contents
- Simple web UI — paste a prompt, call Claude or OpenAI, watch the proof bundle materialise and verify live
- Working Rust core, Node SDK, Python SDK, REST proof service

---

## Monorepo Structure

```
proof-layer/
├── README.md
├── docs/
│   ├── architecture.md
│   ├── proof_bundle_schema.md
│   └── threat_model.md
├── packages/
│   ├── core-rust/          ← canonicalise, hash, sign, verify
│   ├── sdk-node/           ← OpenAI + Anthropic wrappers, OTel export
│   ├── sdk-python/         ← same, + LangChain/decorator support
│   ├── proof-service/      ← REST API (Axum + sled)
│   └── cli/                ← proofctl binary
├── web-demo/               ← single-page demo UI
└── examples/
    ├── node-basic/
    ├── python-basic/
    └── agent-simulated/    ← fake tool calls + RAG steps
```

---

## Sprint Phases

> Phases are sequenced by dependency, not by calendar day. A solo developer should complete phases 1–3 before touching the SDK or UI. Estimate roughly half a day per phase for the core, a day each for SDKs and service, half a day for CLI and UI.

---

### Phase Exit Checks (hard gates)

- **Phase 1 gate:** Deterministic canonical bytes, digest, Merkle root, and signature outputs are fixed by test vectors; tamper tests fail closed.
- **Phase 2 gate:** `/v1/bundles` and `/v1/verify` run against the same Rust core crate, enforce payload limits, and never log plaintext artefacts.
- **Phase 5 gate:** `proofctl create/verify/inspect` works fully offline using only `bundle.pkg` and a public key; invalid bundles produce explicit failure reasons.
- **Docs prerequisite:** `docs/architecture.md`, `docs/proof_bundle_schema.md`, and `docs/threat_model.md` exist before external demos.

---

### Phase 1 — Rust Core (`packages/core-rust`)

**Why first:** Everything downstream depends on canonical, stable hashing and signing. Getting this wrong invalidates everything else.

#### 1.1 — Canonicalisation (`src/canonicalize.rs`)

Implement RFC 8785 JSON Canonicalization Scheme (JCS) with strict input guards:

- Canonicalization engine: `serde_json_canonicalizer`
- Lexicographic key ordering for objects
- No extraneous whitespace
- Stable number rendering
- UTF-8 strings with standard JSON escapes
- Arrays preserve order
- Reject duplicate keys in untrusted raw JSON before converting to `serde_json::Value`
- Reject non-finite numbers or unsupported numeric encodings before canonicalization
- Constrain numeric precision in schema and tests to avoid cross-language drift with large/edge-case numbers

```rust
pub fn canonicalize_value(value: &serde_json::Value) -> Result<Vec<u8>, CanonError>
pub fn canonicalize_json_strict(raw: &[u8]) -> Result<Vec<u8>, CanonError> // use for untrusted input
```

Write exhaustive unit tests including known vectors from RFC 8785 Appendix B.

#### 1.2 — Hashing (`src/hash.rs`)

```rust
pub fn sha256_prefixed(bytes: &[u8]) -> String // "sha256:<64 lowercase hex>"
pub fn sha256_prefixed_file(path: &Path) -> Result<String, IoError>
pub fn parse_sha256_prefixed(digest: &str) -> Result<[u8; 32], DigestError>
```

SHA-256 per FIPS 180-4. Always normalize to lowercase hex with `sha256:` prefix.

#### 1.3 — Merkle Commitment (`src/merkle.rs`)

MVP root construction must be explicit and unambiguous:

- Digest input order is exactly `[header_digest, artefact_digest_1, artefact_digest_2, ...]`
- Parse each digest as raw 32-byte SHA-256 value (never hash hex text directly)
- Leaf hash: `H(0x00 || digest_bytes)`
- Parent hash: `H(0x01 || left || right)`; if odd node count, duplicate the last node
- Root output encoded as `sha256:<hex>`

```rust
pub struct MerkleCommitment {
    pub algorithm: &'static str, // "pl-merkle-sha256-v1"
    pub root: String,
    pub leaves: Vec<String>,
}
pub fn compute_commitment(digests: &[String]) -> Result<MerkleCommitment, MerkleError>
```

Document the exact root construction in `docs/proof_bundle_schema.md`.

#### 1.4 — Signing & Verification (`src/sign.rs`, `src/verify.rs`)

- Ed25519 via `ed25519-dalek` `2.2.x`
- Verification must use `verify_strict()`
- Signed payload is the UTF-8 bytes of `bundle_root` (`sha256:<hex>`), where `bundle_root` commits to canonical header digest + artefact digests
- JWS compact serialisation: `base64url(header).base64url(payload).base64url(sig)`
- Key generation utility for local dev: `proofctl keygen`
- Key material loaded from env/file (never hardcoded)

```rust
pub fn sign_bundle_root(bundle_root: &str, signing_key: &SigningKey, kid: &str) -> Result<String, SignError>
pub fn verify_bundle_root(jws: &str, bundle_root: &str, verifying_key: &VerifyingKey) -> Result<(), VerifyError>
```

#### 1.5 — Tests

Cover tamper cases explicitly:
- Modified artefact → hash mismatch detected
- Modified header → signature fails
- Wrong key → verification fails
- Duplicate JSON keys → canonicalisation rejects
- Malformed digest prefix/length → parse fails before verification
- Tampered JWS header/payload/signature → verification fails
- Cross-language fixtures (Rust/Node/Python) match for canonical bytes, header digest, bundle root, and signature verification

---

### Phase 2 — Proof Service (`packages/proof-service`)

**Recommended stack:** Axum (Rust) with direct use of the core crate. This keeps canonicalization, hashing, Merkle, and signing in one runtime and avoids cross-process drift.

#### Endpoints

```
POST   /v1/bundles                          → create bundle, return bundle_id
GET    /v1/bundles/:bundle_id               → fetch header (no plaintext artefacts)
GET    /v1/bundles/:bundle_id/artefacts/:name → fetch artefact blob
POST   /v1/verify                           → server-side verify a submitted bundle package
```

#### Storage (MVP, sled-based)

- **Bundle headers + indexes:** `sled`
- **Artefacts:** Local filesystem (`./storage/artefacts/{bundle_id}/{name}`)
- Suggested trees:
- `bundles_by_id`: key=`bundle_id`, value=`proof_bundle.json` bytes
- `idx_request_id`: key=`request_id|bundle_id`, value=`bundle_id`
- `idx_created_at`: key=`created_at|bundle_id`, value=`bundle_id`
- `idx_app_id`: key=`app_id|created_at|bundle_id`, value=`bundle_id`

#### Bundle Creation Flow

```
1. Receive capture payload (JSON) + artefact blobs
2. Validate schema (bundle_version, actor, subject, model, inputs, outputs)
3. Store artefacts, compute SHA-256 digest for each
4. Canonicalise header JSON (RFC 8785) from strict raw-bytes path
5. Compute `header_digest = sha256(canonical_header_bytes)`
6. Compute `bundle_root` from `[header_digest, ...artefact_digests]`
7. Sign `bundle_root` with service signing key (Ed25519 JWS)
8. If RFC 3161 stub enabled: call TSA endpoint, attach token
9. Persist bundle header + integrity fields in a single sled batch
10. Return { bundle_id, bundle_root, signature, created_at }
```

#### Durability Notes (sled + filesystem)

- Write artefacts via `tmp` file + `fsync` + atomic rename before committing metadata.
- Use sled compare-and-swap or `Batch` to avoid partial index writes.
- Flush sled on successful bundle creation boundary.

#### Security

- Reject payloads > 10MB (configurable)
- Reject oversized artefacts and package uploads by byte limit (configurable)
- Never log plaintext artefact content
- Signing key loaded from env var / file, never hardcoded

---

### Phase 3 — Node SDK (`packages/sdk-node`)

#### Provider Wrappers

**OpenAI-compatible** (`src/providers/openai_like.ts`):

```typescript
export async function provedCompletion(
  client: OpenAI,
  params: ChatCompletionCreateParams,
  proofClient: ProofLayerClient,
  captureOptions?: CaptureOptions
): Promise<{ completion: ChatCompletion; bundleId: string }>
```

Captures: full request params, response body, `model`, `usage`, `system_fingerprint`.

**Anthropic** (`src/providers/anthropic_like.ts`):

```typescript
export async function provedMessage(
  client: Anthropic,
  params: MessageCreateParams,
  proofClient: ProofLayerClient,
  captureOptions?: CaptureOptions
): Promise<{ message: Message; bundleId: string }>
```

Captures: full messages array (stateless — must capture full history), response, `usage`, `model`, `stop_reason`.

#### Tool Call Capture (`src/tooling/tool_capture.ts`)

```typescript
export function captureToolCall(name: string, input: unknown, output: unknown): ToolCallEvent
```

Generic — works for any tool, RAG retrieval step, or MCP call.

#### OTel Export (`src/export/otel_genai.ts`)

Map captured events to OpenTelemetry GenAI semantic conventions spans. Emit as OTLP or return as structured JSON. This lets the Proof Bundle ID flow into existing tracing pipelines.

---

### Phase 4 — Python SDK (`packages/sdk-python`)

Mirror the Node SDK surface, plus:

**Decorators** (`proofsdk/decorators.py`):

```python
@prove_llm_call(proof_client=client, provider="anthropic")
def my_agent_step(messages: list) -> str:
    ...
```

**LangChain integration** (`proofsdk/providers/langchain_like.py`):
- Implement as a `BaseCallbackHandler` that captures on `on_llm_start` / `on_llm_end` / `on_tool_start` / `on_tool_end`

---

### Phase 5 — CLI (`packages/cli`)

**Recommended:** Rust binary (`clap` derive), using the core crate directly.

CLI guardrails:
- Enforce input and artefact byte limits (same defaults as service)
- Reject unknown integrity algorithms
- Verify artefact digests before signature trust checks

```bash
# Generate a keypair for local dev
proofctl keygen --out ./keys

# Create a bundle from a capture JSON + artefacts
proofctl create \
  --input capture.json \
  --artefact prompt=./prompt.json \
  --artefact response=./response.json \
  --key ./keys/signing.pem \
  --out bundle.pkg

# Verify a bundle package
proofctl verify --in bundle.pkg --key ./keys/verify.pub

# Human-readable inspection
proofctl inspect --in bundle.pkg --format human
proofctl inspect --in bundle.pkg --format json
```

**Bundle package format** (`bundle.pkg` is a `.tar.gz`):

```
proof_bundle.json           ← original
proof_bundle.canonical.json ← JCS-canonicalised form
proof_bundle.sig            ← JWS compact string
artefacts/
  prompt.json
  response.json
manifest.json               ← { files: [{ name, digest, size }] }
```

**Verification steps (printed to stdout):**

```
[✓] Canonicalisation — header re-canonicalised, digest matches
[✓] Artefact integrity — 2/2 artefacts match recorded digests
[✓] Signature — Ed25519 signature valid for bundle_root
[✗] Timestamp — no RFC 3161 token present (optional)
[–] Transparency receipt — not present (optional)

Verification result: VALID (with 2 optional checks skipped)
```

---

### Phase 6 — Web Demo (`web-demo/`)

Single-page app. Stack: Vite + React + Tailwind. No backend framework needed — calls the proof service directly.

#### Layout

```
┌─────────────────────────────────────────────────────┐
│  AI Output Proof Layer — Live Demo                  │
├──────────────────────┬──────────────────────────────┤
│  [Provider: Claude ▼]│                              │
│                      │  PROOF BUNDLE                │
│  System prompt:      │  ─────────────               │
│  [textarea]          │  bundle_id: 01JM...          │
│                      │  created_at: 2026-...        │
│  User prompt:        │  model: claude-sonnet-4-...  │
│  [textarea]          │  inputs_commitment: sha256:  │
│                      │  outputs_commitment: sha256: │
│  [▶ Run & Seal]      │  signature: eyJh...          │
│                      │                              │
│  Response:           │  VERIFICATION                │
│  [readonly textarea] │  ─────────────               │
│                      │  [✓] Canonicalisation        │
│                      │  [✓] Artefact integrity      │
│                      │  [✓] Signature               │
│                      │  [✗] RFC 3161 (not in PoC)  │
└──────────────────────┴──────────────────────────────┘
```

#### Flow

1. User enters prompts, selects provider (Claude / OpenAI)
2. On "Run & Seal": POST to proof service `/v1/bundles` with capture payload
3. Response streams into left panel
4. Proof bundle JSON renders in right panel (expandable tree)
5. POST to `/v1/verify` — verification result renders with pass/fail per step
6. "Download bundle.pkg" button exports the full package

---

## Bundle Schema (MVP v0.1)

```jsonc
{
  "bundle_version": "0.1",
  "bundle_id": "01JMBQ3Q7V0T9E0XH1MG6G4X3E",   // ULID
  "created_at": "2026-03-01T14:12:09Z",          // RFC 3339

  "actor": {
    "issuer": "proof-layer-local",
    "app_id": "demo",
    "env": "dev",
    "signing_key_id": "kid-dev-01"
  },

  "subject": {
    "request_id": "req_9f3c2a",
    "thread_id": "thr_17a1",
    "user_ref": "hmac_sha256:9b2e..."             // pseudonymised
  },

  "model": {
    "provider": "anthropic",
    "model": "claude-sonnet-4-6",
    "parameters": { "temperature": 0.7, "max_tokens": 1024 }
  },

  "inputs": {
    "messages_commitment": "sha256:2f3c...",
    "retrieval_commitment": "sha256:aa91..."      // optional
  },

  "outputs": {
    "assistant_text_commitment": "sha256:91fe...",
    "tool_outputs_commitment": "sha256:0c41..."   // optional
  },

  "trace": {
    "otel_genai_semconv_version": "1.0.0",
    "trace_commitment": "sha256:77ab..."
  },

  "artefacts": [
    {
      "name": "prompt.json",
      "digest": "sha256:2f3c...",
      "size": 412,
      "content_type": "application/json"
    },
    {
      "name": "response.json",
      "digest": "sha256:91fe...",
      "size": 890,
      "content_type": "application/json"
    }
  ],

  "policy": {
    "redactions": [],
    "encryption": { "enabled": false }
  },

  "integrity": {
    "canonicalization": "RFC8785-JCS",
    "hash": "SHA-256",
    "header_digest": "sha256:2f3c...",
    "bundle_root_algorithm": "pl-merkle-sha256-v1",
    "bundle_root": "sha256:5b12...",
    "signature": {
      "format": "JWS",
      "alg": "EdDSA",
      "kid": "kid-dev-01",
      "value": "eyJhbGciOiJFZERTQSIsImtpZCI6ImtpZC1kZXYtMDEifQ..."
    }
  },

  // Optional — stub in PoC, real in v1
  "timestamp": null,
  "receipt": null
}
```

---

## Sequencing Summary

| Phase | Component | Depends On | Rough Effort |
|-------|-----------|------------|--------------|
| 1 | Rust core (canon + hash + sign + verify) | Nothing | Medium-high |
| 2 | Proof Service REST API | Phase 1 (crypto) | Medium |
| 3 | Node SDK (OpenAI + Anthropic wrappers) | Phase 2 | Medium |
| 4 | Python SDK (decorators + LangChain) | Phase 2 | Medium |
| 5 | CLI (proofctl) | Phase 1 | Low-medium |
| 6 | Web demo UI | Phases 2, 3 | Low-medium |

Start Phase 3 and 5 in parallel once Phase 1 is solid. Phase 6 can begin as soon as the proof service `/v1/bundles` endpoint is standing.

---

## Definition of Done (PoC)

A design partner can:

1. Clone the repo and run `docker compose up` to start the proof service
2. Run `npm run demo` or `python examples/python-basic/run.py` to generate a real bundle
3. Run `proofctl verify --in bundle.pkg` and see a clear pass/fail per verification step
4. Open the web UI, type a prompt, watch the proof bundle appear and verify in real time
5. Download `bundle.pkg` and verify it offline with just the CLI and the public key

---

## What's Explicitly Not In This PoC

| Feature | Why deferred |
|---------|-------------|
| RFC 3161 trusted timestamping | Interface stubbed, real TSA integration is v1 |
| Transparency receipts (SCITT/Sigstore) | Architecture documented, implementation is v1 |
| WORM storage (S3 Object Lock, Azure) | Integration guides written for v1 |
| Merkle selective disclosure | Data model supports it; full implementation is v1 |
| BYOK / HSM-backed keys | Local key file for PoC; KMS integration is enterprise tier |
| PII redaction / encryption | Policy field captured; enforcement is v1 |
| Zero-knowledge proofs | Far future |

---

## Key Design Decisions to Document Now

These must be written clearly in `docs/architecture.md` before the first design partner call — they are the credibility anchors:

1. **What exactly is signed** - the `bundle_root` string, where `bundle_root` is derived from `header_digest` and artefact digests; `header_digest` itself is SHA-256 over RFC 8785 canonical header bytes.
2. **Bundle root construction** - ordered digest list `[header_digest, artefact_digest_1, ...]` with explicit domain-separation bytes and duplicate-last handling for odd node counts.
3. **Verification is offline-capable** — a verifier needs only the bundle package and the issuer's public key. No call home required.
4. **Provider adapters are thin** — the core is provider-agnostic. Adding a new provider means implementing one interface, not forking the core.
5. **Non-determinism acknowledged** — LLM outputs are non-deterministic. The Proof Layer records what happened, not what would happen again. Replay is evidence replay (reconstruct timeline), not behavioural replay (reproduce output).

---

## Risks to Watch

| Risk | Mitigation |
|------|-----------|
| Rust compile times slow iteration | Use `cargo check` aggressively; mock the core in tests with pre-baked fixtures |
| JWS/JCS interop across languages | Write cross-language canonicalisation test vectors early; test Node and Python against the Rust reference |
| Duplicate-key detection accidentally bypassed | Require strict raw JSON canonicalization path for all untrusted inputs; fail closed if parser cannot prove uniqueness |
| `sled` index growth / maintenance overhead | Keep tree keys prefix-structured, run periodic compaction/backup task, and revisit SQL backend in v1 if query patterns outgrow KV indexes |
| "Proof" creates false legal expectations | Demo materials say "cryptographically verifiable evidence artefact" not "legal proof"; always qualify |
| Demo AI calls fail / rate limits | Pre-record a fixture run for fallback demo mode |
