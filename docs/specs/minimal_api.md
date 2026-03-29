# Minimal Chat Proof API Specification

Status: Draft (v1 baseline)

## 1) Scope and design goals

This document defines a **minimal, cross-language chat proof API** for SDK consumers who need deterministic chat-session capture and signed proof output.

The API surface is intentionally small:

1. `start_session` (session init)
2. `log_user(...)`
3. `log_ai(...)`
4. `finish_session(...)`

The spec also defines failure behavior and versioning expectations.

---

## 2) Canonical API surface (language-neutral)

### 2.1 `start_session(...)` init semantics

Creates a new in-memory chat proof session bound to a `ProofLayer` instance.

**Required arguments**
- `provider: string`
- `model: string`

**Optional arguments**
- `system_id?: string`
- `request_id?: string`
- `thread_id?: string`
- `user_ref?: string`
- `model_parameters?: object`
- `compliance_profile?: object`
- `retention_class?: string`
- `artefacts?: list<object>`

**Behavior**
- Initializes an empty ordered transcript.
- Stores session metadata for later capture.
- Must not perform capture/signing/network side effects.
- Returns a session handle used for all subsequent calls.

### 2.2 `log_user(content)`

Appends one transcript entry with role `user`.

**Arguments**
- `content: string`

**Behavior**
- Appends `{ role: "user", content }` to session transcript.
- Preserves append order exactly.
- No proof generation or signing occurs at this step.

### 2.3 `log_ai(content)`

Appends one transcript entry with role `assistant`.

**Arguments**
- `content: string`

**Behavior**
- Appends `{ role: "assistant", content }` to session transcript.
- Preserves append order exactly.
- No proof generation or signing occurs at this step.

### 2.4 `finish_session(...)` output contract

Finalizes session capture and returns transcript + proof bundle metadata.

**Arguments**
- No required arguments in v1.

**Capture derivation rules**
- `input`: ordered list of all `user` message contents.
- `output`: concatenation of all `assistant` message contents joined by `"\n\n"`.

**Return shape (canonical)**

```json
{
  "transcript": [
    { "role": "user", "content": "..." },
    { "role": "assistant", "content": "..." }
  ],
  "proof": {
    "bundleId": "string",
    "bundleRoot": "hex-string",
    "signature": "base64-or-encoded-signature",
    "createdAt": "RFC3339 timestamp",
    "bundle": { "...": "implementation-defined signed bundle payload" }
  }
}
```

**Behavioral guarantees**
- Returned `transcript` preserves exact append order.
- `proof` represents capture/signing over the derived session data.
- Session implementations should be treated as single-use after successful finish; callers should start a new session for new interactions.

---

## 3) Failure semantics

All SDKs MUST expose explicit, non-silent failures for at least the following classes.

### 3.1 Capture errors

Raised when capture payload cannot be assembled or sent to underlying capture engine.

Examples:
- missing required provider/model at init
- invalid request shape to underlying client
- transport/client failure in vault mode

### 3.2 Signing errors

Raised when signature generation fails.

Examples:
- invalid/private key parse failure
- unsupported signing algorithm
- signature operation failure in local mode

### 3.3 Serialization errors

Raised when proof/bundle serialization or canonicalization fails.

Examples:
- non-serializable artefacts/model parameters
- invalid JSON encoding constraints

### 3.4 Error contract requirements

- Errors MUST fail the call (no silent fallback-to-success behavior).
- Error type/message SHOULD distinguish capture vs signing vs serialization categories.
- `finish_session(...)` MUST not return partial success objects that look successful when proof generation failed.
- SDK docs SHOULD include language-idiomatic exception/error classes for these categories.

---

## 4) Language-specific naming map (v1)

Canonical names are language-neutral (`start_session`, `log_user`, `log_ai`, `finish_session`).

| Canonical | Python | TypeScript |
| --- | --- | --- |
| `start_session` | `start_chat_session(...)` | `startChatSession(...)` |
| `log_user` | `log_user(...)` | `logUser(...)` |
| `log_ai` | `log_ai(...)` | `logAI(...)` |
| `finish_session` | `finish_session(...)` | `finishSession(...)` |

Notes:
- Python uses snake_case.
- TypeScript uses camelCase.
- TypeScript preserves acronym-style `AI` in `logAI` (not `logAi`).

---

## 5) Examples aligned with final API names

### 5.1 Python

```python
from proofsdk import ProofLayer

proof = ProofLayer.load(signing_key_path="keys/sign_key.pem")
session = proof.start_chat_session(provider="openai", model="gpt-4o-mini")

session.log_user("List EU AI Act transparency obligations.")
assistant_text = llm.chat("List EU AI Act transparency obligations.")
session.log_ai(assistant_text)

result = session.finish_session()
# result["transcript"] -> ordered chat transcript
# result["proof"] -> signed proof-layer output
```

### 5.2 TypeScript

```ts
import { ProofLayer } from "@prooflayer/sdk";

const proof = ProofLayer.load({ signingKeyPath: "keys/sign_key.pem" });
const session = proof.startChatSession({ provider: "openai", model: "gpt-4o-mini" });

session.logUser("List EU AI Act transparency obligations.");
const assistantText = await llm.chat("List EU AI Act transparency obligations.");
session.logAI(assistantText);

const result = await session.finishSession();
// result.transcript -> ordered chat transcript
// result.proof -> signed proof-layer output
```

---

## 6) Versioning policy for API changes

This API follows semantic versioning at SDK package level.

### 6.1 Patch (`x.y.Z`)
- Bug fixes and internal changes.
- No public API shape/signature behavior changes.

### 6.2 Minor (`x.Y.z`)
- Backward-compatible additions only.
- Examples: new optional args, additive response fields, new helper methods.

### 6.3 Major (`X.y.z`)
- Breaking changes.
- Examples: method renames/removals, required-argument changes, return contract incompatibilities, changed default behavior that breaks existing clients.

### 6.4 Compatibility commitments
- The naming map in Section 4 is normative for v1.
- Canonical behavior in Sections 2–3 is normative for v1.
- Any change to normative behavior requires at least a minor release (additive) or major release (breaking), with migration notes.
