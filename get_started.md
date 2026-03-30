# Get Started (Chatbot-First)

This quickstart is intentionally optimized for **proving chat assistant interactions**.

## 1) Generate a signing key

From the repo root:

```bash
cargo run -p proofctl -- generate-keypair --out ./keys
```

This creates a local Ed25519 signing key and matching verify key for transcript proof workflows.

## 2) Run a chat session

Run the chatbot example first:

```bash
python3 examples/python-chat-proof/run.py
```

Primary artefact path to use in docs and checks:

- `examples/bundles/chat-session.bundle.json`

## 3) Verify transcript proof

Verify the produced chat-session bundle:

```bash
cargo run -p proofctl -- verify-bundle \
  --in ./examples/bundles/chat-session.bundle.json \
  --key ./keys/verify.pub
```

If verification succeeds, the transcript commitment and signature are intact.

## 4) Optional disclosure export

Create a selectively disclosed package from the chat-session bundle:

```bash
cargo run -p proofctl -- disclose \
  --in ./examples/bundles/chat-session.bundle.json \
  --items 0 \
  --out ./chat-session.disclosure.pkg

cargo run -p proofctl -- verify-bundle \
  --in ./chat-session.disclosure.pkg \
  --key ./keys/verify.pub
```

Use this when you need to share only part of a transcript while preserving proof integrity.

## Scope Guardrails

The chatbot-first version intentionally prioritizes transcript proof and intentionally does **not** make the following primary:

- Full governance/readiness profile workflows.
- Pack-centric regulatory exports as onboarding defaults.
- Vault-first deployment requirements for local proof generation.
- Non-chat evidence families as the starter examples.

## Advanced/Legacy Appendix (Not Primary Path)

> **Not primary path:** Use these after completing the chatbot quickstart above.

Advanced examples:

- `examples/python-annex-iv/run.py`
- `examples/python-compliance/run.py`
- `examples/python-incident-response/run.py`
- `examples/typescript-compliance/run.mjs`
- `examples/typescript-monitoring/run.mjs`
- `examples/typescript-gpai/run.mjs`
- `examples/python-basic/run.py`
- `examples/agent-simulated/run.py`

Related advanced docs:

- `docs/compliance/eu_ai_act_mapping.md`
- `docs/release_and_operations_guide.md`
- `docs/verification-test-matrix.md`
