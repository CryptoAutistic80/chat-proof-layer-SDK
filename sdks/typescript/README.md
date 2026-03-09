# @proof-layer/sdk (TypeScript SDK)

TypeScript SDK for creating Proof Layer evidence bundles around model calls.
Integrity-sensitive helpers are backed by the local Rust NAPI module in `crates/napi`, while the package surface stays TypeScript-first.

The SDK now has typed builders and `ProofLayer` convenience methods for every evidence item currently implemented in Rust core: `llm_interaction`, `tool_call`, `retrieval`, `human_oversight`, `policy_decision`, `risk_assessment`, `data_governance`, `technical_doc`, `model_evaluation`, `adversarial_test`, `training_provenance`, `literacy_attestation`, `incident_report`, `conformity_assessment`, `declaration`, and `registration`.
The GPAI helpers default `model_evaluation`, `adversarial_test`, and `training_provenance` captures to the vault's `gpai_documentation` retention class.

## Build Native Bindings

```bash
npm install
npm run build
```

## Quick Usage

```js
import {
  ProofLayerExporter,
  LocalProofLayerClient,
  ProofLayer,
  ProofLayerClient,
  buildBundle,
  createDisclosurePolicyTemplate,
  createLlmInteractionRequest,
  hashSha256,
  verifyBundle
} from "@proof-layer/sdk";
import { withProofLayer } from "@proof-layer/sdk/providers/openai";
import { withProofLayer as withGenericProofLayer } from "@proof-layer/sdk/providers/generic";

const proofClient = new ProofLayerClient({ baseUrl: "http://127.0.0.1:8080" });
const localClient = new LocalProofLayerClient({
  signingKeyPem: "-----BEGIN PROOF LAYER ED25519 PRIVATE KEY-----\n...\n-----END PROOF LAYER ED25519 PRIVATE KEY-----\n",
  signingKeyId: "kid-dev-01"
});
const proofLayer = new ProofLayer({
  vaultUrl: "http://127.0.0.1:8080",
  appId: "typescript-demo",
  env: "dev"
});
const openaiClient = {
  chat: {
    completions: {
      create: async (params) => ({
        id: "cmpl-demo",
        model: params.model,
        choices: [{ message: { role: "assistant", content: "Hello" } }],
        usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 }
      })
    }
  }
};

const openai = withProofLayer(openaiClient, proofLayer);
const completion = await openai.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "Say hello" }]
});

console.log(completion.proofLayer.bundleId, completion.id);
console.log(hashSha256(JSON.stringify({ hello: "world" })));

const capture = createLlmInteractionRequest({
  keyId: "kid-dev-01",
  provider: "openai",
  model: "gpt-4o-mini",
  input: [{ role: "user", content: "Say hello" }],
  output: completion
});

const localBundle = buildBundle({
  capture: capture.capture,
  artefacts: capture.artefacts,
  keyPem: "-----BEGIN PROOF LAYER ED25519 PRIVATE KEY-----\n...\n-----END PROOF LAYER ED25519 PRIVATE KEY-----\n",
  kid: "kid-dev-01",
  bundleId: "PLFIXEDGOLDEN000000000000000001",
  createdAt: "2026-03-02T00:00:00+00:00"
});

const locallySealed = await localClient.createBundle({
  capture: { /* capture.json */ },
  artefacts: [{ name: "prompt.json", contentType: "application/json", data: Buffer.from("{}") }]
});

const summary = verifyBundle({
  bundle: locallySealed.bundle,
  artefacts: [{ name: "prompt.json", data: Buffer.from("{}") }],
  publicKeyPem: "-----BEGIN PROOF LAYER ED25519 PUBLIC KEY-----\n...\n-----END PROOF LAYER ED25519 PUBLIC KEY-----\n"
});

console.log(summary.artefact_count);
console.log(proofClient.baseUrl);

const redacted = await proofLayer.disclose({
  bundle: locallySealed.bundle,
  itemIndices: [0],
  fieldRedactions: { "0": ["output_commitment"] }
});
const redactedSummary = await proofLayer.verifyRedactedBundle({
  bundle: redacted,
  artefacts: [],
  publicKeyPem: "-----BEGIN PROOF LAYER ED25519 PUBLIC KEY-----\n...\n-----END PROOF LAYER ED25519 PUBLIC KEY-----\n"
});

const pack = await proofClient.createPack({
  packType: "annex_iv",
  systemId: "system-123",
  bundleFormat: "disclosure",
  disclosurePolicy: "annex_iv_redacted"
});
const templateCatalog = await proofClient.getDisclosureTemplates();
const renderedTemplate = await proofClient.renderDisclosureTemplate({
  profile: "privacy_review",
  name: "privacy_review_internal",
  redactionGroups: ["metadata"],
  redactedFieldsByItemType: {
    risk_assessment: ["/metadata/internal_notes"]
  }
});
await proofClient.updateDisclosureConfig({
  policies: [
    createDisclosurePolicyTemplate("runtime_minimum", {
      name: "runtime_minimum_internal",
      redactionGroups: ["metadata"]
    })
  ]
});
const preview = await proofClient.previewDisclosure({
  bundleId: "BUNDLE_ID",
  packType: "annex_iv",
  policy: {
    name: "risk_only",
    allowed_obligation_refs: ["art9"]
  }
});
const archive = await proofClient.downloadPackExport(pack.pack_id);

const generic = withGenericProofLayer(
  async (params) => ({ id: "generic-1", model: params.model, output_text: "ok" }),
  proofLayer,
  { provider: "custom-provider" }
);

const exporter = new ProofLayerExporter(proofLayer);
await exporter.captureToolEvents([], {
  provider: "openai",
  model: "gpt-4o-mini",
  input: [{ role: "user", content: "hi" }],
  output: { role: "assistant", content: "hello" }
});

const riskBundle = await proofLayer.captureRiskAssessment({
  riskId: "risk-42",
  severity: "medium",
  status: "mitigated",
  summary: "manual review added"
});

console.log(riskBundle.bundle?.items[0].type);
console.log(redactedSummary.disclosed_item_count, archive.length);
console.log(preview.disclosed_item_types);
console.log(templateCatalog.templates[0].profile, renderedTemplate.policy.name);
```
