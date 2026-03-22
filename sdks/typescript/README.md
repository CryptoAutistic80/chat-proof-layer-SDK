# @proof-layer/sdk (TypeScript SDK)

TypeScript SDK for creating Proof Layer evidence bundles around model calls.
Integrity-sensitive helpers are backed by the local Rust NAPI module in `crates/napi`, while the package surface stays TypeScript-first.

The SDK now has typed builders and `ProofLayer` convenience methods for every evidence item currently implemented in Rust core: `llm_interaction`, `tool_call`, `retrieval`, `human_oversight`, `policy_decision`, `risk_assessment`, `data_governance`, `technical_doc`, `instructions_for_use`, `qms_record`, `fundamental_rights_assessment`, `standards_alignment`, `post_market_monitoring`, `corrective_action`, `authority_notification`, `authority_submission`, `reporting_deadline`, `regulator_correspondence`, `model_evaluation`, `adversarial_test`, `training_provenance`, `compute_metrics`, `downstream_documentation`, `copyright_policy`, `training_summary`, `literacy_attestation`, `incident_report`, `conformity_assessment`, `declaration`, and `registration`.
The GPAI helpers default `model_evaluation`, `adversarial_test`, `training_provenance`, and `compute_metrics` captures to the vault's `gpai_documentation` retention class.

## Install

Use one of these paths:

- local repo build: `npm install && npm run build`
- checked release tarball: install the OS-matching `.tgz` asset attached to a `sdk-v*` GitHub release

The package is not published to the public npm registry yet because the current release artifact embeds a platform-specific native N-API module.

## Build Native Bindings

```bash
npm install
npm run build
```

## Build A Checked Package Artifact

```bash
npm run pack:smoke
```

This produces a tarball under `dist/artifacts/` and verifies that the package contains compiled `dist/*` output plus `native/proof-layer-napi.node`. The packaging path defaults to `PROOF_SDK_NATIVE_PROFILE=release`.

The repo’s `.github/workflows/sdk-artifacts.yml` workflow runs the same checked tarball build on Linux, macOS, and Windows, and `.github/workflows/sdk-release.yml` attaches those tarballs to GitHub releases for `sdk-v*` tags.

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
  selectPackReadiness,
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

const readiness = await proofLayer.evaluateCompleteness({
  bundle: locallySealed.bundle,
  profile: "annex_iv_governance_v1"
});

const providerGovernanceReadiness = await proofLayer.evaluateCompleteness({
  // fullProviderGovernanceBundle should contain the provider-side governance evidence set.
  bundle: fullProviderGovernanceBundle,
  profile: "provider_governance_v1"
});

const gpaiReadiness = await proofLayer.evaluateCompleteness({
  // fullGpaiProviderBundle should contain the full structured GPAI provider evidence set.
  bundle: fullGpaiProviderBundle,
  profile: "gpai_provider_v1"
});

const friaReadiness = await proofLayer.evaluateCompleteness({
  // fullFundamentalRightsBundle should contain the deployer-side FRIA assessment + oversight evidence set.
  bundle: fullFundamentalRightsBundle,
  profile: "fundamental_rights_v1"
});
const monitoringReadiness = await proofLayer.evaluateCompleteness({
  // fullPostMarketMonitoringBundle should contain the monitoring, incident, corrective-action, and authority-reporting evidence set.
  bundle: fullPostMarketMonitoringBundle,
  profile: "post_market_monitoring_v1"
});

const timestampCheck = await proofClient.verifyTimestamp({
  bundleId: "BUNDLE_ID"
});

const receiptCheck = await proofClient.verifyReceipt({
  bundleId: "BUNDLE_ID",
  liveCheckMode: "best_effort"
});

const summary = verifyBundle({
  bundle: locallySealed.bundle,
  artefacts: [{ name: "prompt.json", data: Buffer.from("{}") }],
  publicKeyPem: "-----BEGIN PROOF LAYER ED25519 PUBLIC KEY-----\n...\n-----END PROOF LAYER ED25519 PUBLIC KEY-----\n"
});

console.log(summary.artefact_count);
console.log(readiness.status);
console.log(gpaiReadiness.status);
console.log(timestampCheck.assessment.headline, timestampCheck.assessment.level);
console.log(receiptCheck.assessment.summary, receiptCheck.assessment.live_check?.state);
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
const templatePack = await proofClient.createPack({
  packType: "runtime_logs",
  systemId: "system-123",
  bundleFormat: "disclosure",
  disclosureTemplate: {
    profile: "runtime_minimum",
    name: "runtime_minimum_export",
    redactionGroups: ["metadata"]
  }
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
const templatePreview = await proofClient.previewDisclosure({
  bundleId: "BUNDLE_ID",
  packType: "runtime_logs",
  disclosureTemplate: {
    profile: "privacy_review",
    name: "privacy_review_internal",
    redactionGroups: ["metadata"]
  }
});
const archive = await proofClient.downloadPackExport(pack.pack_id);
const vaultReadiness = await proofClient.evaluateCompleteness({
  bundleId: "BUNDLE_ID",
  profile: "annex_iv_governance_v1"
});

const annexXiPackReadiness = await proofClient.evaluateCompleteness({
  packId: "PACK_ID",
  profile: "gpai_provider_v1"
});
const providerGovernancePackReadiness = await proofClient.evaluateCompleteness({
  packId: "PACK_ID",
  profile: "provider_governance_v1"
});
const fundamentalRightsPackReadiness = await proofClient.evaluateCompleteness({
  packId: "PACK_ID",
  profile: "fundamental_rights_v1"
});
const monitoringPackReadiness = await proofClient.evaluateCompleteness({
  packId: "PACK_ID",
  profile: "post_market_monitoring_v1"
});
const packReadiness = selectPackReadiness(pack);

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
console.log(templatePack.pack_id, templatePreview.disclosedItemTypes);
console.log(templateCatalog.templates[0].profile, renderedTemplate.policy.name);
console.log(annexXiPackReadiness.status, providerGovernancePackReadiness.status);
console.log(monitoringReadiness.status, monitoringPackReadiness.status);
console.log(packReadiness?.source, packReadiness?.status);
console.log(vaultReadiness.status);
```

Vault pack responses preserve the legacy per-bundle `completeness_*` fields and add `pack_completeness_*` when a pack has synthesized pack-level readiness support.
Use `selectPackReadiness(packSummaryOrManifest)` when you want one helper that prefers the true pack-scoped signal (`source === "pack_scoped"`) and falls back to the legacy bundle aggregate signal (`source === "bundle_aggregate"`).

Vault verification responses now also include a plain-English `assessment` block.
Use `verifyTimestamp(...)` and `verifyReceipt(...)` when you want both the low-level crypto result and a short human-readable trust summary.
For receipts, `liveCheckMode: "best_effort"` adds an opt-in live Rekor freshness check without turning temporary network problems into a hard failure.

For `annex_iv`, the pack-scoped pass count is currently `8` because `annex_iv_governance_v1` now evaluates the full governance set curated by the pack.
For `provider_governance`, the pack-scoped pass count is currently `8` because `provider_governance_v1` evaluates the provider-side governance set curated by that pack, including corrective action follow-up.
For `post_market_monitoring`, the pack-scoped pass count is currently `6` because `post_market_monitoring_v1` evaluates the required monitoring and authority-reporting rule families.

For the full provider-side Annex IV governance walkthrough, build the SDK and run:

```bash
npm --prefix sdks/typescript build
node examples/typescript-compliance/run.mjs
```

That example captures the checked governance set, previews `annex_iv_redacted`, and exports both full and disclosure-format `annex_iv` packs.
