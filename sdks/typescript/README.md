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

## Quick Start (Chat Session)

```ts
import { ProofLayer, withProofLayer } from "@proof-layer/sdk/chat";

const proofLayer = ProofLayer.load({
  vaultUrl: "http://127.0.0.1:8080",
  appId: "typescript-demo",
  env: "dev"
});

const wrapped = withProofLayer(openaiClient, proofLayer);
const completion = await wrapped.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "Say hello" }]
});

console.log(completion.proofLayer.bundleId);
```

For lifecycle/compliance captures (risk, QMS, declarations, etc.), import from `@proof-layer/sdk/advanced`.

## Advanced Usage

Use `@proof-layer/sdk/advanced` for non-chat builders and lifecycle capture workflows.
