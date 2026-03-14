import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ProofLayer } from "../../sdks/typescript/dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vaultUrl = process.env.PROOF_SERVICE_URL ?? "http://127.0.0.1:8080";
const outputDir = path.join(__dirname, "artifacts");
const outputPath = path.join(outputDir, "provider-governance.pkg");

async function main() {
  const proofLayer = new ProofLayer({
    vaultUrl,
    appId: "typescript-provider-governance-example",
    env: "dev",
    systemId: "hiring-assistant",
    role: "provider",
    complianceProfile: {
      intendedUse: "Recruiter support for first-pass candidate review",
      prohibitedPracticeScreening: "screened_no_prohibited_use",
      riskTier: "high_risk",
      highRiskDomain: "employment",
      deploymentContext: "eu_market_placement",
      metadata: {
        owner: "quality-team",
        market: "eu"
      }
    }
  });

  const interaction = await proofLayer.capture({
    provider: "demo-provider",
    model: "hiring-model-v3",
    requestId: "req-hiring-001",
    input: {
      candidateId: "cand-42",
      prompt: "Summarize the candidate profile for a human recruiter."
    },
    output: {
      summary: "Strong match for the role, pending human review for edge-case criteria."
    },
    retentionClass: "runtime_logs"
  });

  const instructions = await proofLayer.captureInstructionsForUse({
    documentRef: "docs://hiring-assistant/operator-handbook",
    versionTag: "2026.03",
    section: "human-review-required",
    document: {
      summary: "Operators must review all negative or borderline candidate recommendations.",
      owner: "product-compliance"
    },
    retentionClass: "technical_doc"
  });

  const qmsRecord = await proofLayer.captureQmsRecord({
    recordId: "qms-release-approval-42",
    process: "release_approval",
    status: "approved",
    record: {
      approver: "quality-lead",
      gate: "release",
      release: "2026.03"
    },
    retentionClass: "technical_doc"
  });

  const pack = await proofLayer.createPack({
    packType: "provider_governance",
    systemId: "hiring-assistant",
    bundleFormat: "full"
  });
  const manifest = await proofLayer.getPackManifest(pack.pack_id);
  const exportBytes = await proofLayer.downloadPackExport(pack.pack_id);

  mkdirSync(outputDir, { recursive: true });
  writeFileSync(outputPath, Buffer.from(exportBytes));

  console.log("vault_url:", vaultUrl);
  console.log(
    "captured_bundle_ids:",
    [interaction.bundleId, instructions.bundleId, qmsRecord.bundleId].join(", ")
  );
  console.log("pack_id:", pack.pack_id);
  console.log("pack_type:", manifest.pack_type);
  console.log("manifest_bundle_count:", manifest.bundles.length);
  console.log(
    "manifest_items:",
    manifest.bundles.map((entry) => `${entry.bundle_id}:${entry.item_types.join("+")}`).join(", ")
  );
  console.log("export_path:", outputPath);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
