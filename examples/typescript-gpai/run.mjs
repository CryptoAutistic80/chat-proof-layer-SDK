import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ProofLayer } from "../../sdks/typescript/dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vaultUrl = process.env.PROOF_SERVICE_URL ?? "http://127.0.0.1:8080";
const outputDir = path.join(__dirname, "artifacts");
const outputPath = path.join(outputDir, "annex-xi.pkg");

async function main() {
  const proofLayer = new ProofLayer({
    vaultUrl,
    appId: "typescript-gpai-example",
    env: "dev",
    systemId: "foundation-model-alpha",
    role: "provider",
    complianceProfile: {
      gpaiStatus: "provider",
      intendedUse: "General-purpose text and workflow assistance",
      deploymentContext: "eu_market_placement"
    }
  });

  const training = await proofLayer.captureTrainingProvenance({
    datasetRef: "dataset://foundation-model-alpha/pretrain-v5",
    stage: "pretraining",
    lineageRef: "lineage://foundation-model-alpha/2026-03-01",
    computeMetricsRef: "compute-foundation-alpha-v5",
    trainingDatasetSummary: "Multilingual curated web, code, and licensed reference corpora.",
    consortiumContext: "Single-provider training program",
    record: {
      manifests: 28,
      review_owner: "foundation-data-governance"
    }
  });

  const compute = await proofLayer.captureComputeMetrics({
    computeId: "compute-foundation-alpha-v5",
    trainingFlopsEstimate: "1.2e25",
    thresholdBasisRef: "art51_systemic_risk_threshold",
    thresholdValue: "1e25",
    thresholdStatus: "above_threshold",
    estimationMethodology: "Cluster scheduler logs and accelerator utilization rollup.",
    measuredAt: "2026-03-10T12:00:00Z",
    computeResourcesSummary: [
      { name: "gpu_hours", value: "42000", unit: "hours" },
      { name: "accelerator_count", value: "2048", unit: "gpus" }
    ],
    consortiumContext: "Single-provider training program",
    metadata: {
      owner: "foundation-ops"
    }
  });

  const pack = await proofLayer.createPack({
    packType: "annex_xi",
    systemId: "foundation-model-alpha",
    bundleFormat: "full"
  });
  const manifest = await proofLayer.getPackManifest(pack.pack_id);
  const exportBytes = await proofLayer.downloadPackExport(pack.pack_id);

  mkdirSync(outputDir, { recursive: true });
  writeFileSync(outputPath, Buffer.from(exportBytes));

  console.log("vault_url:", vaultUrl);
  console.log("captured_bundle_ids:", [training.bundleId, compute.bundleId].join(", "));
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
