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

  const technicalDoc = await proofLayer.captureTechnicalDoc({
    documentRef: "docs://foundation-model-alpha/gpai-provider-overview",
    section: "provider_overview",
    annexIvSections: ["annex_xi_section_1", "annex_xi_section_2"],
    systemDescriptionSummary:
      "General-purpose text and workflow assistance model offered by the provider for EU market placement and downstream integration.",
    modelDescriptionSummary:
      "Foundation-model provider workflow for multilingual text generation and downstream enterprise assistance use cases.",
    capabilitiesAndLimitations:
      "Supports broad text and workflow tasks, but threshold tracking, evaluation coverage, and downstream documentation still govern safe release and use.",
    designChoicesSummary:
      "The provider file emphasizes lineage traceability, compute-threshold tracking, model evaluation, and publishable transparency outputs.",
    evaluationMetricsSummary:
      "Capability, multilingual quality, and policy-adherence metrics are reviewed before release and whenever material training updates occur.",
    humanOversightDesignSummary:
      "Provider release review gates publish model updates only after documented evaluation, threshold, and policy checks are complete.",
    postMarketMonitoringPlanRef: "gpai://foundation-model-alpha/provider-monitoring-2026-03",
    descriptor: {
      owner: "foundation-ops",
      document_class: "gpai_provider_system_card"
    },
    modelId: "foundation-model-alpha-model-v3",
    version: "2026.03",
    retentionClass: "gpai_documentation"
  });

  const evaluation = await proofLayer.captureModelEvaluation({
    evaluationId: "eval-foundation-model-alpha-provider-2026-03",
    benchmark: "gpai_provider_release_suite",
    status: "passed_with_follow_up",
    summary:
      "Pre-release GPAI provider evaluation covered multilingual capability, policy adherence, and threshold-sensitive release checks.",
    metricsSummary: [
      { name: "instruction_following", value: "0.91", unit: "score" },
      { name: "policy_adherence", value: "0.97", unit: "score" },
      { name: "multilingual_quality", value: "0.88", unit: "score" }
    ],
    groupPerformance: [
      { group: "en", summary: "Stable quality across enterprise help-desk and drafting tasks." },
      { group: "fr_de_es", summary: "Slightly lower quality, but within release threshold." }
    ],
    evaluationMethodology:
      "Combination of scripted benchmark runs, reviewer spot checks, and release-gate policy tests.",
    report: {
      owner: "foundation-ops",
      benchmark_suite: "gpai-provider-eval-2026-03",
      release: "2026.03"
    },
    metadata: {
      owner: "foundation-ops",
      market: "eu"
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

  const copyrightPolicy = await proofLayer.captureCopyrightPolicy({
    policyRef: "policy://foundation-model-alpha/copyright-compliance",
    status: "approved",
    jurisdiction: "EU",
    document: {
      owner: "foundation-ops",
      policy_version: "2026.03",
      review_cycle: "quarterly"
    },
    metadata: {
      owner: "foundation-ops",
      market: "eu"
    }
  });

  const trainingSummary = await proofLayer.captureTrainingSummary({
    summaryRef: "summary://foundation-model-alpha/training-2026-03",
    status: "published",
    audience: "public",
    document: {
      owner: "foundation-ops",
      publication_status: "ready_for_release",
      dataset_summary: "Multilingual curated web, code, and licensed reference corpora."
    },
    metadata: {
      owner: "foundation-ops",
      market: "eu"
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
  console.log(
    "captured_bundle_ids:",
    [
      technicalDoc.bundleId,
      evaluation.bundleId,
      training.bundleId,
      compute.bundleId,
      copyrightPolicy.bundleId,
      trainingSummary.bundleId
    ].join(", ")
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
