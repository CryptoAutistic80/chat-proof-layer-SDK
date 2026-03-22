import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ProofLayer } from "../../sdks/typescript/dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vaultUrl = process.env.PROOF_SERVICE_URL ?? "http://127.0.0.1:8080";
const fixtureDir = path.join(__dirname, "..", "..", "fixtures", "golden", "annex_iv_governance");
const outputDir = path.join(__dirname, "artifacts");
const fullOutputPath = path.join(outputDir, "annex-iv-full.pack");
const disclosureOutputPath = path.join(outputDir, "annex-iv-disclosure.pack");

function loadFixture(name) {
  return JSON.parse(readFileSync(path.join(fixtureDir, name), "utf8"));
}

async function main() {
  const proofLayer = new ProofLayer({
    vaultUrl,
    appId: "typescript-annex-iv-example",
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

  const technicalDocFixture = loadFixture("technical_doc.json");
  const riskFixture = loadFixture("risk_assessment.json");
  const dataFixture = loadFixture("data_governance.json");
  const instructionsFixture = loadFixture("instructions_for_use.json");
  const oversightFixture = loadFixture("human_oversight.json");
  const qmsFixture = loadFixture("qms_record.json");
  const standardsFixture = loadFixture("standards_alignment.json");
  const monitoringFixture = loadFixture("post_market_monitoring.json");

  const technicalDoc = await proofLayer.captureTechnicalDoc({
    documentRef: technicalDocFixture.document_ref,
    section: technicalDocFixture.section,
    annexIvSections: technicalDocFixture.annex_iv_sections,
    systemDescriptionSummary: technicalDocFixture.system_description_summary,
    modelDescriptionSummary: technicalDocFixture.model_description_summary,
    capabilitiesAndLimitations: technicalDocFixture.capabilities_and_limitations,
    designChoicesSummary: technicalDocFixture.design_choices_summary,
    evaluationMetricsSummary: technicalDocFixture.evaluation_metrics_summary,
    humanOversightDesignSummary: technicalDocFixture.human_oversight_design_summary,
    postMarketMonitoringPlanRef: technicalDocFixture.post_market_monitoring_plan_ref,
    descriptor: {
      owner: "quality-team",
      document_class: "annex_iv_system_card"
    },
    modelId: "hiring-model-v3",
    version: "2026.03",
    retentionClass: "technical_doc"
  });

  const riskAssessment = await proofLayer.captureRiskAssessment({
    riskId: riskFixture.risk_id,
    severity: riskFixture.severity,
    status: riskFixture.status,
    summary: riskFixture.summary,
    riskDescription: riskFixture.risk_description,
    likelihood: riskFixture.likelihood,
    affectedGroups: riskFixture.affected_groups,
    mitigationMeasures: riskFixture.mitigation_measures,
    residualRiskLevel: riskFixture.residual_risk_level,
    riskOwner: riskFixture.risk_owner,
    vulnerableGroupsConsidered: riskFixture.vulnerable_groups_considered,
    testResultsSummary: riskFixture.test_results_summary,
    metadata: riskFixture.metadata,
    modelId: "hiring-model-v3",
    version: "2026.03",
    retentionClass: "risk_mgmt"
  });

  const dataGovernance = await proofLayer.captureDataGovernance({
    decision: dataFixture.decision,
    datasetRef: dataFixture.dataset_ref,
    datasetName: dataFixture.dataset_name,
    datasetVersion: dataFixture.dataset_version,
    sourceDescription: dataFixture.source_description,
    collectionPeriod: dataFixture.collection_period,
    geographicalScope: dataFixture.geographical_scope,
    preprocessingOperations: dataFixture.preprocessing_operations,
    biasDetectionMethodology: dataFixture.bias_detection_methodology,
    biasMetrics: dataFixture.bias_metrics,
    mitigationActions: dataFixture.mitigation_actions,
    dataGaps: dataFixture.data_gaps,
    personalDataCategories: dataFixture.personal_data_categories,
    safeguards: dataFixture.safeguards,
    metadata: dataFixture.metadata,
    modelId: "hiring-model-v3",
    version: "2026.03",
    retentionClass: "technical_doc"
  });

  const instructionsForUse = await proofLayer.captureInstructionsForUse({
    documentRef: instructionsFixture.document_ref,
    versionTag: instructionsFixture.version,
    section: instructionsFixture.section,
    providerIdentity: instructionsFixture.provider_identity,
    intendedPurpose: instructionsFixture.intended_purpose,
    systemCapabilities: instructionsFixture.system_capabilities,
    accuracyMetrics: instructionsFixture.accuracy_metrics,
    foreseeableRisks: instructionsFixture.foreseeable_risks,
    explainabilityCapabilities: instructionsFixture.explainability_capabilities,
    humanOversightGuidance: instructionsFixture.human_oversight_guidance,
    computeRequirements: instructionsFixture.compute_requirements,
    serviceLifetime: instructionsFixture.service_lifetime,
    logManagementGuidance: instructionsFixture.log_management_guidance,
    metadata: instructionsFixture.metadata,
    modelId: "hiring-model-v3",
    version: "2026.03",
    retentionClass: "technical_doc"
  });

  const humanOversight = await proofLayer.captureHumanOversight({
    action: oversightFixture.action,
    reviewer: oversightFixture.reviewer,
    actorRole: oversightFixture.actor_role,
    anomalyDetected: oversightFixture.anomaly_detected,
    overrideAction: oversightFixture.override_action,
    interpretationGuidanceFollowed: oversightFixture.interpretation_guidance_followed,
    automationBiasDetected: oversightFixture.automation_bias_detected,
    twoPersonVerification: oversightFixture.two_person_verification,
    stopTriggered: oversightFixture.stop_triggered,
    stopReason: oversightFixture.stop_reason,
    notes: {
      escalation_path: "quality-panel",
      sla_hours: 24
    },
    modelId: "hiring-model-v3",
    version: "2026.03",
    retentionClass: "risk_mgmt"
  });

  const qmsRecord = await proofLayer.captureQmsRecord({
    recordId: qmsFixture.record_id,
    process: qmsFixture.process,
    status: qmsFixture.status,
    policyName: qmsFixture.policy_name,
    revision: qmsFixture.revision,
    effectiveDate: qmsFixture.effective_date,
    scope: qmsFixture.scope,
    auditResultsSummary: qmsFixture.audit_results_summary,
    continuousImprovementActions: qmsFixture.continuous_improvement_actions,
    metadata: qmsFixture.metadata,
    modelId: "hiring-model-v3",
    version: "2026.03",
    retentionClass: "technical_doc"
  });

  const standardsAlignment = await proofLayer.captureStandardsAlignment({
    standardRef: standardsFixture.standard_ref,
    status: standardsFixture.status,
    scope: standardsFixture.scope,
    metadata: standardsFixture.metadata,
    modelId: "hiring-model-v3",
    version: "2026.03",
    retentionClass: "technical_doc"
  });

  const postMarketMonitoring = await proofLayer.capturePostMarketMonitoring({
    planId: monitoringFixture.plan_id,
    status: monitoringFixture.status,
    summary: monitoringFixture.summary,
    metadata: monitoringFixture.metadata,
    modelId: "hiring-model-v3",
    version: "2026.03",
    retentionClass: "risk_mgmt"
  });

  const preview = await proofLayer.previewDisclosure({
    bundleId: dataGovernance.bundleId,
    packType: "annex_iv",
    disclosurePolicy: "annex_iv_redacted"
  });

  const fullPack = await proofLayer.createPack({
    packType: "annex_iv",
    systemId: "hiring-assistant",
    bundleFormat: "full"
  });
  const disclosurePack = await proofLayer.createPack({
    packType: "annex_iv",
    systemId: "hiring-assistant",
    bundleFormat: "disclosure",
    disclosurePolicy: "annex_iv_redacted"
  });

  const fullManifest = await proofLayer.getPackManifest(fullPack.pack_id);
  const disclosureManifest = await proofLayer.getPackManifest(disclosurePack.pack_id);
  const fullExportBytes = await proofLayer.downloadPackExport(fullPack.pack_id);
  const disclosureExportBytes = await proofLayer.downloadPackExport(disclosurePack.pack_id);

  mkdirSync(outputDir, { recursive: true });
  writeFileSync(fullOutputPath, Buffer.from(fullExportBytes));
  writeFileSync(disclosureOutputPath, Buffer.from(disclosureExportBytes));

  console.log("vault_url:", vaultUrl);
  console.log(
    "captured_bundle_ids:",
    [
      technicalDoc.bundleId,
      riskAssessment.bundleId,
      dataGovernance.bundleId,
      instructionsForUse.bundleId,
      humanOversight.bundleId,
      qmsRecord.bundleId,
      standardsAlignment.bundleId,
      postMarketMonitoring.bundleId
    ].join(", ")
  );
  console.log("preview_policy:", preview.policy_name);
  console.log("preview_item_types:", preview.disclosed_item_types.join(", "));
  console.log(
    "preview_field_redactions:",
    JSON.stringify(preview.disclosed_item_field_redactions ?? {})
  );
  console.log("full_pack_id:", fullPack.pack_id);
  console.log("full_manifest_items:", fullManifest.bundles.map((entry) => entry.item_types[0]).join(", "));
  console.log("full_export_path:", fullOutputPath);
  console.log("disclosure_pack_id:", disclosurePack.pack_id);
  console.log(
    "disclosure_manifest_items:",
    disclosureManifest.bundles.map((entry) => entry.item_types[0]).join(", ")
  );
  console.log("disclosure_export_path:", disclosureOutputPath);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
