import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ProofLayer } from "../../sdks/typescript/dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vaultUrl = process.env.PROOF_SERVICE_URL ?? "http://127.0.0.1:8080";
const outputDir = path.join(__dirname, "artifacts");
const outputPath = path.join(outputDir, "post-market-monitoring.pkg");

async function main() {
  const proofLayer = new ProofLayer({
    vaultUrl,
    appId: "typescript-monitoring-example",
    env: "dev",
    systemId: "claims-assistant",
    role: "provider",
    complianceProfile: {
      intendedUse: "Claims triage support with human review",
      prohibitedPracticeScreening: "screened_no_prohibited_use",
      riskTier: "high_risk",
      deploymentContext: "eu_market_placement",
      metadata: {
        owner: "safety-ops",
        market: "eu"
      }
    }
  });

  const interaction = await proofLayer.capture({
    provider: "demo-provider",
    model: "claims-model-v2",
    requestId: "req-claims-001",
    input: {
      claimId: "claim-42",
      prompt: "Summarize the claim for a human reviewer and flag missing documents."
    },
    output: {
      summary: "Missing discharge letter. Human review required before recommendation."
    },
    retentionClass: "runtime_logs"
  });

  const monitoring = await proofLayer.capturePostMarketMonitoring({
    planId: "pmm-claims-2026-03",
    status: "active",
    summary: "Weekly drift review with incident escalation thresholds for adverse outcomes.",
    report: {
      cadence: "weekly",
      owner: "safety-ops",
      metrics: ["false_negative_rate", "appeal_rate"]
    },
    retentionClass: "risk_mgmt"
  });

  const incident = await proofLayer.captureIncidentReport({
    incidentId: "inc-claims-42",
    severity: "serious",
    status: "open",
    occurredAt: "2026-03-08T07:15:00Z",
    summary: "Potentially adverse recommendation surfaced in a sensitive claims case.",
    detectionMethod: "post_market_monitoring",
    rootCauseSummary: "Missing-document threshold was too permissive for a narrow claims segment.",
    authorityNotificationRequired: true,
    authorityNotificationStatus: "drafted",
    report: {
      owner: "incident-ops",
      corrective_action_ref: "ca-claims-42"
    },
    retentionClass: "risk_mgmt"
  });

  const notification = await proofLayer.captureAuthorityNotification({
    notificationId: "notif-claims-42",
    authority: "eu_ai_office",
    status: "drafted",
    incidentId: "inc-claims-42",
    dueAt: "2026-03-10T12:00:00Z",
    report: {
      article: "73",
      summary: "Initial authority notification for claims incident review."
    },
    retentionClass: "risk_mgmt"
  });

  const submission = await proofLayer.captureAuthoritySubmission({
    submissionId: "sub-claims-42",
    authority: "eu_ai_office",
    status: "submitted",
    channel: "portal",
    submittedAt: "2026-03-08T09:30:00Z",
    document: {
      incidentId: "inc-claims-42",
      article: "73",
      summary: "Initial notification package for monitoring follow-up."
    },
    retentionClass: "risk_mgmt"
  });

  const pack = await proofLayer.createPack({
    packType: "post_market_monitoring",
    systemId: "claims-assistant",
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
      interaction.bundleId,
      monitoring.bundleId,
      incident.bundleId,
      notification.bundleId,
      submission.bundleId
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
