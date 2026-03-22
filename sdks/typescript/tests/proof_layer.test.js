import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ProofLayer } from "../dist/index.js";
import { withProofLayer } from "../dist/providers/openai.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../..");
const goldenDir = path.join(repoRoot, "fixtures", "golden");
const annexIvDir = path.join(goldenDir, "annex_iv_governance");
const gpaiDir = path.join(goldenDir, "gpai_provider");
const incidentResponseDir = path.join(goldenDir, "incident_response");
const monitoringDir = path.join(goldenDir, "post_market_monitoring");
const providerGovernanceDir = path.join(goldenDir, "provider_governance");
const conformityDir = path.join(goldenDir, "conformity");

async function annexIvBundle() {
  const [
    riskAssessment,
    dataGovernance,
    technicalDoc,
    instructionsForUse,
    humanOversight,
    qmsRecord,
    standardsAlignment,
    postMarketMonitoring,
  ] = await Promise.all([
    readFile(path.join(annexIvDir, "risk_assessment.json"), "utf8"),
    readFile(path.join(annexIvDir, "data_governance.json"), "utf8"),
    readFile(path.join(annexIvDir, "technical_doc.json"), "utf8"),
    readFile(path.join(annexIvDir, "instructions_for_use.json"), "utf8"),
    readFile(path.join(annexIvDir, "human_oversight.json"), "utf8"),
    readFile(path.join(annexIvDir, "qms_record.json"), "utf8"),
    readFile(path.join(annexIvDir, "standards_alignment.json"), "utf8"),
    readFile(path.join(annexIvDir, "post_market_monitoring.json"), "utf8"),
  ]);

  return {
    bundle_version: "1.0",
    bundle_id: "B-annex-iv",
    created_at: "2026-03-21T00:00:00Z",
    actor: {
      issuer: "proof-layer-test",
      app_id: "typescript-sdk",
      env: "test",
      signing_key_id: "kid-dev-01",
      role: "provider",
    },
    subject: {
      system_id: "hiring-assistant",
    },
    context: {},
    items: [
      { type: "technical_doc", data: JSON.parse(technicalDoc) },
      { type: "risk_assessment", data: JSON.parse(riskAssessment) },
      { type: "data_governance", data: JSON.parse(dataGovernance) },
      { type: "instructions_for_use", data: JSON.parse(instructionsForUse) },
      { type: "human_oversight", data: JSON.parse(humanOversight) },
      { type: "qms_record", data: JSON.parse(qmsRecord) },
      { type: "standards_alignment", data: JSON.parse(standardsAlignment) },
      {
        type: "post_market_monitoring",
        data: JSON.parse(postMarketMonitoring),
      },
    ],
    artefacts: [],
    policy: {
      redactions: [],
      encryption: { enabled: false },
    },
    integrity: {
      canonicalization: "RFC8785-JCS",
      hash: "SHA-256",
      header_digest:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      bundle_root_algorithm: "pl-merkle-sha256-v4",
      bundle_root:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      signature: {
        format: "JWS",
        alg: "EdDSA",
        kid: "kid-dev-01",
        value: "sig",
      },
    },
  };
}

async function gpaiProviderBundle() {
  const [
    technicalDoc,
    modelEvaluation,
    trainingProvenance,
    computeMetrics,
    copyrightPolicy,
    trainingSummary,
  ] = await Promise.all([
    readFile(path.join(gpaiDir, "technical_doc.json"), "utf8"),
    readFile(path.join(gpaiDir, "model_evaluation.json"), "utf8"),
    readFile(path.join(gpaiDir, "training_provenance.json"), "utf8"),
    readFile(path.join(gpaiDir, "compute_metrics.json"), "utf8"),
    readFile(path.join(gpaiDir, "copyright_policy.json"), "utf8"),
    readFile(path.join(gpaiDir, "training_summary.json"), "utf8"),
  ]);

  return {
    bundle_version: "1.0",
    bundle_id: "B-gpai-provider",
    created_at: "2026-03-21T00:00:00Z",
    actor: {
      issuer: "proof-layer-test",
      app_id: "typescript-sdk",
      env: "test",
      signing_key_id: "kid-dev-01",
      role: "provider",
    },
    subject: {
      system_id: "foundation-model-alpha",
    },
    context: {},
    items: [
      { type: "technical_doc", data: JSON.parse(technicalDoc) },
      { type: "model_evaluation", data: JSON.parse(modelEvaluation) },
      { type: "training_provenance", data: JSON.parse(trainingProvenance) },
      { type: "compute_metrics", data: JSON.parse(computeMetrics) },
      { type: "copyright_policy", data: JSON.parse(copyrightPolicy) },
      { type: "training_summary", data: JSON.parse(trainingSummary) },
    ],
    artefacts: [],
    policy: {
      redactions: [],
      encryption: { enabled: false },
    },
    integrity: {
      canonicalization: "RFC8785-JCS",
      hash: "SHA-256",
      header_digest:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      bundle_root_algorithm: "pl-merkle-sha256-v4",
      bundle_root:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      signature: {
        format: "JWS",
        alg: "EdDSA",
        kid: "kid-dev-01",
        value: "sig",
      },
    },
  };
}

async function providerGovernanceBundle() {
  const [
    riskAssessment,
    dataGovernance,
    technicalDoc,
    instructionsForUse,
    qmsRecord,
    standardsAlignment,
    postMarketMonitoring,
    correctiveAction,
  ] = await Promise.all([
    readFile(path.join(providerGovernanceDir, "risk_assessment.json"), "utf8"),
    readFile(path.join(providerGovernanceDir, "data_governance.json"), "utf8"),
    readFile(path.join(providerGovernanceDir, "technical_doc.json"), "utf8"),
    readFile(
      path.join(providerGovernanceDir, "instructions_for_use.json"),
      "utf8",
    ),
    readFile(path.join(providerGovernanceDir, "qms_record.json"), "utf8"),
    readFile(
      path.join(providerGovernanceDir, "standards_alignment.json"),
      "utf8",
    ),
    readFile(
      path.join(providerGovernanceDir, "post_market_monitoring.json"),
      "utf8",
    ),
    readFile(
      path.join(providerGovernanceDir, "corrective_action.json"),
      "utf8",
    ),
  ]);

  return {
    bundle_version: "1.0",
    bundle_id: "B-provider-governance",
    created_at: "2026-03-22T12:00:00Z",
    actor: {
      issuer: "proof-layer-test",
      app_id: "typescript-sdk",
      env: "test",
      signing_key_id: "kid-dev-01",
      role: "provider",
    },
    subject: {
      system_id: "hiring-assistant",
    },
    context: {},
    items: [
      { type: "technical_doc", data: JSON.parse(technicalDoc) },
      { type: "risk_assessment", data: JSON.parse(riskAssessment) },
      { type: "data_governance", data: JSON.parse(dataGovernance) },
      { type: "instructions_for_use", data: JSON.parse(instructionsForUse) },
      { type: "qms_record", data: JSON.parse(qmsRecord) },
      { type: "standards_alignment", data: JSON.parse(standardsAlignment) },
      {
        type: "post_market_monitoring",
        data: JSON.parse(postMarketMonitoring),
      },
      { type: "corrective_action", data: JSON.parse(correctiveAction) },
    ],
    artefacts: [],
    policy: {
      redactions: [],
      encryption: { enabled: false },
    },
    integrity: {
      canonicalization: "RFC8785-JCS",
      hash: "SHA-256",
      header_digest:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      bundle_root_algorithm: "pl-merkle-sha256-v4",
      bundle_root:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      signature: {
        format: "JWS",
        alg: "EdDSA",
        kid: "kid-dev-01",
        value: "sig",
      },
    },
  };
}

async function conformityBundle() {
  const [conformityAssessment, declaration, registration] = await Promise.all([
    readFile(path.join(conformityDir, "conformity_assessment.json"), "utf8"),
    readFile(path.join(conformityDir, "declaration.json"), "utf8"),
    readFile(path.join(conformityDir, "registration.json"), "utf8"),
  ]);

  return {
    bundle_version: "1.0",
    bundle_id: "B-conformity",
    created_at: "2026-03-22T15:00:00Z",
    actor: {
      issuer: "proof-layer-test",
      app_id: "typescript-sdk",
      env: "test",
      signing_key_id: "kid-dev-01",
      role: "provider",
    },
    subject: {
      system_id: "system-conformity",
    },
    context: {},
    items: [
      {
        type: "conformity_assessment",
        data: JSON.parse(conformityAssessment),
      },
      { type: "declaration", data: JSON.parse(declaration) },
      { type: "registration", data: JSON.parse(registration) },
    ],
    artefacts: [],
    policy: {
      redactions: [],
      encryption: { enabled: false },
    },
    integrity: {
      canonicalization: "RFC8785-JCS",
      hash: "SHA-256",
      header_digest:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      bundle_root_algorithm: "pl-merkle-sha256-v4",
      bundle_root:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      signature: {
        format: "JWS",
        alg: "EdDSA",
        kid: "kid-dev-01",
        value: "sig",
      },
    },
  };
}

async function postMarketMonitoringBundle() {
  const [
    monitoring,
    incidentReport,
    correctiveAction,
    authorityNotification,
    authoritySubmission,
    reportingDeadline,
  ] = await Promise.all([
    readFile(path.join(monitoringDir, "post_market_monitoring.json"), "utf8"),
    readFile(path.join(monitoringDir, "incident_report.json"), "utf8"),
    readFile(path.join(monitoringDir, "corrective_action.json"), "utf8"),
    readFile(path.join(monitoringDir, "authority_notification.json"), "utf8"),
    readFile(path.join(monitoringDir, "authority_submission.json"), "utf8"),
    readFile(path.join(monitoringDir, "reporting_deadline.json"), "utf8"),
  ]);

  return {
    bundle_version: "1.0",
    bundle_id: "B-post-market-monitoring",
    created_at: "2026-03-22T00:00:00Z",
    actor: {
      issuer: "proof-layer-test",
      app_id: "typescript-sdk",
      env: "test",
      signing_key_id: "kid-dev-01",
      role: "provider",
    },
    subject: {
      system_id: "claims-assistant",
    },
    context: {},
    items: [
      { type: "post_market_monitoring", data: JSON.parse(monitoring) },
      { type: "incident_report", data: JSON.parse(incidentReport) },
      { type: "corrective_action", data: JSON.parse(correctiveAction) },
      {
        type: "authority_notification",
        data: JSON.parse(authorityNotification),
      },
      {
        type: "authority_submission",
        data: JSON.parse(authoritySubmission),
      },
      { type: "reporting_deadline", data: JSON.parse(reportingDeadline) },
    ],
    artefacts: [],
    policy: {
      redactions: [],
      encryption: { enabled: false },
    },
    integrity: {
      canonicalization: "RFC8785-JCS",
      hash: "SHA-256",
      header_digest:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      bundle_root_algorithm: "pl-merkle-sha256-v4",
      bundle_root:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      signature: {
        format: "JWS",
        alg: "EdDSA",
        kid: "kid-dev-01",
        value: "sig",
      },
    },
  };
}

async function incidentResponseBundle() {
  const [
    technicalDoc,
    riskAssessment,
    humanOversight,
    policyDecision,
    incidentReport,
    correctiveAction,
    authorityNotification,
    authoritySubmission,
    reportingDeadline,
    regulatorCorrespondence,
  ] = await Promise.all([
    readFile(path.join(incidentResponseDir, "technical_doc.json"), "utf8"),
    readFile(path.join(incidentResponseDir, "risk_assessment.json"), "utf8"),
    readFile(path.join(incidentResponseDir, "human_oversight.json"), "utf8"),
    readFile(path.join(incidentResponseDir, "policy_decision.json"), "utf8"),
    readFile(path.join(incidentResponseDir, "incident_report.json"), "utf8"),
    readFile(path.join(incidentResponseDir, "corrective_action.json"), "utf8"),
    readFile(
      path.join(incidentResponseDir, "authority_notification.json"),
      "utf8",
    ),
    readFile(
      path.join(incidentResponseDir, "authority_submission.json"),
      "utf8",
    ),
    readFile(path.join(incidentResponseDir, "reporting_deadline.json"), "utf8"),
    readFile(
      path.join(incidentResponseDir, "regulator_correspondence.json"),
      "utf8",
    ),
  ]);

  return {
    bundle_version: "1.0",
    bundle_id: "B-incident-response",
    created_at: "2026-03-22T18:00:00Z",
    actor: {
      issuer: "proof-layer-test",
      app_id: "typescript-sdk",
      env: "test",
      signing_key_id: "kid-dev-01",
      role: "deployer",
    },
    subject: {
      system_id: "benefits-review",
    },
    context: {},
    items: [
      { type: "technical_doc", data: JSON.parse(technicalDoc) },
      { type: "risk_assessment", data: JSON.parse(riskAssessment) },
      { type: "human_oversight", data: JSON.parse(humanOversight) },
      { type: "policy_decision", data: JSON.parse(policyDecision) },
      { type: "incident_report", data: JSON.parse(incidentReport) },
      { type: "corrective_action", data: JSON.parse(correctiveAction) },
      {
        type: "authority_notification",
        data: JSON.parse(authorityNotification),
      },
      {
        type: "authority_submission",
        data: JSON.parse(authoritySubmission),
      },
      { type: "reporting_deadline", data: JSON.parse(reportingDeadline) },
      {
        type: "regulator_correspondence",
        data: JSON.parse(regulatorCorrespondence),
      },
    ],
    artefacts: [],
    policy: {
      redactions: [],
      encryption: { enabled: false },
    },
    integrity: {
      canonicalization: "RFC8785-JCS",
      hash: "SHA-256",
      header_digest:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      bundle_root_algorithm: "pl-merkle-sha256-v4",
      bundle_root:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      signature: {
        format: "JWS",
        alg: "EdDSA",
        kid: "kid-dev-01",
        value: "sig",
      },
    },
  };
}

test("ProofLayer.capture seals a local llm_interaction bundle", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-123",
    complianceProfile: {
      intendedUse: "Internal reviewer assistance",
      riskTier: "high_risk_candidate",
      gpaiStatus: "downstream_integrator",
    },
    issuer: "proof-layer-ts",
    appId: "typescript-sdk",
    env: "test",
  });

  const result = await proofLayer.capture({
    provider: "openai",
    model: "gpt-4o-mini",
    input: [{ role: "user", content: "hello" }],
    output: { role: "assistant", content: "hi" },
    requestId: "req-proof-layer-1",
  });

  assert.equal(result.bundle?.bundle_version, "1.0");
  assert.equal(result.bundle?.subject?.system_id, "system-123");
  assert.equal(
    result.bundle?.compliance_profile?.intended_use,
    "Internal reviewer assistance",
  );
  assert.equal(result.bundle?.integrity.signature.kid, "kid-dev-01");
  assert.equal(typeof result.bundleRoot, "string");
});

test("ProofLayer.captureComputeMetrics seals local GPAI threshold evidence", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-gpai-threshold",
  });

  const result = await proofLayer.captureComputeMetrics({
    computeId: "compute-2026-q1",
    trainingFlopsEstimate: "1.2e25",
    thresholdBasisRef: "art51",
    thresholdValue: "1e25",
    thresholdStatus: "above_threshold",
  });

  assert.equal(result.bundle?.items[0].type, "compute_metrics");
  assert.equal(
    result.bundle?.items[0].data.threshold_status,
    "above_threshold",
  );
  assert.equal(result.bundle?.policy.retention_class, "gpai_documentation");
});

test("ProofLayer.disclose returns a locally verifiable redacted bundle", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const publicKeyPem = await readFile(
    path.join(goldenDir, "verify_key.txt"),
    "utf8",
  );
  const bundle = JSON.parse(
    await readFile(
      path.join(goldenDir, "fixed_bundle", "proof_bundle.json"),
      "utf8",
    ),
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
  });

  const redacted = await proofLayer.disclose({
    bundle,
    itemIndices: [0],
  });
  const summary = await proofLayer.verifyRedactedBundle({
    bundle: redacted,
    artefacts: [],
    publicKeyPem,
  });

  assert.equal(redacted.disclosed_items.length, 1);
  assert.deepEqual(summary, {
    disclosed_item_count: 1,
    disclosed_artefact_count: 0,
  });
});

test("ProofLayer.disclose forwards field-level redaction options", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const bundle = JSON.parse(
    await readFile(
      path.join(goldenDir, "fixed_bundle", "proof_bundle.json"),
      "utf8",
    ),
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
  });

  const redacted = await proofLayer.disclose({
    bundle,
    itemIndices: [0],
    fieldRedactions: { 0: ["output_commitment"] },
  });

  assert.equal(redacted.disclosed_items[0].item, undefined);
  assert.deepEqual(
    redacted.disclosed_items[0].field_redacted_item?.redacted_paths,
    ["/output_commitment"],
  );
});

test("ProofLayer local mode can evaluate completeness", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
  });

  const report = await proofLayer.evaluateCompleteness({
    bundle: await annexIvBundle(),
    profile: "annex_iv_governance_v1",
  });

  assert.equal(report.status, "pass");
  assert.equal(report.pass_count, 8);
});

test("ProofLayer local mode can evaluate gpai provider completeness", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
  });

  const report = await proofLayer.evaluateCompleteness({
    bundle: await gpaiProviderBundle(),
    profile: "gpai_provider_v1",
  });

  assert.equal(report.status, "pass");
  assert.equal(report.pass_count, 6);
});

test("ProofLayer local mode can evaluate provider governance completeness", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
  });

  const report = await proofLayer.evaluateCompleteness({
    bundle: await providerGovernanceBundle(),
    profile: "provider_governance_v1",
  });

  assert.equal(report.status, "pass");
  assert.equal(report.pass_count, 8);
});

test("ProofLayer local mode can evaluate conformity completeness", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
  });

  const report = await proofLayer.evaluateCompleteness({
    bundle: await conformityBundle(),
    profile: "conformity_v1",
  });

  assert.equal(report.status, "pass");
  assert.equal(report.pass_count, 3);
});

test("ProofLayer local mode can evaluate post-market monitoring completeness", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
  });

  const report = await proofLayer.evaluateCompleteness({
    bundle: await postMarketMonitoringBundle(),
    profile: "post_market_monitoring_v1",
  });

  assert.equal(report.status, "pass");
  assert.equal(report.pass_count, 6);
});

test("ProofLayer local mode can evaluate incident response completeness", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
  });

  const report = await proofLayer.evaluateCompleteness({
    bundle: await incidentResponseBundle(),
    profile: "incident_response_v1",
  });

  assert.equal(report.status, "pass");
  assert.equal(report.pass_count, 10);
});

test("ProofLayer vault mode can verify timestamp", async () => {
  let captured;
  const proofLayer = new ProofLayer({
    vaultUrl: "http://127.0.0.1:8080",
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return new Response(
        JSON.stringify({
          valid: true,
          message: "VALID: Timestamp token is valid",
          assessment: {
            level: "structural",
            headline: "Timestamp token is valid",
            summary: "The timestamp token matches this proof.",
            next_step: "Add trust files if you need stronger proof.",
            checks: [],
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    },
  });

  const result = await proofLayer.verifyTimestamp({ bundleId: "B1" });

  assert.equal(captured.url, "http://127.0.0.1:8080/v1/verify/timestamp");
  assert.equal(result.assessment.level, "structural");
});

test("ProofLayer vault mode can verify receipt with live check mode", async () => {
  let captured;
  const proofLayer = new ProofLayer({
    vaultUrl: "http://127.0.0.1:8080",
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return new Response(
        JSON.stringify({
          valid: true,
          message: "VALID: Transparency proof confirmed",
          assessment: {
            level: "trusted",
            headline: "Transparency proof confirmed",
            summary: "The receipt matches this proof.",
            next_step: "Keep the trusted key with the proof.",
            checks: [],
            live_check: {
              mode: "required",
              state: "pass",
              checked_at: "2026-03-06T12:10:00Z",
              summary: "Live log confirmation passed.",
            },
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    },
  });

  const result = await proofLayer.verifyReceipt({
    bundleId: "B1",
    liveCheckMode: "required",
  });

  assert.equal(captured.url, "http://127.0.0.1:8080/v1/verify/receipt");
  assert.equal(result.assessment.live_check?.mode, "required");
});

test("ProofLayer local mode rejects timestamp verification", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
  });

  await assert.rejects(
    proofLayer.verifyTimestamp({ bundleId: "B1" }),
    /verifyTimestamp is not supported for local mode/,
  );
});

test("ProofLayer vault mode can update disclosure config", async () => {
  let captured;
  const proofLayer = new ProofLayer({
    vaultUrl: "http://127.0.0.1:8080",
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return new Response(init.body, {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  const result = await proofLayer.updateDisclosureConfig({
    policies: [
      {
        name: "regulator_minimum",
        excluded_item_types: ["tool_call"],
        include_artefact_metadata: false,
        include_artefact_bytes: false,
        artefact_names: [],
      },
    ],
  });

  assert.equal(captured.url, "http://127.0.0.1:8080/v1/config/disclosure");
  assert.equal(captured.init.method, "PUT");
  assert.equal(result.policies[0].name, "regulator_minimum");
});

test("ProofLayer vault mode can evaluate completeness", async () => {
  let captured;
  const proofLayer = new ProofLayer({
    vaultUrl: "http://127.0.0.1:8080",
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return new Response(
        JSON.stringify({
          profile: "gpai_provider_v1",
          status: "warn",
          bundle_id: "B1",
          system_id: "foundation-model-alpha",
          pass_count: 5,
          warn_count: 1,
          fail_count: 0,
          rules: [],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    },
  });

  const result = await proofLayer.evaluateCompleteness({
    bundleId: "B1",
    profile: "gpai_provider_v1",
  });

  assert.equal(captured.url, "http://127.0.0.1:8080/v1/completeness/evaluate");
  assert.equal(result.status, "warn");
});

test("ProofLayer vault mode can evaluate pack completeness", async () => {
  let captured;
  const proofLayer = new ProofLayer({
    vaultUrl: "http://127.0.0.1:8080",
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return new Response(
        JSON.stringify({
          profile: "gpai_provider_v1",
          status: "pass",
          bundle_id: "P1",
          system_id: "foundation-model-alpha",
          pass_count: 6,
          warn_count: 0,
          fail_count: 0,
          rules: [],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    },
  });

  const result = await proofLayer.evaluateCompleteness({
    packId: "P1",
    profile: "gpai_provider_v1",
  });

  assert.equal(captured.url, "http://127.0.0.1:8080/v1/completeness/evaluate");
  assert.deepEqual(JSON.parse(captured.init.body), {
    pack_id: "P1",
    profile: "gpai_provider_v1",
  });
  assert.equal(result.status, "pass");
});

test("ProofLayer local mode rejects pack completeness evaluation", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
  });

  await assert.rejects(
    () =>
      proofLayer.evaluateCompleteness({
        packId: "P1",
        profile: "gpai_provider_v1",
      }),
    /packId is not supported for local completeness evaluation/,
  );
});

test("ProofLayer vault mode can list disclosure templates", async () => {
  let captured;
  const proofLayer = new ProofLayer({
    vaultUrl: "http://127.0.0.1:8080",
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return new Response(
        JSON.stringify({
          templates: [
            {
              profile: "runtime_minimum",
              description: "Runtime disclosure template",
              default_redaction_groups: ["commitments"],
              policy: {
                name: "runtime_minimum",
              },
            },
          ],
          redaction_groups: [
            {
              name: "commitments",
              description: "Hide digest fields.",
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    },
  });

  const result = await proofLayer.getDisclosureTemplates();

  assert.equal(captured.url, "http://127.0.0.1:8080/v1/disclosure/templates");
  assert.equal(result.templates[0].profile, "runtime_minimum");
});

test("ProofLayer vault mode can render disclosure templates", async () => {
  let captured;
  const proofLayer = new ProofLayer({
    vaultUrl: "http://127.0.0.1:8080",
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return new Response(
        JSON.stringify({
          profile: "privacy_review",
          description: "Privacy review disclosure",
          default_redaction_groups: ["metadata"],
          policy: {
            name: "privacy_review_custom",
            redacted_fields_by_item_type: {
              risk_assessment: ["/metadata/internal_notes"],
            },
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    },
  });

  const result = await proofLayer.renderDisclosureTemplate({
    profile: "privacy_review",
    name: "privacy_review_custom",
    redactionGroups: ["metadata"],
    redactedFieldsByItemType: {
      risk_assessment: ["/metadata/internal_notes"],
    },
  });

  assert.equal(
    captured.url,
    "http://127.0.0.1:8080/v1/disclosure/templates/render",
  );
  assert.equal(result.policy.name, "privacy_review_custom");
});

test("ProofLayer vault mode can create packs with inline disclosure templates", async () => {
  let captured;
  const proofLayer = new ProofLayer({
    vaultUrl: "http://127.0.0.1:8080",
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return new Response(
        JSON.stringify({
          pack_id: "P-inline",
          pack_type: "runtime_logs",
          created_at: "2026-03-09T12:00:00Z",
          bundle_format: "disclosure",
          disclosure_policy: "runtime_template_pack",
          bundle_count: 1,
          bundle_ids: ["B-inline"],
        }),
        { status: 201, headers: { "content-type": "application/json" } },
      );
    },
  });

  const result = await proofLayer.createPack({
    packType: "runtime_logs",
    bundleFormat: "disclosure",
    disclosureTemplate: {
      profile: "runtime_minimum",
      name: "runtime_template_pack",
      redactionGroups: ["metadata"],
    },
  });

  assert.equal(captured.url, "http://127.0.0.1:8080/v1/packs");
  assert.equal(result.disclosure_policy, "runtime_template_pack");
});

test("ProofLayer vault mode can preview disclosure selection", async () => {
  let captured;
  const proofLayer = new ProofLayer({
    vaultUrl: "http://127.0.0.1:8080",
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return new Response(
        JSON.stringify({
          bundle_id: "B1",
          policy_name: "risk_only",
          disclosed_item_indices: [1],
          disclosed_item_types: ["risk_assessment"],
          disclosed_item_obligation_refs: ["art9"],
          disclosed_artefact_indices: [],
          disclosed_artefact_names: [],
          disclosed_artefact_bytes_included: false,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    },
  });

  const result = await proofLayer.previewDisclosure({
    bundleId: "B1",
    policy: {
      name: "risk_only",
      allowed_obligation_refs: ["art9"],
    },
  });

  assert.equal(captured.url, "http://127.0.0.1:8080/v1/disclosure/preview");
  assert.equal(captured.init.method, "POST");
  assert.deepEqual(result.disclosed_item_types, ["risk_assessment"]);
});

test("ProofLayer vault mode can preview disclosure using a template request", async () => {
  let captured;
  const proofLayer = new ProofLayer({
    vaultUrl: "http://127.0.0.1:8080",
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return new Response(
        JSON.stringify({
          bundle_id: "B2",
          policy_name: "privacy_review_internal",
          disclosed_item_indices: [0],
          disclosed_item_types: ["llm_interaction"],
          disclosed_item_obligation_refs: ["art12_19_26"],
          disclosed_item_field_redactions: { 0: ["/parameters"] },
          disclosed_artefact_indices: [],
          disclosed_artefact_names: [],
          disclosed_artefact_bytes_included: false,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    },
  });

  const result = await proofLayer.previewDisclosure({
    bundleId: "B2",
    packType: "runtime_logs",
    disclosureTemplate: {
      profile: "privacy_review",
      name: "privacy_review_internal",
      redactionGroups: ["metadata"],
    },
  });

  assert.equal(captured.url, "http://127.0.0.1:8080/v1/disclosure/preview");
  assert.equal(result.policy_name, "privacy_review_internal");
});

test("withProofLayer attaches proof metadata to OpenAI-like responses", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
  });

  const wrapped = withProofLayer(
    {
      chat: {
        completions: {
          create: async (params) => ({
            id: "cmpl-typed-1",
            model: params.model,
            choices: [{ message: { role: "assistant", content: "ok" } }],
            usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
          }),
        },
      },
    },
    proofLayer,
    { requestId: "req-proof-layer-wrapper" },
  );

  const completion = await wrapped.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "hello" }],
  });

  assert.equal(completion.id, "cmpl-typed-1");
  assert.equal(completion.proofLayer.bundle?.bundle_version, "1.0");
  assert.equal(completion.proofLayer.signature.length > 10, true);
});

test("ProofLayer.captureRiskAssessment seals lifecycle evidence locally", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-risk-42",
  });

  const result = await proofLayer.captureRiskAssessment({
    riskId: "risk-42",
    severity: "medium",
    status: "mitigated",
    summary: "manual review added",
  });

  assert.equal(result.bundle?.items[0].type, "risk_assessment");
  assert.equal(result.bundle?.subject.system_id, "system-risk-42");
});

test("ProofLayer.captureTechnicalDoc seals inline document evidence locally", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-doc-42",
  });

  const result = await proofLayer.captureTechnicalDoc({
    documentRef: "annex-iv/system-card",
    section: "safety_controls",
    document: Buffer.from("annex-iv-body", "utf8"),
    documentName: "system-card.txt",
  });

  assert.equal(result.bundle?.items[0].type, "technical_doc");
  assert.equal(result.bundle?.subject.system_id, "system-doc-42");
  assert.ok(result.bundle?.items[0].data.commitment.startsWith("sha256:"));
});

test("ProofLayer.captureInstructionsForUse seals governance evidence locally", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-ifu-42",
  });

  const result = await proofLayer.captureInstructionsForUse({
    documentRef: "docs://ifu/v1",
    versionTag: "v1.2",
    section: "operator_controls",
    document: Buffer.from("review before override", "utf8"),
    documentName: "instructions.txt",
  });

  assert.equal(result.bundle?.items[0].type, "instructions_for_use");
  assert.equal(result.bundle?.subject.system_id, "system-ifu-42");
  assert.ok(result.bundle?.items[0].data.commitment.startsWith("sha256:"));
});

test("ProofLayer reuses a shared compliance profile across annex iv governance captures", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "hiring-assistant",
    role: "provider",
    complianceProfile: {
      intendedUse: "Recruiter support for first-pass candidate review",
      prohibitedPracticeScreening: "screened_no_prohibited_use",
      riskTier: "high_risk",
      highRiskDomain: "employment",
      deploymentContext: "eu_market_placement",
    },
  });

  const risk = await proofLayer.captureRiskAssessment({
    riskId: "risk-42",
    severity: "high",
    status: "mitigated",
    riskDescription: "Potential unfair ranking of borderline candidates.",
  });
  const dataGovernance = await proofLayer.captureDataGovernance({
    decision: "approved_with_restrictions",
    datasetRef: "dataset://hiring-assistant/training-v3",
    datasetName: "hiring-assistant-training",
  });

  assert.equal(risk.bundle?.compliance_profile?.high_risk_domain, "employment");
  assert.equal(
    dataGovernance.bundle?.compliance_profile?.prohibited_practice_screening,
    "screened_no_prohibited_use",
  );
  assert.equal(risk.bundle?.subject.system_id, "hiring-assistant");
  assert.equal(dataGovernance.bundle?.subject.system_id, "hiring-assistant");
});

test("ProofLayer.captureRetrieval seals retrieval evidence locally", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-rag-42",
  });

  const result = await proofLayer.captureRetrieval({
    corpus: "policy-kb",
    query: "refund policy",
    result: { docs: [{ id: "doc-1", score: 0.99 }] },
  });

  assert.equal(result.bundle?.items[0].type, "retrieval");
  assert.equal(result.bundle?.subject.system_id, "system-rag-42");
  assert.ok(
    result.bundle?.items[0].data.result_commitment.startsWith("sha256:"),
  );
});

test("ProofLayer.capturePolicyDecision seals policy decision evidence locally", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-policy-42",
  });

  const result = await proofLayer.capturePolicyDecision({
    policyName: "harm-filter",
    decision: "blocked",
    rationale: { classifier_score: 0.98 },
  });

  assert.equal(result.bundle?.items[0].type, "policy_decision");
  assert.equal(result.bundle?.subject.system_id, "system-policy-42");
  assert.ok(
    result.bundle?.items[0].data.rationale_commitment.startsWith("sha256:"),
  );
});

test("ProofLayer.captureLiteracyAttestation seals literacy evidence locally", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-literacy-42",
  });

  const result = await proofLayer.captureLiteracyAttestation({
    attestedRole: "reviewer",
    status: "completed",
    trainingRef: "course://ai-literacy/v1",
    attestation: { completion_id: "att-42" },
    retentionClass: "ai_literacy",
  });

  assert.equal(result.bundle?.items[0].type, "literacy_attestation");
  assert.equal(result.bundle?.subject.system_id, "system-literacy-42");
  assert.ok(
    result.bundle?.items[0].data.attestation_commitment.startsWith("sha256:"),
  );
});

test("ProofLayer.captureIncidentReport seals incident evidence locally", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-incident-42",
  });

  const result = await proofLayer.captureIncidentReport({
    incidentId: "inc-42",
    severity: "serious",
    status: "open",
    occurredAt: "2026-03-06T10:15:00Z",
    summary: "unsafe medical guidance surfaced",
    report: "timeline and corrective actions",
    retentionClass: "risk_mgmt",
  });

  assert.equal(result.bundle?.items[0].type, "incident_report");
  assert.equal(result.bundle?.subject.system_id, "system-incident-42");
  assert.ok(
    result.bundle?.items[0].data.report_commitment.startsWith("sha256:"),
  );
});

test("ProofLayer.capturePostMarketMonitoring seals monitoring evidence locally", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-monitoring-42",
  });

  const result = await proofLayer.capturePostMarketMonitoring({
    planId: "pmm-42",
    status: "active",
    summary: "weekly drift review with escalation thresholds",
    report: { owner: "safety-ops", cadence: "weekly" },
    retentionClass: "risk_mgmt",
  });

  assert.equal(result.bundle?.items[0].type, "post_market_monitoring");
  assert.equal(result.bundle?.subject.system_id, "system-monitoring-42");
  assert.ok(
    result.bundle?.items[0].data.report_commitment.startsWith("sha256:"),
  );
});

test("ProofLayer.captureAuthorityNotification seals authority-reporting evidence locally", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-incident-43",
  });

  const result = await proofLayer.captureAuthorityNotification({
    notificationId: "notif-42",
    authority: "eu_ai_office",
    status: "drafted",
    incidentId: "inc-42",
    dueAt: "2026-03-08T12:00:00Z",
    report: { incident: "inc-42", severity: "serious" },
    retentionClass: "risk_mgmt",
  });

  assert.equal(result.bundle?.items[0].type, "authority_notification");
  assert.equal(result.bundle?.subject.system_id, "system-incident-43");
  assert.ok(
    result.bundle?.items[0].data.report_commitment.startsWith("sha256:"),
  );
});

test("ProofLayer.captureModelEvaluation seals evaluation evidence locally", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-gpai-42",
  });

  const result = await proofLayer.captureModelEvaluation({
    evaluationId: "eval-42",
    benchmark: "mmlu-pro",
    status: "completed",
    summary: "baseline complete",
    report: { score: "0.84" },
  });

  assert.equal(result.bundle?.items[0].type, "model_evaluation");
  assert.equal(result.bundle?.subject.system_id, "system-gpai-42");
  assert.ok(
    result.bundle?.items[0].data.report_commitment.startsWith("sha256:"),
  );
});

test("ProofLayer.captureAdversarialTest seals adversarial evidence locally", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-gpai-43",
  });

  const result = await proofLayer.captureAdversarialTest({
    testId: "adv-42",
    focus: "prompt-injection",
    status: "open",
    findingSeverity: "high",
    report: "exploit transcript",
  });

  assert.equal(result.bundle?.items[0].type, "adversarial_test");
  assert.equal(result.bundle?.subject.system_id, "system-gpai-43");
  assert.ok(
    result.bundle?.items[0].data.report_commitment.startsWith("sha256:"),
  );
});

test("ProofLayer.captureTrainingProvenance seals provenance evidence locally", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-gpai-44",
  });

  const result = await proofLayer.captureTrainingProvenance({
    datasetRef: "dataset://foundation/pretrain-v3",
    stage: "pretraining",
    lineageRef: "lineage://snapshot/2026-03-01",
    record: { manifests: 12 },
  });

  assert.equal(result.bundle?.items[0].type, "training_provenance");
  assert.equal(result.bundle?.subject.system_id, "system-gpai-44");
  assert.ok(
    result.bundle?.items[0].data.record_commitment.startsWith("sha256:"),
  );
});

test("ProofLayer.captureConformityAssessment seals conformity evidence locally", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-conf-42",
  });

  const result = await proofLayer.captureConformityAssessment({
    assessmentId: "ca-42",
    procedure: "annex_vii",
    status: "completed",
    report: { outcome: "pass" },
    retentionClass: "technical_doc",
  });

  assert.equal(result.bundle?.items[0].type, "conformity_assessment");
  assert.equal(result.bundle?.subject.system_id, "system-conf-42");
  assert.ok(
    result.bundle?.items[0].data.report_commitment.startsWith("sha256:"),
  );
});

test("ProofLayer.captureDeclaration seals declaration evidence locally", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-conf-43",
  });

  const result = await proofLayer.captureDeclaration({
    declarationId: "decl-42",
    jurisdiction: "eu",
    status: "issued",
    document: "eu declaration body",
    retentionClass: "technical_doc",
  });

  assert.equal(result.bundle?.items[0].type, "declaration");
  assert.equal(result.bundle?.subject.system_id, "system-conf-43");
  assert.ok(
    result.bundle?.items[0].data.document_commitment.startsWith("sha256:"),
  );
});

test("ProofLayer.captureRegistration seals registration evidence locally", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-conf-44",
  });

  const result = await proofLayer.captureRegistration({
    registrationId: "reg-42",
    authority: "eu_database",
    status: "accepted",
    receipt: { receipt_id: "rcpt-42" },
    retentionClass: "technical_doc",
  });

  assert.equal(result.bundle?.items[0].type, "registration");
  assert.equal(result.bundle?.subject.system_id, "system-conf-44");
  assert.ok(
    result.bundle?.items[0].data.receipt_commitment.startsWith("sha256:"),
  );
});
