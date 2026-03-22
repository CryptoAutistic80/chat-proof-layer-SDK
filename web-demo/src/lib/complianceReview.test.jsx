import { describe, expect, test } from "vitest";
import {
  buildComplianceReview,
  buildRecordExplainer,
} from "./complianceReview";
import { getPlaygroundScenario } from "./sdkPlaygroundScenarios";

describe("buildComplianceReview", () => {
  test("maps bundle runs and pack state into plain-language review output", () => {
    const review = buildComplianceReview(
      getPlaygroundScenario("py_incident_escalation"),
      {
        bundleRuns: [
          {
            label: "Incident report",
            bundleId: "bundle-1",
            itemTypes: ["incident_report"],
            summary: "Initial incident evidence.",
          },
        ],
        packManifest: {
          bundles: [{ bundle_id: "bundle-1", item_types: ["incident_report"] }],
        },
        downloadInfo: {
          fileName: "incident-response.pack",
        },
        completenessReport: {
          profile: "annex_iv_governance_v1",
          status: "warn",
          pass_count: 4,
          warn_count: 1,
          fail_count: 0,
          rules: [
            {
              status: "warn",
              missing_fields: ["stop_reason"],
            },
          ],
        },
        packCompletenessReport: {
          profile: "annex_iv_governance_v1",
          status: "pass",
          pass_count: 8,
          warn_count: 0,
          fail_count: 0,
          rules: [],
        },
      },
    );

    expect(review.title).toBe("Incident escalation evidence map");
    expect(review.capturedNow[0].bundleId).toBe("bundle-1");
    expect(review.supportsPack.packType).toBe("incident_response");
    expect(review.supportsPack.exportState).toContain("ready to download");
    expect(review.lawExplainer.expectation).toContain("clear incident trail");
    expect(review.readiness.profile).toBe("annex_iv_governance_v1");
    expect(review.readiness.topMissingFields).toContain("stop_reason");
    expect(review.packReadiness?.status).toBe("pass");
    expect(review.packReadiness?.summary).toContain("exported pack");
    expect(review.commonNextEvidence.length).toBeGreaterThan(0);
  });

  test("builds a record explainer for packless chatbot scenarios", () => {
    const explainer = buildRecordExplainer(
      getPlaygroundScenario("ts_chatbot_support"),
      {
        packType: null,
      },
    );

    expect(explainer.captured.title).toBe("What was stored");
    expect(explainer.share.body).toContain(
      "does not automatically build an export package",
    );
  });

  test("uses GPAI-specific readiness wording when the gpai profile is attached", () => {
    const review = buildComplianceReview(
      getPlaygroundScenario("ts_gpai_thresholds"),
      {
        completenessReport: {
          profile: "gpai_provider_v1",
          status: "pass",
          pass_count: 6,
          warn_count: 0,
          fail_count: 0,
          rules: [],
        },
      },
    );

    expect(review.readiness.profile).toBe("gpai_provider_v1");
    expect(review.readiness.summary).toContain("GPAI provider");
    expect(review.readinessScopeNote).toBeNull();
  });

  test("uses conformity-specific readiness wording when the conformity profile is attached", () => {
    const review = buildComplianceReview(
      getPlaygroundScenario("ts_support_rules"),
      {
        completenessReport: {
          profile: "conformity_v1",
          status: "fail",
          pass_count: 0,
          warn_count: 0,
          fail_count: 1,
          rules: [
            {
              status: "fail",
              missing_fields: ["registration_number"],
            },
          ],
        },
      },
    );

    expect(review.readiness.profile).toBe("conformity_v1");
    expect(review.readiness.summary).toContain("conformity");
  });

  test("uses FRIA-specific readiness wording when the deployer profile is attached", () => {
    const review = buildComplianceReview(
      getPlaygroundScenario("py_hiring_review"),
      {
        completenessReport: {
          profile: "fundamental_rights_v1",
          status: "pass",
          pass_count: 2,
          warn_count: 0,
          fail_count: 0,
          rules: [],
        },
      },
    );

    expect(review.readiness.profile).toBe("fundamental_rights_v1");
    expect(review.readiness.summary).toContain("fundamental-rights assessment");
  });

  test("uses monitoring-specific readiness wording when the monitoring profile is attached", () => {
    const review = buildComplianceReview(
      getPlaygroundScenario("py_incident_escalation"),
      {
        completenessReport: {
          profile: "post_market_monitoring_v1",
          status: "fail",
          pass_count: 0,
          warn_count: 0,
          fail_count: 2,
          rules: [
            {
              status: "fail",
              missing_fields: ["document_commitment"],
            },
          ],
        },
      },
    );

    expect(review.readiness.profile).toBe("post_market_monitoring_v1");
    expect(review.readiness.summary).toContain("post-market monitoring");
  });

  test("uses provider-governance-specific readiness wording when that profile is attached", () => {
    const review = buildComplianceReview(
      getPlaygroundScenario("ts_support_rules"),
      {
        completenessReport: {
          profile: "provider_governance_v1",
          status: "fail",
          pass_count: 0,
          warn_count: 0,
          fail_count: 2,
          rules: [
            {
              status: "fail",
              missing_fields: ["record_commitment"],
            },
          ],
        },
      },
    );

    expect(review.readiness.profile).toBe("provider_governance_v1");
    expect(review.readiness.summary).toContain("provider-governance");
  });

  test("uses incident-response-specific readiness wording when that profile is attached", () => {
    const review = buildComplianceReview(
      getPlaygroundScenario("py_incident_escalation"),
      {
        completenessReport: {
          profile: "incident_response_v1",
          status: "fail",
          pass_count: 0,
          warn_count: 0,
          fail_count: 2,
          rules: [
            {
              status: "fail",
              missing_fields: ["rationale_commitment"],
            },
          ],
        },
      },
    );

    expect(review.readiness.profile).toBe("incident_response_v1");
    expect(review.readiness.summary).toContain("incident-response");
  });

  test("leaves exported pack readiness empty when no pack completeness report is attached", () => {
    const review = buildComplianceReview(
      getPlaygroundScenario("ts_support_rules"),
      {
        completenessReport: {
          profile: "annex_iv_governance_v1",
          status: "pass",
          pass_count: 8,
          warn_count: 0,
          fail_count: 0,
          rules: [],
        },
      },
    );

    expect(review.readiness.status).toBe("pass");
    expect(review.packReadiness).toBeNull();
  });
});
