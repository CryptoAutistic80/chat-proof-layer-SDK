import { describe, expect, test } from "vitest";
import { buildRunNarrativeSummary } from "./narrative";

describe("buildRunNarrativeSummary", () => {
  test("uses GPAI-specific readiness wording for a passing provider-file flow", () => {
    const summary = buildRunNarrativeSummary(
      {
        presetKey: "investor_summary",
        scenarioLabel: "GPAI provider Annex XI pack",
        scenarioId: "ts_gpai_thresholds",
        bundleId: "bundle-1",
        bundleRuns: [{ bundleId: "bundle-1" }],
        completenessProfile: "gpai_provider_v1",
        completenessReport: {
          profile: "gpai_provider_v1",
          status: "pass",
          pass_count: 6,
          warn_count: 0,
          fail_count: 0,
          rules: [],
        },
      },
      null,
    );

    expect(summary.completenessStatus.title).toBe("Readiness check passed");
    expect(summary.completenessStatus.summary).toContain(
      "gpai_provider_v1",
    );
  });

  test("uses FRIA-specific readiness wording for deployer rights flows", () => {
    const summary = buildRunNarrativeSummary(
      {
        presetKey: "investor_summary",
        scenarioLabel: "FRIA review",
        bundleId: "bundle-2",
        bundleRuns: [{ bundleId: "bundle-2" }],
        completenessProfile: "fundamental_rights_v1",
        completenessReport: {
          profile: "fundamental_rights_v1",
          status: "fail",
          pass_count: 0,
          warn_count: 0,
          fail_count: 1,
          rules: [],
        },
      },
      null,
    );

    expect(summary.completenessStatus.summary).toContain(
      "required deployer-side rights area(s)",
    );
  });

  test("uses conformity-specific readiness wording for conformity flows", () => {
    const summary = buildRunNarrativeSummary(
      {
        presetKey: "investor_summary",
        scenarioLabel: "Conformity file",
        bundleId: "bundle-5",
        bundleRuns: [{ bundleId: "bundle-5" }],
        completenessProfile: "conformity_v1",
        completenessReport: {
          profile: "conformity_v1",
          status: "warn",
          pass_count: 2,
          warn_count: 1,
          fail_count: 0,
          rules: [],
        },
      },
      null,
    );

    expect(summary.completenessStatus.summary).toContain(
      "required conformity area",
    );
  });

  test("uses monitoring-specific readiness wording for monitoring flows", () => {
    const summary = buildRunNarrativeSummary(
      {
        presetKey: "investor_summary",
        scenarioLabel: "Monitoring escalation",
        bundleId: "bundle-3",
        bundleRuns: [{ bundleId: "bundle-3" }],
        completenessProfile: "post_market_monitoring_v1",
        completenessReport: {
          profile: "post_market_monitoring_v1",
          status: "warn",
          pass_count: 5,
          warn_count: 1,
          fail_count: 0,
          rules: [],
        },
      },
      null,
    );

    expect(summary.completenessStatus.summary).toContain(
      "required post-market monitoring area",
    );
  });

  test("uses incident-response readiness wording for incident flows", () => {
    const summary = buildRunNarrativeSummary(
      {
        presetKey: "investor_summary",
        scenarioLabel: "Incident response",
        bundleId: "bundle-6",
        bundleRuns: [{ bundleId: "bundle-6" }],
        completenessProfile: "incident_response_v1",
        completenessReport: {
          profile: "incident_response_v1",
          status: "fail",
          pass_count: 0,
          warn_count: 0,
          fail_count: 1,
          rules: [],
        },
      },
      null,
    );

    expect(summary.completenessStatus.summary).toContain(
      "required incident-response area(s)",
    );
  });

  test("uses provider-governance readiness wording for provider governance flows", () => {
    const summary = buildRunNarrativeSummary(
      {
        presetKey: "investor_summary",
        scenarioLabel: "Provider governance",
        bundleId: "bundle-4",
        bundleRuns: [{ bundleId: "bundle-4" }],
        completenessProfile: "provider_governance_v1",
        completenessReport: {
          profile: "provider_governance_v1",
          status: "fail",
          pass_count: 0,
          warn_count: 0,
          fail_count: 2,
          rules: [],
        },
      },
      null,
    );

    expect(summary.completenessStatus.summary).toContain(
      "required provider-governance area(s)",
    );
  });

  test("uses timestamp and transparency assessment wording when available", () => {
    const summary = buildRunNarrativeSummary(
      {
        presetKey: "investor_summary",
        timestampVerification: {
          valid: true,
          assessment: {
            level: "qualified",
            headline: "Qualified timestamp trust confirmed",
            summary:
              "The timestamp token matches this proof and passed the stronger trust checks you asked for.",
            next_step:
              "Keep the trust files with the proof so another person can repeat the same check.",
            checks: [],
          },
        },
        receiptVerification: {
          valid: true,
          assessment: {
            level: "structural",
            headline: "Transparency receipt is valid",
            summary:
              "The stored receipt matches this proof, but stronger trust checks were not proven. The log was also checked live.",
            next_step:
              "Add the trusted log key if you want to show who issued the receipt.",
            checks: [],
            live_check: {
              mode: "best_effort",
              state: "pass",
              checked_at: "2026-03-22T12:00:00Z",
              summary: "The live log still includes this entry.",
            },
          },
        },
      },
      {
        timestamp: { enabled: true },
        transparency: { enabled: true },
      },
    );

    expect(summary.timestampStatus.title).toBe(
      "Qualified timestamp trust confirmed",
    );
    expect(summary.timestampStatus.tone).toBe("good");
    expect(summary.transparencyStatus.title).toBe(
      "Transparency receipt is valid",
    );
    expect(summary.transparencyStatus.tone).toBe("accent");
    expect(summary.transparencyStatus.summary).toContain(
      "checked live",
    );
  });
});
