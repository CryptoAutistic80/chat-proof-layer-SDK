import { describe, expect, test } from "vitest";
import { buildRunNarrativeSummary } from "./narrative";

describe("buildRunNarrativeSummary", () => {
  test("uses generic pending copy and gpai-specific failure wording", () => {
    const summary = buildRunNarrativeSummary(
      {
        presetKey: "investor_summary",
        scenarioLabel: "GPAI thresholds",
        bundleId: "bundle-1",
        bundleRuns: [{ bundleId: "bundle-1" }],
        completenessProfile: "gpai_provider_v1",
        completenessReport: {
          profile: "gpai_provider_v1",
          status: "fail",
          pass_count: 0,
          warn_count: 0,
          fail_count: 2,
          rules: [],
        },
      },
      null,
    );

    expect(summary.completenessStatus.title).toBe("Readiness check failed");
    expect(summary.completenessStatus.summary).toContain(
      "required GPAI provider area(s)",
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
