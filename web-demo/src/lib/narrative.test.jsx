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
});
