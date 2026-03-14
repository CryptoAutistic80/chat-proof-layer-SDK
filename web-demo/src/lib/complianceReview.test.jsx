import { describe, expect, test } from "vitest";
import { buildComplianceReview, buildRecordExplainer } from "./complianceReview";
import { getPlaygroundScenario } from "./sdkPlaygroundScenarios";

describe("buildComplianceReview", () => {
  test("maps bundle runs and pack state into plain-language review output", () => {
    const review = buildComplianceReview(getPlaygroundScenario("py_incident_escalation"), {
      bundleRuns: [
        {
          label: "Incident report",
          bundleId: "bundle-1",
          itemTypes: ["incident_report"],
          summary: "Initial incident evidence."
        }
      ],
      packManifest: {
        bundles: [{ bundle_id: "bundle-1", item_types: ["incident_report"] }]
      },
      downloadInfo: {
        fileName: "incident-response.pack"
      }
    });

    expect(review.title).toBe("Incident escalation evidence map");
    expect(review.capturedNow[0].bundleId).toBe("bundle-1");
    expect(review.supportsPack.packType).toBe("incident_response");
    expect(review.supportsPack.exportState).toContain("ready to download");
    expect(review.lawExplainer.expectation).toContain("clear incident trail");
    expect(review.missingEvidence.length).toBeGreaterThan(0);
  });

  test("builds a record explainer for packless chatbot scenarios", () => {
    const explainer = buildRecordExplainer(getPlaygroundScenario("ts_chatbot_support"), {
      packType: null
    });

    expect(explainer.captured.title).toBe("What was stored");
    expect(explainer.share.body).toContain("does not automatically build an export package");
  });
});
