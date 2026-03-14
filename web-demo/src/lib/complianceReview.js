import { getPlaygroundScenario } from "./sdkPlaygroundScenarios";

function exportedState(run) {
  if (run?.downloadInfo) {
    return "Pack exported and ready to download.";
  }
  if (run?.packSummary) {
    return "Pack created, but the browser download is not attached yet.";
  }
  return "Pack not exported yet.";
}

export function buildComplianceReview(inputScenario, run) {
  const scenario =
    typeof inputScenario === "string"
      ? getPlaygroundScenario(inputScenario)
      : inputScenario;
  const bundleRuns = Array.isArray(run?.bundleRuns) ? run.bundleRuns : [];

  return {
    title: `${scenario.label} evidence map`,
    summary:
      "This review is an illustrative evidence map for the selected example. It is not legal advice or a complete AI Act determination.",
    capturedNow: bundleRuns.map((bundleRun) => ({
      label: bundleRun.label,
      bundleId: bundleRun.bundleId,
      itemTypes: bundleRun.itemTypes,
      summary: bundleRun.summary
    })),
    supportsPack: {
      packType: scenario.packType,
      bundleCount: run?.packManifest?.bundles?.length ?? bundleRuns.length,
      exportState: exportedState(run),
      manifestItems:
        run?.packManifest?.bundles?.map((entry) => ({
          bundleId: entry.bundle_id,
          itemTypes: entry.item_types
        })) ?? []
    },
    missingEvidence: scenario.reviewGaps
  };
}
