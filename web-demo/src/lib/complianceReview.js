import { findScenarioByPackType, getPlaygroundScenario } from "./sdkPlaygroundScenarios";

function normalizeScenario(inputScenario, run) {
  if (typeof inputScenario === "string") {
    return getPlaygroundScenario(inputScenario);
  }
  if (inputScenario?.id) {
    return inputScenario;
  }
  if (run?.scenarioId) {
    return getPlaygroundScenario(run.scenarioId);
  }
  return findScenarioByPackType(run?.packType ?? null, run?.bundle?.items ?? []) ?? getPlaygroundScenario("ts_chatbot_support");
}

function exportedState(run, scenario) {
  if (!scenario.packType) {
    return "No export pack is created for this example by default.";
  }
  if (run?.downloadInfo) {
    return "Pack exported and ready to download.";
  }
  if (run?.packSummary) {
    return "Pack created, but the browser download is not attached yet.";
  }
  return "Pack not exported yet.";
}

function defaultShareAudience(scenario) {
  switch (scenario.packType) {
    case "provider_governance":
      return "an internal quality or regulator-facing review";
    case "annex_xi":
      return "a GPAI, technical-documentation, or regulator-facing review";
    case "fundamental_rights":
      return "a deployer-side rights, risk, or regulator review";
    case "incident_response":
      return "incident managers, regulators, or internal response leads";
    default:
      return "an engineering, support, or compliance review";
  }
}

function bundleRunsFromRun(run) {
  return Array.isArray(run?.bundleRuns) ? run.bundleRuns : [];
}

export function buildComplianceReview(inputScenario, run) {
  const scenario = normalizeScenario(inputScenario, run);
  const bundleRuns = bundleRunsFromRun(run);

  return {
    title: `${scenario.label} evidence map`,
    summary:
      "This is a plain-English evidence map for the selected workflow. It is not legal advice or a complete EU AI Act determination.",
    capturedNow: bundleRuns.map((bundleRun) => ({
      label: bundleRun.label,
      bundleId: bundleRun.bundleId,
      itemTypes: bundleRun.itemTypes,
      summary: bundleRun.summary
    })),
    supportsPack: {
      packType: scenario.packType ?? "No export pack by default",
      bundleCount: run?.packManifest?.bundles?.length ?? bundleRuns.length,
      exportState: exportedState(run, scenario),
      manifestItems:
        run?.packManifest?.bundles?.map((entry) => ({
          bundleId: entry.bundle_id,
          itemTypes: entry.item_types
        })) ?? []
    },
    lawExplainer: scenario.lawExplainer,
    missingEvidence: scenario.missingEvidence
  };
}

export function buildRecordExplainer(inputScenario, run) {
  const scenario = normalizeScenario(inputScenario, run);
  const packLabel = scenario.packType ?? "no export pack by default";

  return {
    intro: scenario.recordExplorerIntro,
    captured: {
      title: "What was stored",
      body:
        "This view explains the main record contents in plain English before you open any raw JSON. Start here if you want to understand the story of the run.",
      lawExplainer: scenario.lawExplainer
    },
    proof: {
      title: "What can be independently checked",
      body:
        "This view focuses on whether the record can be verified later and what a reviewer can confirm about integrity, timestamps, transparency, and disclosure decisions.",
      lawExplainer: scenario.lawExplainer
    },
    share: {
      title: "What can leave the system",
      body: scenario.packType
        ? `This workflow can build a ${packLabel} package for ${defaultShareAudience(scenario)}.`
        : "This example does not automatically build an export package. It teaches capture first, then lets you inspect the record before deciding how to share it.",
      audience: defaultShareAudience(scenario),
      lawExplainer: scenario.lawExplainer
    },
    missingEvidence: scenario.missingEvidence
  };
}
