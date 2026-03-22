import {
  findScenarioByPackType,
  getPlaygroundScenario,
} from "./sdkPlaygroundScenarios";

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
  return (
    findScenarioByPackType(run?.packType ?? null, run?.bundle?.items ?? []) ??
    getPlaygroundScenario("ts_chatbot_support")
  );
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
    case "annex_iv":
      return "an Annex IV, regulator-facing, or conformity review";
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

function readinessCopy(profile, status, subject = "workflow") {
  if (profile === "annex_iv_governance_v1") {
    if (status === "pass") {
      return `The structured governance fields for this Annex IV ${subject} meet the current advisory minimum.`;
    }
    if (status === "warn") {
      return `The ${subject} has at least one minimally complete governance record for each required area, but some captured records are thinner than the current advisory minimum.`;
    }
    return `The ${subject} is missing at least one required governance area or does not yet include a minimally complete record for that area.`;
  }
  if (profile === "gpai_provider_v1") {
    if (status === "pass") {
      return `The structured GPAI provider fields for this ${subject} meet the current advisory minimum.`;
    }
    if (status === "warn") {
      return `The ${subject} has at least one minimally complete GPAI provider record for each required area, but some captured records are thinner than the current advisory minimum.`;
    }
    return `The ${subject} is missing at least one required GPAI provider area or does not yet include a minimally complete record for that area.`;
  }
  if (status === "pass") {
    return `The structured fields for this ${subject} meet the current advisory minimum.`;
  }
  if (status === "warn") {
    return `The ${subject} has at least one minimally complete record for each required area, but some captured records are thinner than the current advisory minimum.`;
  }
  return `The ${subject} is missing at least one required area or does not yet include a minimally complete record for that area.`;
}

function summarizeReadinessReport(report, subject = "workflow") {
  if (!report) {
    return null;
  }

  const topMissingFields = [
    ...new Set(
      (report.rules ?? [])
        .filter((rule) => rule.status === "warn" || rule.status === "fail")
        .flatMap((rule) => rule.missing_fields ?? []),
    ),
  ].slice(0, 6);

  return {
    profile: report.profile,
    status: report.status,
    passCount: report.pass_count ?? 0,
    warnCount: report.warn_count ?? 0,
    failCount: report.fail_count ?? 0,
    topMissingFields,
    summary: readinessCopy(report.profile, report.status, subject),
  };
}

function buildReadinessSummary(run) {
  return (
    summarizeReadinessReport(run?.completenessReport, "workflow") ?? {
      profile: null,
      status: "muted",
      passCount: 0,
      warnCount: 0,
      failCount: 0,
      topMissingFields: [],
      summary: "No readiness check is attached to this workflow.",
    }
  );
}

export function buildComplianceReview(inputScenario, run) {
  const scenario = normalizeScenario(inputScenario, run);
  const bundleRuns = bundleRunsFromRun(run);
  const readiness = buildReadinessSummary(run);
  const packReadiness = summarizeReadinessReport(
    run?.packCompletenessReport,
    "exported pack",
  );

  return {
    title: `${scenario.label} evidence map`,
    summary:
      "This is a plain-English evidence map for the selected workflow. The readiness check is an advisory structural review, not legal advice and not a complete EU AI Act determination.",
    capturedNow: bundleRuns.map((bundleRun) => ({
      label: bundleRun.label,
      bundleId: bundleRun.bundleId,
      itemTypes: bundleRun.itemTypes,
      summary: bundleRun.summary,
    })),
    supportsPack: {
      packType: scenario.packType ?? "No export pack by default",
      bundleCount: run?.packManifest?.bundles?.length ?? bundleRuns.length,
      exportState: exportedState(run, scenario),
      manifestItems:
        run?.packManifest?.bundles?.map((entry) => ({
          bundleId: entry.bundle_id,
          itemTypes: entry.item_types,
        })) ?? [],
    },
    readiness,
    packReadiness,
    lawExplainer: scenario.lawExplainer,
    commonNextEvidence: scenario.missingEvidence,
  };
}

export function buildRecordExplainer(inputScenario, run) {
  const scenario = normalizeScenario(inputScenario, run);
  const packLabel = scenario.packType ?? "no export pack by default";

  return {
    intro: scenario.recordExplorerIntro,
    captured: {
      title: "What was stored",
      body: "This view explains the main record contents in plain English before you open any raw JSON. Start here if you want to understand the story of the run.",
      lawExplainer: scenario.lawExplainer,
    },
    proof: {
      title: "What can be independently checked",
      body: "This view focuses on whether the record can be verified later and what a reviewer can confirm about integrity, timestamps, transparency, and disclosure decisions.",
      lawExplainer: scenario.lawExplainer,
    },
    share: {
      title: "What can leave the system",
      body: scenario.packType
        ? `This workflow can build a ${packLabel} package for ${defaultShareAudience(scenario)}.`
        : "This example does not automatically build an export package. It teaches capture first, then lets you inspect the record before deciding how to share it.",
      audience: defaultShareAudience(scenario),
      lawExplainer: scenario.lawExplainer,
    },
    commonNextEvidence: scenario.missingEvidence,
  };
}
