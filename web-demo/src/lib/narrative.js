import { getPreset } from "./presets";

export function humanCaptureMode(captureMode) {
  if (captureMode === "live_provider_capture") {
    return "Live provider run";
  }
  if (captureMode === "synthetic_demo_capture") {
    return "Synthetic sample run";
  }
  return "Awaiting run";
}

export function proofRecordLabel(bundleId) {
  if (!bundleId) {
    return "Not sealed yet";
  }
  return bundleId;
}

function integrityStatus(run) {
  if (run?.verifyResponse?.valid) {
    return {
      tone: "good",
      title: "Integrity check passed",
      summary: "Verified: this proof record and its captured materials match the connected signer."
    };
  }
  if (run?.verifyResponse?.message) {
    return {
      tone: "warn",
      title: "Integrity check needs attention",
      summary: run.verifyResponse.message
    };
  }
  return {
    tone: "muted",
    title: "Integrity check pending",
    summary: "Verification will run after a proof record is created."
  };
}

function timestampStatus(run, vaultConfig) {
  if (!vaultConfig?.timestamp?.enabled) {
    return {
      tone: "muted",
      title: "Timestamp not configured",
      summary: "Not configured on this vault."
    };
  }
  if (run?.timestampVerification?.valid) {
    return {
      tone: "good",
      title: "Timestamp confirmed",
      summary: "Verified: the timestamp token matches this proof record."
    };
  }
  if (run?.timestampVerification?.message) {
    return {
      tone: "warn",
      title: "Timestamp needs attention",
      summary: run.timestampVerification.message
    };
  }
  return {
    tone: "muted",
    title: "Timestamp pending",
    summary: "Timestamp was requested, but no result is attached yet."
  };
}

function transparencyStatus(run, vaultConfig) {
  if (!vaultConfig?.transparency?.enabled) {
    return {
      tone: "muted",
      title: "Transparency not configured",
      summary: "Not configured on this vault."
    };
  }
  if (run?.receiptVerification?.valid) {
    return {
      tone: "good",
      title: "Transparency receipt confirmed",
      summary: "Verified: the transparency receipt matches this proof record."
    };
  }
  if (run?.receiptVerification?.message) {
    return {
      tone: "warn",
      title: "Transparency receipt needs attention",
      summary: run.receiptVerification.message
    };
  }
  return {
    tone: "muted",
    title: "Transparency receipt pending",
    summary: "Transparency was requested, but no receipt result is attached yet."
  };
}

function disclosureStatus(run) {
  const itemCount = Array.isArray(run?.disclosurePreview?.disclosed_item_indices)
    ? run.disclosurePreview.disclosed_item_indices.length
    : 0;
  const artefactCount = Array.isArray(run?.disclosurePreview?.disclosed_artefact_names)
    ? run.disclosurePreview.disclosed_artefact_names.length
    : 0;
  if (!run?.disclosurePreview) {
    return {
      tone: "muted",
      title: "Disclosure preview pending",
      summary: "Run or load a proof record to see what a reviewer would receive."
    };
  }
  if (itemCount > 0 || artefactCount > 0) {
    return {
      tone: "accent",
      title: "Disclosure preview available",
      summary: `${itemCount} item(s) and ${artefactCount} captured material(s) are included under the selected sharing profile.`
    };
  }
  return {
    tone: "warn",
    title: "No disclosure output",
    summary: "This sharing profile does not reveal any content for this proof record."
  };
}

function exportStatus(run) {
  if (run?.downloadInfo) {
    return {
      tone: "good",
      title: "Share package ready",
      summary: `A ${run.bundleFormat} share package is ready to download.`
    };
  }
  const itemCount = Array.isArray(run?.disclosurePreview?.disclosed_item_indices)
    ? run.disclosurePreview.disclosed_item_indices.length
    : 0;
  const artefactCount = Array.isArray(run?.disclosurePreview?.disclosed_artefact_names)
    ? run.disclosurePreview.disclosed_artefact_names.length
    : 0;
  if (run?.bundleFormat === "full") {
    return {
      tone: "accent",
      title: "Full export available",
      summary: "This run can be exported as a full share package."
    };
  }
  if (itemCount === 0 && artefactCount === 0) {
    return {
      tone: "warn",
      title: "No disclosure package available",
      summary: "This proof record does not produce a redacted share package under the selected sharing profile."
    };
  }
  return {
    tone: "accent",
    title: "Disclosure export available",
    summary: "This run can be exported as a redacted share package."
  };
}

export function buildRunNarrativeSummary(run, vaultConfig) {
  const preset = getPreset(run?.presetKey);
  const mode = humanCaptureMode(run?.captureMode);
  const scenario = preset.label;
  const headline = run?.bundleId
    ? `${scenario} completed`
    : "Run a scenario to create a proof record";
  const summary = run?.bundleId
    ? `${mode} for ${run?.provider ?? "provider"}:${run?.model ?? "model"} created one proof record for the ${scenario.toLowerCase()} scenario.`
    : "Choose a scenario, run it, and the site will explain what happened, what can be proven, and what can be shared.";

  return {
    headline,
    summary,
    scenario,
    preset,
    mode,
    proofRecord: proofRecordLabel(run?.bundleId),
    integrityStatus: integrityStatus(run),
    timestampStatus: timestampStatus(run, vaultConfig),
    transparencyStatus: transparencyStatus(run, vaultConfig),
    disclosureStatus: disclosureStatus(run),
    exportStatus: exportStatus(run)
  };
}
