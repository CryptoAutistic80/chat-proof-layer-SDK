import React, {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  attachTimestamp,
  anchorBundle,
  createBundle,
  createPack,
  downloadPackExport,
  evaluateCompleteness,
  fetchBundle,
  fetchBundleArtefact,
  fetchDemoProviderResponse,
  fetchDisclosureTemplates,
  fetchPackManifest,
  fetchSystemSummary,
  fetchVaultConfig,
  formatBytes,
  listBundles,
  previewDisclosure,
  verifyBundle,
  verifyReceipt,
  verifyTimestamp,
} from "../lib/vaultApi";
import {
  DEFAULT_SERVICE_URL,
  DEFAULT_SYSTEM_ID,
  applyPresetToDraft,
  defaultModelFor,
  defaultTemplateName,
  getPreset,
  inferPresetKey,
  isProviderLiveEnabled,
  modelOptionsFor,
} from "../lib/presets";
import { buildCaptureEnvelope, decodeJsonBytes } from "../lib/captureBuilders";
import {
  buildComplianceReview,
  buildRecordExplainer,
} from "../lib/complianceReview";
import {
  applyScenarioToDraft,
  firstScenarioForLane,
  findScenarioByPackType,
  getPlaygroundScenario,
  inferPackTypeFromItems,
  initialPlaygroundScenario,
} from "../lib/sdkPlaygroundScenarios";
import { renderScenarioScript } from "../lib/sdkScriptTemplates";
import { buildScenarioWorkflow } from "../lib/sdkWorkflowBuilders";

const DemoContext = createContext(null);
const COMPLETENESS_PROFILE_BY_PACK_TYPE = {
  annex_iv: "annex_iv_governance_v1",
  annex_xi: "gpai_provider_v1",
};

function arrayValue(value) {
  return Array.isArray(value) ? value : [];
}

function previewStats(preview) {
  return {
    itemCount: arrayValue(preview?.disclosed_item_indices).length,
    artefactCount: arrayValue(preview?.disclosed_artefact_names).length,
  };
}

function hasTemporaryProviderKey(value) {
  return Boolean(value && value.trim());
}

function canUseLiveMode(vaultConfig, provider, providerApiKey) {
  return (
    isProviderLiveEnabled(vaultConfig, provider) ||
    hasTemporaryProviderKey(providerApiKey)
  );
}

function readinessProfileForPackType(packType) {
  return COMPLETENESS_PROFILE_BY_PACK_TYPE[packType] ?? null;
}

function packCompletenessProfile(packSummary, packManifest) {
  return (
    packSummary?.pack_completeness_profile ??
    packManifest?.pack_completeness_profile ??
    null
  );
}

function trustTone(level) {
  return level === "trusted" || level === "qualified" ? "good" : "accent";
}

function timestampActivityTone(verification) {
  if (!verification?.valid) {
    return "warn";
  }
  return verification?.assessment ? trustTone(verification.assessment.level) : "good";
}

function receiptActivityTone(verification) {
  if (!verification?.valid) {
    return "warn";
  }
  const liveState = verification?.assessment?.live_check?.state;
  if (liveState === "fail") {
    return "warn";
  }
  if (liveState === "warn") {
    return "accent";
  }
  return verification?.assessment ? trustTone(verification.assessment.level) : "good";
}

function assuranceActivityMessage(verification, fallback) {
  if (verification?.assessment?.summary) {
    return verification.assessment.summary;
  }
  return verification?.message ?? fallback;
}

function createInitialDraft() {
  const preset = getPreset("investor_summary");
  const scenario = initialPlaygroundScenario();
  return {
    serviceUrl: DEFAULT_SERVICE_URL,
    apiKey: "",
    providerApiKey: "",
    presetKey: preset.key,
    mode: "synthetic",
    provider: "openai",
    model: defaultModelFor("openai"),
    actorRole: preset.actorRole,
    systemId: DEFAULT_SYSTEM_ID,
    systemPrompt: preset.systemPrompt,
    userPrompt: preset.userPrompt,
    temperature: "0.2",
    maxTokens: "256",
    attachTimestamp: true,
    attachTransparency: true,
    bundleFormat: preset.bundleFormat,
    templateProfile: preset.disclosureProfile,
    templateName: defaultTemplateName(preset.disclosureProfile),
    selectedGroups: [],
    lane: scenario.lane,
    scenarioId: scenario.id,
    playgroundHydrated: false,
    intendedUse: "",
    prohibitedPracticeScreening: "",
    riskTier: "",
    highRiskDomain: "",
    gpaiStatus: "",
    systemicRisk: false,
    friaRequired: false,
    deploymentContext: "",
    owner: "",
    market: "",
    datasetName: "",
    datasetVersion: "",
    sourceDescription: "",
    biasMethodology: "",
    safeguards: "",
    instructionsSummary: "",
    instructionsSection: "",
    humanOversightGuidance: "",
    qmsStatus: "",
    qmsApprover: "",
    datasetRef: "",
    trainingDatasetSummary: "",
    consortiumContext: "",
    trainingFlopsEstimate: "",
    thresholdStatus: "",
    thresholdValue: "",
    gpuHours: "",
    acceleratorCount: "",
    monitoringSummary: "",
    authority: "",
    submissionSummary: "",
    friaSummary: "",
    affectedRights: "",
    assessor: "",
    reviewer: "",
    overrideAction: "",
    incidentSummary: "",
    rootCauseSummary: "",
    correctiveActionRef: "",
    notificationSummary: "",
    dueAt: "",
    correspondenceSubject: "",
  };
}

export function DemoProvider({ children }) {
  const [draft, setDraft] = useState(createInitialDraft);
  const [vaultConfig, setVaultConfig] = useState(null);
  const [templateCatalog, setTemplateCatalog] = useState(null);
  const [currentRun, setCurrentRun] = useState(null);
  const [recentRuns, setRecentRuns] = useState([]);
  const [activityLog, setActivityLog] = useState([]);
  const [errors, setErrors] = useState({ connection: "", workflow: "" });
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [isPreviewing, setIsPreviewing] = useState(false);
  const [isExporting, setIsExporting] = useState(false);

  const currentPreset = useMemo(
    () => getPreset(draft.presetKey),
    [draft.presetKey],
  );
  const currentScenario = useMemo(
    () => getPlaygroundScenario(draft.scenarioId),
    [draft.scenarioId],
  );

  useEffect(() => {
    void refreshVaultCapabilities();
  }, []);

  useEffect(() => {
    return () => {
      if (currentRun?.downloadInfo?.url) {
        URL.revokeObjectURL(currentRun.downloadInfo.url);
      }
    };
  }, [currentRun?.downloadInfo?.url]);

  function appendActivity(title, detail, tone = "muted") {
    const time = new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
    setActivityLog((items) =>
      [{ title, detail, tone, time }, ...items].slice(0, 16),
    );
  }

  function buildRunAnnotations(scenario, runState) {
    return {
      review: buildComplianceReview(scenario, runState),
      recordExplainer: buildRecordExplainer(scenario, runState),
    };
  }

  async function loadRecentRuns(systemId = draft.systemId) {
    if (!systemId.trim()) {
      setRecentRuns([]);
      return [];
    }
    const response = await listBundles(draft.serviceUrl, draft.apiKey, {
      system_id: systemId.trim(),
      limit: 10,
    });
    setRecentRuns(response.items ?? []);
    return response.items ?? [];
  }

  function syncTemplateDefaults(catalog, nextDraft) {
    const templates = arrayValue(catalog?.templates);
    if (templates.length === 0) {
      return nextDraft;
    }
    const selected =
      templates.find(
        (template) => template.profile === nextDraft.templateProfile,
      ) ?? templates[0];
    return {
      ...nextDraft,
      templateProfile: selected.profile,
      templateName: nextDraft.templateName?.trim()
        ? nextDraft.templateName
        : defaultTemplateName(selected.profile),
      selectedGroups:
        nextDraft.selectedGroups.length > 0
          ? nextDraft.selectedGroups
          : (selected.default_redaction_groups ?? []),
    };
  }

  async function refreshVaultCapabilities() {
    setIsRefreshing(true);
    setErrors((current) => ({ ...current, connection: "" }));
    try {
      const [configResponse, templateResponse] = await Promise.all([
        fetchVaultConfig(draft.serviceUrl, draft.apiKey),
        fetchDisclosureTemplates(draft.serviceUrl, draft.apiKey),
      ]);
      setVaultConfig(configResponse);
      setTemplateCatalog(templateResponse);
      setDraft((current) => {
        const synced = syncTemplateDefaults(templateResponse, current);
        if (
          !canUseLiveMode(
            configResponse,
            synced.provider,
            synced.providerApiKey,
          ) &&
          synced.mode === "live"
        ) {
          return { ...synced, mode: "synthetic" };
        }
        return synced;
      });
      await loadRecentRuns(draft.systemId);
      appendActivity(
        "Vault connected",
        `${configResponse.service.addr} · ${configResponse.signing.ephemeral ? "ephemeral signer" : "configured signer"}`,
        "good",
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setErrors((current) => ({ ...current, connection: message }));
      appendActivity("Vault connection failed", message, "bad");
    } finally {
      setIsRefreshing(false);
    }
  }

  function updateDraft(key, value) {
    setDraft((current) => {
      if (key === "provider") {
        const nextModelOptions = modelOptionsFor(value);
        const nextModel = nextModelOptions.includes(current.model)
          ? current.model
          : nextModelOptions[0];
        const liveAvailable = canUseLiveMode(
          vaultConfig,
          value,
          current.providerApiKey,
        );
        return {
          ...current,
          provider: value,
          model: nextModel,
          mode:
            current.mode === "live" && !liveAvailable
              ? "synthetic"
              : current.mode,
        };
      }
      if (key === "providerApiKey") {
        const nextValue = value;
        return {
          ...current,
          providerApiKey: nextValue,
          mode:
            current.mode === "live" &&
            !canUseLiveMode(vaultConfig, current.provider, nextValue)
              ? "synthetic"
              : current.mode,
        };
      }
      return { ...current, [key]: value };
    });
  }

  function selectPreset(presetKey) {
    const preset = getPreset(presetKey);
    setDraft((current) => ({
      ...syncTemplateDefaults(
        templateCatalog,
        applyPresetToDraft(current, preset, vaultConfig),
      ),
      playgroundHydrated: false,
    }));
  }

  function selectLane(lane) {
    const scenario = firstScenarioForLane(lane);
    setDraft((current) => applyScenarioToDraft(current, scenario));
  }

  function selectScenario(scenarioId) {
    const scenario = getPlaygroundScenario(scenarioId);
    setDraft((current) => applyScenarioToDraft(current, scenario));
  }

  function ensurePlaygroundDraft() {
    setDraft((current) => {
      if (current.playgroundHydrated) {
        return current;
      }
      return applyScenarioToDraft(
        current,
        getPlaygroundScenario(current.scenarioId),
      );
    });
  }

  function buildTemplateRequest(
    templateProfile = draft.templateProfile,
    selectedGroups = draft.selectedGroups,
    templateName = draft.templateName,
  ) {
    return {
      profile: templateProfile,
      name: templateName?.trim() || defaultTemplateName(templateProfile),
      redaction_groups: selectedGroups,
      redacted_fields_by_item_type: {},
    };
  }

  async function fetchArtefacts(bundleId, bundleArtefacts) {
    const files = await Promise.all(
      arrayValue(bundleArtefacts).map(async (artefact) => {
        const response = await fetchBundleArtefact(
          draft.serviceUrl,
          draft.apiKey,
          bundleId,
          artefact.name,
        );
        return {
          name: artefact.name,
          bytes: new Uint8Array(response.buffer),
          contentType: response.contentType ?? artefact.content_type,
        };
      }),
    );

    const parsed = {};
    for (const file of files) {
      if (file.name.endsWith(".json")) {
        try {
          parsed[file.name] = decodeJsonBytes(file.bytes.buffer);
        } catch {
          // ignore non-JSON payloads
        }
      } else if (file.name.endsWith(".md")) {
        parsed[file.name] = new TextDecoder().decode(file.bytes);
      }
    }

    return { files, parsed };
  }

  async function runInlineVerification(bundle, files) {
    const publicKeyPem = vaultConfig?.signing?.public_key_pem;
    if (!publicKeyPem) {
      return {
        valid: false,
        message: "The connected vault did not expose a public verify key.",
        artefacts_verified: 0,
      };
    }
    return verifyBundle(draft.serviceUrl, draft.apiKey, {
      bundle,
      artefacts: files.map((file) => ({
        name: file.name,
        data_base64: btoa(String.fromCharCode(...file.bytes)),
      })),
      public_key_pem: publicKeyPem,
    });
  }

  async function verifyCreatedBundle(bundle, artefacts) {
    const publicKeyPem = vaultConfig?.signing?.public_key_pem;
    if (!publicKeyPem) {
      return {
        valid: false,
        message: "The connected vault did not expose a public verify key.",
        artefacts_verified: 0,
      };
    }
    return verifyBundle(draft.serviceUrl, draft.apiKey, {
      bundle,
      artefacts: artefacts.map((artefact) => ({
        name: artefact.name,
        data_base64: artefact.data_base64,
      })),
      public_key_pem: publicKeyPem,
    });
  }

  async function evaluateReadinessFor(bundleId, packType, bundle = null) {
    const profile = readinessProfileForPackType(packType);
    if (!profile) {
      return {
        completenessProfile: null,
        completenessReport: null,
      };
    }
    const payload = bundle
      ? { bundle, profile }
      : { bundle_id: bundleId, profile };
    const completenessReport = await evaluateCompleteness(
      draft.serviceUrl,
      draft.apiKey,
      payload,
    );
    appendActivity(
      "Readiness check updated",
      `${completenessReport.status} · ${completenessReport.pass_count} pass / ${completenessReport.warn_count} warn / ${completenessReport.fail_count} fail`,
      completenessReport.status === "fail"
        ? "warn"
        : completenessReport.status === "warn"
          ? "accent"
          : "good",
    );
    return {
      completenessProfile: profile,
      completenessReport,
    };
  }

  async function previewFor(bundleId, systemId, options = {}) {
    const templateProfile = options.templateProfile ?? draft.templateProfile;
    const selectedGroups = options.selectedGroups ?? draft.selectedGroups;
    const bundleFormat = options.bundleFormat ?? draft.bundleFormat;
    const packType = Object.prototype.hasOwnProperty.call(options, "packType")
      ? options.packType
      : currentPreset.packType;
    const payload = {
      bundle_id: bundleId,
      pack_type: packType,
      disclosure_template: buildTemplateRequest(
        templateProfile,
        selectedGroups,
      ),
    };
    const response = await previewDisclosure(
      draft.serviceUrl,
      draft.apiKey,
      payload,
    );
    appendActivity(
      "Disclosure preview ready",
      `${previewStats(response).itemCount} items · ${previewStats(response).artefactCount} artefacts`,
      "accent",
    );
    if (
      bundleFormat === "disclosure" &&
      previewStats(response).itemCount === 0 &&
      previewStats(response).artefactCount === 0
    ) {
      appendActivity(
        "Disclosure result empty",
        "This sharing profile does not reveal any content for this proof record.",
        "warn",
      );
    }
    return response;
  }

  async function exportFor(bundleId, systemId, options = {}) {
    const bundleFormat = options.bundleFormat ?? draft.bundleFormat;
    const templateProfile = options.templateProfile ?? draft.templateProfile;
    const selectedGroups = options.selectedGroups ?? draft.selectedGroups;
    const packType = Object.prototype.hasOwnProperty.call(options, "packType")
      ? options.packType
      : currentPreset.packType;
    const bundleIds = Array.isArray(options.bundleIds)
      ? options.bundleIds.filter((value) => typeof value === "string" && value.trim())
      : [];
    const requestBody = {
      pack_type: packType,
      bundle_format: bundleFormat,
    };
    if (bundleIds.length > 0) {
      requestBody.bundle_ids = bundleIds;
    } else {
      requestBody.system_id = systemId;
    }
    if (bundleFormat === "disclosure") {
      requestBody.disclosure_template = buildTemplateRequest(
        templateProfile,
        selectedGroups,
      );
    }
    const packSummary = await createPack(
      draft.serviceUrl,
      draft.apiKey,
      requestBody,
    );
    const packManifest = await fetchPackManifest(
      draft.serviceUrl,
      draft.apiKey,
      packSummary.pack_id,
    );
    let packCompletenessReport = null;
    const completenessProfile = packCompletenessProfile(packSummary, packManifest);
    if (completenessProfile) {
      try {
        packCompletenessReport = await evaluateCompleteness(
          draft.serviceUrl,
          draft.apiKey,
          {
            pack_id: packSummary.pack_id,
            profile: completenessProfile,
          },
        );
        appendActivity(
          "Exported pack readiness updated",
          `${packCompletenessReport.status} · ${packCompletenessReport.pass_count} pass / ${packCompletenessReport.warn_count} warn / ${packCompletenessReport.fail_count} fail`,
          packCompletenessReport.status === "fail"
            ? "warn"
            : packCompletenessReport.status === "warn"
              ? "accent"
              : "good",
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        appendActivity("Exported pack readiness unavailable", message, "warn");
      }
    }
    const exportPayload = await downloadPackExport(
      draft.serviceUrl,
      draft.apiKey,
      packSummary.pack_id,
    );
    const blob = new Blob([exportPayload.buffer], {
      type: exportPayload.contentType ?? "application/gzip",
    });
    const downloadInfo = {
      url:
        typeof URL.createObjectURL === "function"
          ? URL.createObjectURL(blob)
          : "",
      fileName: `${bundleFormat === "disclosure" ? "disclosure" : "full"}-${bundleId}.pack`,
      size: blob.size,
    };
    appendActivity(
      "Pack exported",
      `${packSummary.bundle_count} bundle(s) · ${formatBytes(blob.size)}`,
      "good",
    );
    return { packSummary, packManifest, packCompletenessReport, downloadInfo };
  }

  async function loadRun(bundleId) {
    const bundle = await fetchBundle(draft.serviceUrl, draft.apiKey, bundleId);
    const { files, parsed } = await fetchArtefacts(bundleId, bundle.artefacts);
    const verifyResponse = await runInlineVerification(bundle, files);
    const responsePayload = parsed["response.json"] ?? null;
    const promptPayload = parsed["prompt.json"] ?? null;
    const tracePayload = parsed["trace.json"] ?? null;
    const itemTypes = bundle.items.map((item) => item.type);
    const inferredPackType =
      currentRun?.bundleId === bundleId
        ? currentRun.packType
        : tracePayload &&
            Object.prototype.hasOwnProperty.call(tracePayload, "pack_type")
          ? tracePayload.pack_type
          : inferPackTypeFromItems(bundle.items);
    const scenario =
      currentRun?.bundleId === bundleId && currentRun?.scenarioId
        ? getPlaygroundScenario(currentRun.scenarioId)
        : findScenarioByPackType(inferredPackType, bundle.items);
    const bundleFormat =
      currentRun?.bundleId === bundleId
        ? currentRun.bundleFormat
        : (tracePayload?.bundle_format ?? draft.bundleFormat);
    const disclosureProfile =
      currentRun?.bundleId === bundleId
        ? currentRun.disclosureProfile
        : (tracePayload?.disclosure_profile ?? draft.templateProfile);
    const packSummary =
      currentRun?.bundleId === bundleId ? currentRun.packSummary : null;
    const packManifest =
      currentRun?.bundleId === bundleId ? currentRun.packManifest : null;
    const downloadInfo =
      currentRun?.bundleId === bundleId ? currentRun.downloadInfo : null;
    const packCompletenessReport =
      currentRun?.bundleId === bundleId
        ? currentRun.packCompletenessReport
        : null;
    const previewResponse =
      inferredPackType !== null
        ? await previewFor(
            bundleId,
            bundle.subject?.system_id ?? draft.systemId,
            {
              packType: inferredPackType,
              bundleFormat,
              templateProfile: disclosureProfile,
            },
          )
        : null;
    const readinessState =
      currentRun?.bundleId === bundleId &&
      currentRun?.completenessProfile ===
        readinessProfileForPackType(inferredPackType)
        ? {
            completenessProfile: currentRun.completenessProfile,
            completenessReport: currentRun.completenessReport,
          }
        : await evaluateReadinessFor(bundleId, inferredPackType, bundle);
    const systemSummary = await fetchSystemSummary(
      draft.serviceUrl,
      draft.apiKey,
      bundle.subject?.system_id ?? draft.systemId,
    );
    let timestampVerification = null;
    if (bundle.timestamp) {
      try {
        timestampVerification = await verifyTimestamp(
          draft.serviceUrl,
          draft.apiKey,
          bundleId,
        );
      } catch (error) {
        timestampVerification = {
          valid: false,
          message: error instanceof Error ? error.message : String(error),
        };
      }
    }
    let receiptVerification = null;
    if (bundle.receipt) {
      try {
        receiptVerification = await verifyReceipt(
          draft.serviceUrl,
          draft.apiKey,
          bundleId,
        );
      } catch (error) {
        receiptVerification = {
          valid: false,
          message: error instanceof Error ? error.message : String(error),
        };
      }
    }
    await loadRecentRuns(bundle.subject?.system_id ?? draft.systemId);

    const scenarioId =
      currentRun?.bundleId === bundleId
        ? currentRun.scenarioId
        : (scenario?.id ?? null);

    const bundleRuns =
      currentRun?.bundleId === bundleId
        ? currentRun.bundleRuns
        : [
            {
              bundleId,
              label: scenario?.label ?? "Loaded bundle",
              bundleRole: "primary",
              itemTypes,
              summary: "Loaded from the vault.",
              verifyResponse,
              timestampVerification,
              receiptVerification,
            },
          ];

    const hydratedRun = {
      bundleId,
      primaryBundleId: bundleId,
      presetKey:
        currentRun?.bundleId === bundleId
          ? currentRun.presetKey
          : inferPresetKey({
              packType: inferredPackType,
              disclosureProfile,
              bundleFormat,
            }),
      scenarioId,
      scenarioLabel:
        currentRun?.bundleId === bundleId
          ? currentRun.scenarioLabel
          : (scenario?.label ?? "Loaded bundle"),
      scenarioOutcomeLabel:
        currentRun?.bundleId === bundleId
          ? currentRun.scenarioOutcomeLabel
          : "Loaded from the vault without the original playground state.",
      lane:
        currentRun?.bundleId === bundleId
          ? currentRun.lane
          : (scenario?.lane ?? "typescript"),
      captureMode:
        responsePayload?.response_source ||
        tracePayload?.capture_mode ||
        "governance_bundle_capture",
      provider: bundle.context?.provider ?? draft.provider,
      model: bundle.context?.model ?? draft.model,
      actorRole: bundle.actor?.role ?? draft.actorRole,
      packType: inferredPackType,
      bundleFormat,
      disclosureProfile,
      createMeta:
        currentRun?.bundleId === bundleId ? currentRun.createMeta : null,
      bundle,
      responseText:
        responsePayload?.output ||
        responsePayload?.output_text ||
        "No direct model response payload is attached to this bundle.",
      promptPayload,
      responsePayload,
      tracePayload,
      artefacts: files.map((file) => ({
        name: file.name,
        content_type: file.contentType,
      })),
      verifyResponse,
      timestampResponse: bundle.timestamp ?? null,
      timestampVerification,
      anchorResponse: bundle.receipt ?? null,
      receiptVerification,
      disclosurePreview: previewResponse,
      packSummary,
      packManifest,
      packCompletenessReport,
      downloadInfo,
      completenessProfile: readinessState.completenessProfile,
      completenessReport: readinessState.completenessReport,
      systemSummary,
      bundleRuns,
      scriptSource:
        currentRun?.bundleId === bundleId
          ? currentRun.scriptSource
          : scenarioId
            ? renderScenarioScript(scenarioId, draft)
            : "",
    };
    Object.assign(
      hydratedRun,
      buildRunAnnotations(scenario, {
        bundle,
        bundleRuns,
        packType: inferredPackType,
        packSummary,
        packManifest,
        packCompletenessReport,
        downloadInfo,
        completenessProfile: readinessState.completenessProfile,
        completenessReport: readinessState.completenessReport,
        scenarioId,
      }),
    );
    setCurrentRun(hydratedRun);
    return hydratedRun;
  }

  async function ensureRunLoaded(bundleId) {
    if (!bundleId) {
      return null;
    }
    if (currentRun?.bundleId === bundleId && currentRun.bundle) {
      return currentRun;
    }
    return loadRun(bundleId);
  }

  async function runBundleLifecycle(step) {
    const createMeta = await createBundle(
      draft.serviceUrl,
      draft.apiKey,
      step.createPayload,
    );
    appendActivity(
      "Bundle sealed",
      `${step.label} · ${createMeta.bundle_id}`,
      "good",
    );

    let bundle = await fetchBundle(
      draft.serviceUrl,
      draft.apiKey,
      createMeta.bundle_id,
    );
    const verifyResponse = await verifyCreatedBundle(
      bundle,
      step.createPayload.artefacts,
    );
    appendActivity(
      verifyResponse.valid ? "Bundle verified" : "Bundle verification warning",
      verifyResponse.valid
        ? `${step.label} verified against the connected signer key.`
        : verifyResponse.message,
      verifyResponse.valid ? "good" : "warn",
    );

    let timestampResponse = null;
    let timestampVerification = null;
    if (draft.attachTimestamp && vaultConfig?.timestamp?.enabled) {
      try {
        timestampResponse = await attachTimestamp(
          draft.serviceUrl,
          draft.apiKey,
          createMeta.bundle_id,
        );
        timestampVerification = await verifyTimestamp(
          draft.serviceUrl,
          draft.apiKey,
          createMeta.bundle_id,
        );
      } catch (error) {
        timestampVerification = {
          valid: false,
          message: error instanceof Error ? error.message : String(error),
        };
      }
    }

    let anchorResponse = null;
    let receiptVerification = null;
    if (
      draft.attachTransparency &&
      vaultConfig?.transparency?.enabled &&
      timestampResponse
    ) {
      try {
        anchorResponse = await anchorBundle(
          draft.serviceUrl,
          draft.apiKey,
          createMeta.bundle_id,
        );
        receiptVerification = await verifyReceipt(
          draft.serviceUrl,
          draft.apiKey,
          createMeta.bundle_id,
        );
      } catch (error) {
        receiptVerification = {
          valid: false,
          message: error instanceof Error ? error.message : String(error),
        };
      }
    }

    if (timestampResponse || anchorResponse) {
      bundle = await fetchBundle(
        draft.serviceUrl,
        draft.apiKey,
        createMeta.bundle_id,
      );
    }

    return {
      ...step,
      bundleId: createMeta.bundle_id,
      timestampRequested: draft.attachTimestamp,
      transparencyRequested: draft.attachTransparency,
      createMeta,
      bundle,
      verifyResponse,
      timestampResponse,
      timestampVerification,
      anchorResponse,
      receiptVerification,
    };
  }

  async function runWorkflow() {
    setIsRunning(true);
    setErrors((current) => ({ ...current, workflow: "" }));
    const preset = currentPreset;

    try {
      if (
        draft.mode === "live" &&
        !canUseLiveMode(vaultConfig, draft.provider, draft.providerApiKey)
      ) {
        throw new Error(
          "Live provider mode needs either provider access already available through the vault or a provider API key entered below.",
        );
      }
      const providerResult = await fetchDemoProviderResponse(
        draft.serviceUrl,
        draft.apiKey,
        {
          mode: draft.mode,
          provider: draft.provider,
          model: draft.model,
          system_prompt: draft.systemPrompt,
          user_prompt: draft.userPrompt,
          provider_api_key: hasTemporaryProviderKey(draft.providerApiKey)
            ? draft.providerApiKey.trim()
            : undefined,
          temperature: Number.parseFloat(draft.temperature) || 0.2,
          max_tokens: Number.parseInt(draft.maxTokens, 10) || 256,
        },
      );
      appendActivity(
        "Capture generated",
        `${providerResult.capture_mode} · ${providerResult.provider}:${providerResult.model}`,
        draft.mode === "live" ? "accent" : "muted",
      );

      const envelope = await buildCaptureEnvelope({
        preset,
        providerResult,
        actorRole: draft.actorRole,
        systemId: draft.systemId.trim() || DEFAULT_SYSTEM_ID,
        temperature: Number.parseFloat(draft.temperature) || 0.2,
        maxTokens: Number.parseInt(draft.maxTokens, 10) || 256,
      });

      const createMeta = await createBundle(
        draft.serviceUrl,
        draft.apiKey,
        envelope.createPayload,
      );
      appendActivity(
        "Bundle sealed",
        `${createMeta.bundle_id} · ${createMeta.bundle_root}`,
        "good",
      );

      let bundle = await fetchBundle(
        draft.serviceUrl,
        draft.apiKey,
        createMeta.bundle_id,
      );
      const verifyResponse = await verifyCreatedBundle(
        bundle,
        envelope.createPayload.artefacts,
      );
      appendActivity(
        verifyResponse.valid
          ? "Bundle verified"
          : "Bundle verification warning",
        verifyResponse.valid
          ? "Verified: bundle signature and artefacts match the connected vault signer key."
          : verifyResponse.message,
        verifyResponse.valid ? "good" : "warn",
      );

      let timestampResponse = null;
      let timestampVerification = null;
      if (draft.attachTimestamp && vaultConfig?.timestamp?.enabled) {
        try {
          timestampResponse = await attachTimestamp(
            draft.serviceUrl,
            draft.apiKey,
            createMeta.bundle_id,
          );
          timestampVerification = await verifyTimestamp(
            draft.serviceUrl,
            draft.apiKey,
            createMeta.bundle_id,
          );
          appendActivity(
            timestampVerification?.assessment?.headline ??
              (timestampVerification.valid
                ? "Timestamp checked"
                : "Timestamp warning"),
            assuranceActivityMessage(
              timestampVerification,
              "The timestamp token matches the current bundle root.",
            ),
            timestampActivityTone(timestampVerification),
          );
        } catch (error) {
          timestampVerification = {
            valid: false,
            message: error instanceof Error ? error.message : String(error),
          };
          appendActivity(
            "Timestamp step failed",
            timestampVerification.message,
            "bad",
          );
        }
      } else if (draft.attachTimestamp) {
        appendActivity(
          "Timestamp not configured",
          "This vault is not configured for RFC 3161 timestamping.",
          "warn",
        );
      }

      let anchorResponse = null;
      let receiptVerification = null;
      if (
        draft.attachTransparency &&
        vaultConfig?.transparency?.enabled &&
        timestampResponse
      ) {
        try {
          anchorResponse = await anchorBundle(
            draft.serviceUrl,
            draft.apiKey,
            createMeta.bundle_id,
          );
          receiptVerification = await verifyReceipt(
            draft.serviceUrl,
            draft.apiKey,
            createMeta.bundle_id,
          );
          appendActivity(
            receiptVerification?.assessment?.headline ??
              (receiptVerification.valid ? "Receipt checked" : "Receipt warning"),
            assuranceActivityMessage(
              receiptVerification,
              "The transparency receipt matches the current bundle.",
            ),
            receiptActivityTone(receiptVerification),
          );
        } catch (error) {
          receiptVerification = {
            valid: false,
            message: error instanceof Error ? error.message : String(error),
          };
          appendActivity(
            "Transparency step failed",
            receiptVerification.message,
            "bad",
          );
        }
      } else if (draft.attachTransparency) {
        appendActivity(
          "Transparency not configured",
          "This vault is not configured for a transparency receipt on this run.",
          "warn",
        );
      }

      if (timestampResponse || anchorResponse) {
        bundle = await fetchBundle(
          draft.serviceUrl,
          draft.apiKey,
          createMeta.bundle_id,
        );
      }

      const disclosurePreview = await previewFor(
        createMeta.bundle_id,
        bundle.subject?.system_id ?? draft.systemId,
        {
          packType: preset.packType,
          bundleFormat: draft.bundleFormat,
        },
      );
      const stats = previewStats(disclosurePreview);
      let exportState = {
        packSummary: null,
        packManifest: null,
        packCompletenessReport: null,
        downloadInfo: null,
      };
      if (
        draft.bundleFormat === "full" ||
        stats.itemCount > 0 ||
        stats.artefactCount > 0
      ) {
        exportState = await exportFor(
          createMeta.bundle_id,
          bundle.subject?.system_id ?? draft.systemId,
          {
            packType: preset.packType,
            bundleFormat: draft.bundleFormat,
            bundleIds: [createMeta.bundle_id],
          },
        );
      } else {
        appendActivity(
          "Export skipped",
          "This proof record does not produce a redacted share package under the selected sharing profile.",
          "warn",
        );
      }

      const readinessState = await evaluateReadinessFor(
        createMeta.bundle_id,
        preset.packType,
        bundle,
      );

      const systemSummary = await fetchSystemSummary(
        draft.serviceUrl,
        draft.apiKey,
        bundle.subject?.system_id ?? draft.systemId,
      );
      await loadRecentRuns(bundle.subject?.system_id ?? draft.systemId);

      const nextRun = {
        bundleId: createMeta.bundle_id,
        primaryBundleId: createMeta.bundle_id,
        presetKey: preset.key,
        captureMode: providerResult.capture_mode,
        provider: providerResult.provider,
        model: providerResult.model,
        actorRole: draft.actorRole,
        packType: preset.packType,
        bundleFormat: draft.bundleFormat,
        disclosureProfile: draft.templateProfile,
        createMeta,
        bundle,
        responseText: envelope.responseText,
        promptPayload: envelope.promptPayload,
        responsePayload: envelope.responsePayload,
        tracePayload: envelope.tracePayload,
        artefacts: envelope.createPayload.artefacts,
        verifyResponse,
        timestampResponse,
        timestampVerification,
        anchorResponse,
        receiptVerification,
        disclosurePreview,
        packSummary: exportState.packSummary,
        packManifest: exportState.packManifest,
        packCompletenessReport: exportState.packCompletenessReport,
        downloadInfo: exportState.downloadInfo,
        completenessProfile: readinessState.completenessProfile,
        completenessReport: readinessState.completenessReport,
        systemSummary,
        bundleRuns: [
          {
            bundleId: createMeta.bundle_id,
            label: preset.label,
            bundleRole: "primary",
            timestampRequested: draft.attachTimestamp,
            transparencyRequested: draft.attachTransparency,
            itemTypes:
              envelope.itemTypes ??
              envelope.createPayload.capture.items.map((item) => item.type),
            summary: preset.outcomeLabel,
            verifyResponse,
            timestampVerification,
            receiptVerification,
          },
        ],
      };
      Object.assign(
        nextRun,
        buildRunAnnotations(null, {
          ...nextRun,
          scenarioId: null,
        }),
      );
      setCurrentRun(nextRun);
      return createMeta.bundle_id;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setErrors((current) => ({ ...current, workflow: message }));
      appendActivity("Workflow failed", message, "bad");
      throw error;
    } finally {
      setIsRunning(false);
    }
  }

  async function runScenarioWorkflow() {
    setIsRunning(true);
    setErrors((current) => ({ ...current, workflow: "" }));
    const scenario = currentScenario;

    try {
      let providerResult = null;
      const needsInteraction = scenario.steps.some(
        (step) => step.kind === "interaction",
      );
      if (needsInteraction) {
        if (
          draft.mode === "live" &&
          !canUseLiveMode(vaultConfig, draft.provider, draft.providerApiKey)
        ) {
          throw new Error(
            "Live provider mode needs either provider access already available through the vault or a provider API key entered below.",
          );
        }
        providerResult = await fetchDemoProviderResponse(
          draft.serviceUrl,
          draft.apiKey,
          {
            mode: draft.mode,
            provider: draft.provider,
            model: draft.model,
            system_prompt: draft.systemPrompt,
            user_prompt: draft.userPrompt,
            provider_api_key: hasTemporaryProviderKey(draft.providerApiKey)
              ? draft.providerApiKey.trim()
              : undefined,
            temperature: Number.parseFloat(draft.temperature) || 0.2,
            max_tokens: Number.parseInt(draft.maxTokens, 10) || 256,
          },
        );
        appendActivity(
          "Scenario capture generated",
          `${providerResult.capture_mode} · ${providerResult.provider}:${providerResult.model}`,
          draft.mode === "live" ? "accent" : "muted",
        );
      }

      const steps = await buildScenarioWorkflow(
        scenario,
        draft,
        providerResult,
      );
      const bundleRuns = [];
      for (const step of steps) {
        bundleRuns.push(await runBundleLifecycle(step));
      }

      const primaryBundle =
        bundleRuns.find((bundleRun) => bundleRun.bundleRole === "primary") ??
        bundleRuns[0];
      const disclosurePreview =
        scenario.packType !== null
          ? await previewFor(primaryBundle.bundleId, draft.systemId, {
              packType: scenario.packType,
              bundleFormat: scenario.bundleFormat,
              templateProfile: scenario.disclosureProfile,
            })
          : null;
      const exportState =
        scenario.packType !== null
          ? await exportFor(primaryBundle.bundleId, draft.systemId, {
              packType: scenario.packType,
              bundleFormat: scenario.bundleFormat,
              templateProfile: scenario.disclosureProfile,
              bundleIds: bundleRuns.map((bundleRun) => bundleRun.bundleId),
            })
          : {
              packSummary: null,
              packManifest: null,
              packCompletenessReport: null,
              downloadInfo: null,
            };
      const readinessState = await evaluateReadinessFor(
        primaryBundle.bundleId,
        scenario.packType,
        primaryBundle.bundle,
      );
      const systemSummary = await fetchSystemSummary(
        draft.serviceUrl,
        draft.apiKey,
        draft.systemId,
      );
      await loadRecentRuns(draft.systemId);

      const scriptSource = renderScenarioScript(scenario, draft);
      const review = buildComplianceReview(scenario, {
        bundleRuns,
        packSummary: exportState.packSummary,
        packManifest: exportState.packManifest,
        packCompletenessReport: exportState.packCompletenessReport,
        downloadInfo: exportState.downloadInfo,
        completenessProfile: readinessState.completenessProfile,
        completenessReport: readinessState.completenessReport,
      });
      const recordExplainer = buildRecordExplainer(scenario, {
        bundle: primaryBundle.bundle,
        bundleRuns,
        packType: scenario.packType,
        packSummary: exportState.packSummary,
        packManifest: exportState.packManifest,
        packCompletenessReport: exportState.packCompletenessReport,
        downloadInfo: exportState.downloadInfo,
      });
      const nextRun = {
        bundleId: primaryBundle.bundleId,
        primaryBundleId: primaryBundle.bundleId,
        scenarioId: scenario.id,
        scenarioLabel: scenario.label,
        scenarioOutcomeLabel: scenario.description,
        lane: scenario.lane,
        captureMode:
          providerResult?.capture_mode ??
          (scenario.lane === "cli"
            ? "cli_playground_capture"
            : "governance_bundle_capture"),
        provider: providerResult?.provider ?? null,
        model: providerResult?.model ?? null,
        actorRole: scenario.actorRole,
        packType: scenario.packType,
        bundleFormat: scenario.bundleFormat,
        disclosureProfile: scenario.disclosureProfile,
        createMeta: primaryBundle.createMeta,
        bundle: primaryBundle.bundle,
        responseText:
          primaryBundle.responseText ??
          primaryBundle.localPayloads?.report?.summary ??
          "This scenario focuses on governance evidence rather than a direct model response.",
        promptPayload: primaryBundle.promptPayload ?? null,
        responsePayload: primaryBundle.responsePayload ?? null,
        tracePayload: primaryBundle.tracePayload ?? null,
        artefacts: primaryBundle.createPayload.artefacts,
        verifyResponse: primaryBundle.verifyResponse,
        timestampResponse: primaryBundle.timestampResponse,
        timestampVerification: primaryBundle.timestampVerification,
        anchorResponse: primaryBundle.anchorResponse,
        receiptVerification: primaryBundle.receiptVerification,
        disclosurePreview,
        packSummary: exportState.packSummary,
        packManifest: exportState.packManifest,
        packCompletenessReport: exportState.packCompletenessReport,
        downloadInfo: exportState.downloadInfo,
        completenessProfile: readinessState.completenessProfile,
        completenessReport: readinessState.completenessReport,
        systemSummary,
        bundleRuns,
        scriptSource,
        review,
        recordExplainer,
      };
      setCurrentRun(nextRun);
      return primaryBundle.bundleId;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setErrors((current) => ({ ...current, workflow: message }));
      appendActivity("Scenario workflow failed", message, "bad");
      throw error;
    } finally {
      setIsRunning(false);
    }
  }

  async function previewCurrentRun() {
    if (!currentRun?.bundleId || currentRun.packType === null) {
      return null;
    }
    setIsPreviewing(true);
    try {
      const response = await previewFor(
        currentRun.bundleId,
        currentRun.bundle?.subject?.system_id ?? draft.systemId,
        {
          packType: currentRun.packType,
          bundleFormat: currentRun.bundleFormat,
          templateProfile: currentRun.disclosureProfile,
        },
      );
      setCurrentRun((run) =>
        run ? { ...run, disclosurePreview: response } : run,
      );
      return response;
    } finally {
      setIsPreviewing(false);
    }
  }

  async function exportCurrentRun() {
    if (
      !currentRun?.bundleId ||
      !currentRun.bundle?.subject?.system_id ||
      currentRun.packType === null
    ) {
      return null;
    }
    setIsExporting(true);
    try {
      const stats = previewStats(currentRun.disclosurePreview);
      if (
        currentRun.bundleFormat === "disclosure" &&
        stats.itemCount === 0 &&
        stats.artefactCount === 0
      ) {
        appendActivity(
          "Export skipped",
          "This proof record does not produce a redacted share package under the selected sharing profile.",
          "warn",
        );
        return null;
      }
      const exportState = await exportFor(
        currentRun.bundleId,
        currentRun.bundle.subject.system_id,
        {
          packType: currentRun.packType,
          bundleFormat: currentRun.bundleFormat,
          templateProfile: currentRun.disclosureProfile,
          bundleIds: currentRun.bundleRuns.map((bundleRun) => bundleRun.bundleId),
        },
      );
      setCurrentRun((run) => {
        if (!run) {
          return run;
        }
        const nextRun = {
          ...run,
          packSummary: exportState.packSummary,
          packManifest: exportState.packManifest,
          packCompletenessReport: exportState.packCompletenessReport,
          downloadInfo: exportState.downloadInfo,
        };
        return {
          ...nextRun,
          ...buildRunAnnotations(
            run.scenarioId ? getPlaygroundScenario(run.scenarioId) : null,
            nextRun,
          ),
        };
      });
      return exportState;
    } finally {
      setIsExporting(false);
    }
  }

  const value = {
    draft,
    vaultConfig,
    templateCatalog,
    currentPreset,
    currentScenario,
    currentRun,
    recentRuns,
    activityLog,
    errors,
    isRefreshing,
    isRunning,
    isPreviewing,
    isExporting,
    actions: {
      refreshVaultCapabilities,
      updateDraft,
      selectPreset,
      selectLane,
      selectScenario,
      ensurePlaygroundDraft,
      runWorkflow,
      runScenarioWorkflow,
      previewCurrentRun,
      exportCurrentRun,
      ensureRunLoaded,
      loadRecentRuns,
    },
  };

  return <DemoContext.Provider value={value}>{children}</DemoContext.Provider>;
}

export function useDemo() {
  const value = useContext(DemoContext);
  if (!value) {
    throw new Error("useDemo must be used within DemoProvider");
  }
  return value;
}
