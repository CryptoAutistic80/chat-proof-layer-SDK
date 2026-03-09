import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import {
  attachTimestamp,
  anchorBundle,
  createBundle,
  createPack,
  downloadPackExport,
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
  verifyTimestamp
} from "../lib/vaultApi";
import {
  DEFAULT_SERVICE_URL,
  DEFAULT_SYSTEM_ID,
  PRESETS,
  applyPresetToDraft,
  defaultModelFor,
  defaultTemplateName,
  getPreset,
  isProviderLiveEnabled,
  modelOptionsFor
} from "../lib/presets";
import { buildCaptureEnvelope, decodeJsonBytes } from "../lib/captureBuilders";

const DemoContext = createContext(null);

function arrayValue(value) {
  return Array.isArray(value) ? value : [];
}

function previewStats(preview) {
  return {
    itemCount: arrayValue(preview?.disclosed_item_indices).length,
    artefactCount: arrayValue(preview?.disclosed_artefact_names).length
  };
}

function hasTemporaryProviderKey(value) {
  return Boolean(value && value.trim());
}

function canUseLiveMode(vaultConfig, provider, providerApiKey) {
  return isProviderLiveEnabled(vaultConfig, provider) || hasTemporaryProviderKey(providerApiKey);
}

function createInitialDraft() {
  const preset = getPreset("investor_summary");
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
    selectedGroups: []
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

  const currentPreset = useMemo(() => getPreset(draft.presetKey), [draft.presetKey]);

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
      second: "2-digit"
    });
    setActivityLog((items) => [{ title, detail, tone, time }, ...items].slice(0, 16));
  }

  async function loadRecentRuns(systemId = draft.systemId) {
    if (!systemId.trim()) {
      setRecentRuns([]);
      return [];
    }
    const response = await listBundles(draft.serviceUrl, draft.apiKey, {
      system_id: systemId.trim(),
      limit: 10
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
      templates.find((template) => template.profile === nextDraft.templateProfile) ?? templates[0];
    return {
      ...nextDraft,
      templateProfile: selected.profile,
      templateName: nextDraft.templateName?.trim()
        ? nextDraft.templateName
        : defaultTemplateName(selected.profile),
      selectedGroups:
        nextDraft.selectedGroups.length > 0
          ? nextDraft.selectedGroups
          : selected.default_redaction_groups ?? []
    };
  }

  async function refreshVaultCapabilities() {
    setIsRefreshing(true);
    setErrors((current) => ({ ...current, connection: "" }));
    try {
      const [configResponse, templateResponse] = await Promise.all([
        fetchVaultConfig(draft.serviceUrl, draft.apiKey),
        fetchDisclosureTemplates(draft.serviceUrl, draft.apiKey)
      ]);
      setVaultConfig(configResponse);
      setTemplateCatalog(templateResponse);
      setDraft((current) => {
        const synced = syncTemplateDefaults(templateResponse, current);
        if (!canUseLiveMode(configResponse, synced.provider, synced.providerApiKey) && synced.mode === "live") {
          return { ...synced, mode: "synthetic" };
        }
        return synced;
      });
      await loadRecentRuns(draft.systemId);
      appendActivity(
        "Vault connected",
        `${configResponse.service.addr} · ${configResponse.signing.ephemeral ? "ephemeral signer" : "configured signer"}`,
        "good"
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
        const liveAvailable = canUseLiveMode(vaultConfig, value, current.providerApiKey);
        return {
          ...current,
          provider: value,
          model: nextModel,
          mode: current.mode === "live" && !liveAvailable ? "synthetic" : current.mode
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
              : current.mode
        };
      }
      return { ...current, [key]: value };
    });
  }

  function selectPreset(presetKey) {
    const preset = getPreset(presetKey);
    setDraft((current) => syncTemplateDefaults(templateCatalog, applyPresetToDraft(current, preset, vaultConfig)));
  }

  function buildTemplateRequest() {
    return {
      profile: draft.templateProfile,
      name: draft.templateName.trim() || defaultTemplateName(draft.templateProfile),
      redaction_groups: draft.selectedGroups,
      redacted_fields_by_item_type: {}
    };
  }

  async function fetchArtefacts(bundleId, bundleArtefacts) {
    const files = await Promise.all(
      arrayValue(bundleArtefacts).map(async (artefact) => {
        const response = await fetchBundleArtefact(
          draft.serviceUrl,
          draft.apiKey,
          bundleId,
          artefact.name
        );
        return {
          name: artefact.name,
          bytes: new Uint8Array(response.buffer),
          contentType: response.contentType ?? artefact.content_type
        };
      })
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
        artefacts_verified: 0
      };
    }
    return verifyBundle(draft.serviceUrl, draft.apiKey, {
      bundle,
      artefacts: files.map((file) => ({
        name: file.name,
        data_base64: btoa(String.fromCharCode(...file.bytes))
      })),
      public_key_pem: publicKeyPem
    });
  }

  async function previewFor(bundleId, systemId, currentBundleFormat = draft.bundleFormat) {
    const payload = {
      bundle_id: bundleId,
      pack_type: currentPreset.packType,
      disclosure_template: buildTemplateRequest()
    };
    const response = await previewDisclosure(draft.serviceUrl, draft.apiKey, payload);
    appendActivity(
      "Disclosure preview ready",
      `${previewStats(response).itemCount} items · ${previewStats(response).artefactCount} artefacts`,
      "accent"
    );
    if (
      currentBundleFormat === "disclosure" &&
      previewStats(response).itemCount === 0 &&
      previewStats(response).artefactCount === 0
    ) {
      appendActivity(
        "Disclosure result empty",
        "No disclosure output for this profile on the current run.",
        "warn"
      );
    }
    return response;
  }

  async function exportFor(bundleId, systemId, currentBundleFormat = draft.bundleFormat) {
    const requestBody = {
      pack_type: currentPreset.packType,
      system_id: systemId,
      bundle_format: currentBundleFormat
    };
    if (currentBundleFormat === "disclosure") {
      requestBody.disclosure_template = buildTemplateRequest();
    }
    const packSummary = await createPack(draft.serviceUrl, draft.apiKey, requestBody);
    const packManifest = await fetchPackManifest(draft.serviceUrl, draft.apiKey, packSummary.pack_id);
    const exportPayload = await downloadPackExport(
      draft.serviceUrl,
      draft.apiKey,
      packSummary.pack_id
    );
    const blob = new Blob([exportPayload.buffer], {
      type: exportPayload.contentType ?? "application/gzip"
    });
    const downloadInfo = {
      url: URL.createObjectURL(blob),
      fileName: `${currentBundleFormat === "disclosure" ? "disclosure" : "full"}-${bundleId}.pack`,
      size: blob.size
    };
    appendActivity(
      "Pack exported",
      `${packSummary.bundle_count} bundle(s) · ${formatBytes(blob.size)}`,
      "good"
    );
    return { packSummary, packManifest, downloadInfo };
  }

  async function loadRun(bundleId) {
    const bundle = await fetchBundle(draft.serviceUrl, draft.apiKey, bundleId);
    const { files, parsed } = await fetchArtefacts(bundleId, bundle.artefacts);
    const verifyResponse = await runInlineVerification(bundle, files);
    const previewResponse = await previewFor(
      bundleId,
      bundle.subject?.system_id ?? draft.systemId,
      draft.bundleFormat
    );
    const systemSummary = await fetchSystemSummary(
      draft.serviceUrl,
      draft.apiKey,
      bundle.subject?.system_id ?? draft.systemId
    );
    let timestampVerification = null;
    if (bundle.timestamp) {
      try {
        timestampVerification = await verifyTimestamp(draft.serviceUrl, draft.apiKey, bundleId);
      } catch (error) {
        timestampVerification = {
          valid: false,
          message: error instanceof Error ? error.message : String(error)
        };
      }
    }
    let receiptVerification = null;
    if (bundle.receipt) {
      try {
        receiptVerification = await verifyReceipt(draft.serviceUrl, draft.apiKey, bundleId);
      } catch (error) {
        receiptVerification = {
          valid: false,
          message: error instanceof Error ? error.message : String(error)
        };
      }
    }
    await loadRecentRuns(bundle.subject?.system_id ?? draft.systemId);

    const responsePayload = parsed["response.json"] ?? null;
    const promptPayload = parsed["prompt.json"] ?? null;
    const tracePayload = parsed["trace.json"] ?? null;

    const hydratedRun = {
      bundleId,
      captureMode:
        responsePayload?.response_source ||
        tracePayload?.capture_mode ||
        "synthetic_demo_capture",
      provider: bundle.context?.provider ?? draft.provider,
      model: bundle.context?.model ?? draft.model,
      actorRole: bundle.actor?.role ?? draft.actorRole,
      packType: currentPreset.packType,
      bundleFormat: draft.bundleFormat,
      disclosureProfile: draft.templateProfile,
      createMeta: currentRun?.bundleId === bundleId ? currentRun.createMeta : null,
      bundle,
      responseText:
        responsePayload?.output ||
        responsePayload?.output_text ||
        "Response payload not available.",
      promptPayload,
      responsePayload,
      tracePayload,
      artefacts: files.map((file) => ({
        name: file.name,
        content_type: file.contentType
      })),
      verifyResponse,
      timestampResponse: bundle.timestamp ?? null,
      timestampVerification,
      anchorResponse: bundle.receipt ?? null,
      receiptVerification,
      disclosurePreview: previewResponse,
      packSummary: currentRun?.bundleId === bundleId ? currentRun.packSummary : null,
      packManifest: currentRun?.bundleId === bundleId ? currentRun.packManifest : null,
      downloadInfo: currentRun?.bundleId === bundleId ? currentRun.downloadInfo : null,
      systemSummary
    };
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
          "Live provider mode requires either a vault-configured provider key or a temporary provider API key in the playground."
        );
      }
      const providerResult = await fetchDemoProviderResponse(draft.serviceUrl, draft.apiKey, {
        mode: draft.mode,
        provider: draft.provider,
        model: draft.model,
        system_prompt: draft.systemPrompt,
        user_prompt: draft.userPrompt,
        provider_api_key: hasTemporaryProviderKey(draft.providerApiKey)
          ? draft.providerApiKey.trim()
          : undefined,
        temperature: Number.parseFloat(draft.temperature) || 0.2,
        max_tokens: Number.parseInt(draft.maxTokens, 10) || 256
      });
      appendActivity(
        "Capture generated",
        `${providerResult.capture_mode} · ${providerResult.provider}:${providerResult.model}`,
        draft.mode === "live" ? "accent" : "muted"
      );

      const envelope = await buildCaptureEnvelope({
        preset,
        providerResult,
        actorRole: draft.actorRole,
        systemId: draft.systemId.trim() || DEFAULT_SYSTEM_ID,
        temperature: Number.parseFloat(draft.temperature) || 0.2,
        maxTokens: Number.parseInt(draft.maxTokens, 10) || 256
      });

      const createMeta = await createBundle(draft.serviceUrl, draft.apiKey, envelope.createPayload);
      appendActivity(
        "Bundle sealed",
        `${createMeta.bundle_id} · ${createMeta.bundle_root}`,
        "good"
      );

      let bundle = await fetchBundle(draft.serviceUrl, draft.apiKey, createMeta.bundle_id);
      const verifyResponse = await verifyBundle(draft.serviceUrl, draft.apiKey, {
        bundle,
        artefacts: envelope.createPayload.artefacts.map((artefact) => ({
          name: artefact.name,
          data_base64: artefact.data_base64
        })),
        public_key_pem: vaultConfig?.signing?.public_key_pem ?? ""
      });
      appendActivity(
        verifyResponse.valid ? "Bundle verified" : "Bundle verification warning",
        verifyResponse.valid
          ? "Verified: bundle signature and artefacts match the connected vault signer key."
          : verifyResponse.message,
        verifyResponse.valid ? "good" : "warn"
      );

      let timestampResponse = null;
      let timestampVerification = null;
      if (draft.attachTimestamp && vaultConfig?.timestamp?.enabled) {
        try {
          timestampResponse = await attachTimestamp(draft.serviceUrl, draft.apiKey, createMeta.bundle_id);
          timestampVerification = await verifyTimestamp(
            draft.serviceUrl,
            draft.apiKey,
            createMeta.bundle_id
          );
          appendActivity(
            timestampVerification.valid ? "Timestamp checked" : "Timestamp warning",
            timestampVerification.valid
              ? "Verified: the timestamp token matches the current bundle root."
              : timestampVerification.message,
            timestampVerification.valid ? "good" : "warn"
          );
        } catch (error) {
          timestampVerification = {
            valid: false,
            message: error instanceof Error ? error.message : String(error)
          };
          appendActivity("Timestamp step failed", timestampVerification.message, "bad");
        }
      } else if (draft.attachTimestamp) {
        appendActivity("Timestamp not configured", "This vault is not configured for RFC 3161 timestamping.", "warn");
      }

      let anchorResponse = null;
      let receiptVerification = null;
      if (draft.attachTransparency && vaultConfig?.transparency?.enabled && timestampResponse) {
        try {
          anchorResponse = await anchorBundle(draft.serviceUrl, draft.apiKey, createMeta.bundle_id);
          receiptVerification = await verifyReceipt(
            draft.serviceUrl,
            draft.apiKey,
            createMeta.bundle_id
          );
          appendActivity(
            receiptVerification.valid ? "Receipt checked" : "Receipt warning",
            receiptVerification.valid
              ? "Verified: the transparency receipt matches the current bundle."
              : receiptVerification.message,
            receiptVerification.valid ? "good" : "warn"
          );
        } catch (error) {
          receiptVerification = {
            valid: false,
            message: error instanceof Error ? error.message : String(error)
          };
          appendActivity("Transparency step failed", receiptVerification.message, "bad");
        }
      } else if (draft.attachTransparency) {
        appendActivity(
          "Transparency not configured",
          "This vault is not configured for a transparency receipt on this run.",
          "warn"
        );
      }

      if (timestampResponse || anchorResponse) {
        bundle = await fetchBundle(draft.serviceUrl, draft.apiKey, createMeta.bundle_id);
      }

      const disclosurePreview = await previewFor(
        createMeta.bundle_id,
        bundle.subject?.system_id ?? draft.systemId,
        draft.bundleFormat
      );
      const stats = previewStats(disclosurePreview);
      let exportState = {
        packSummary: null,
        packManifest: null,
        downloadInfo: null
      };
      if (draft.bundleFormat === "full" || stats.itemCount > 0 || stats.artefactCount > 0) {
        exportState = await exportFor(
          createMeta.bundle_id,
          bundle.subject?.system_id ?? draft.systemId,
          draft.bundleFormat
        );
      } else {
        appendActivity(
          "Export skipped",
          "No disclosure pack to export for this run with the selected profile.",
          "warn"
        );
      }

      const systemSummary = await fetchSystemSummary(
        draft.serviceUrl,
        draft.apiKey,
        bundle.subject?.system_id ?? draft.systemId
      );
      await loadRecentRuns(bundle.subject?.system_id ?? draft.systemId);

      const nextRun = {
        bundleId: createMeta.bundle_id,
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
        downloadInfo: exportState.downloadInfo,
        systemSummary
      };
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

  async function previewCurrentRun() {
    if (!currentRun?.bundleId) {
      return null;
    }
    setIsPreviewing(true);
    try {
      const response = await previewFor(
        currentRun.bundleId,
        currentRun.bundle?.subject?.system_id ?? draft.systemId,
        currentRun.bundleFormat
      );
      setCurrentRun((run) => (run ? { ...run, disclosurePreview: response } : run));
      return response;
    } finally {
      setIsPreviewing(false);
    }
  }

  async function exportCurrentRun() {
    if (!currentRun?.bundleId || !currentRun.bundle?.subject?.system_id) {
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
          "No disclosure pack to export for this run with the selected profile.",
          "warn"
        );
        return null;
      }
      const exportState = await exportFor(
        currentRun.bundleId,
        currentRun.bundle.subject.system_id,
        currentRun.bundleFormat
      );
      setCurrentRun((run) =>
        run
          ? {
              ...run,
              packSummary: exportState.packSummary,
              packManifest: exportState.packManifest,
              downloadInfo: exportState.downloadInfo
            }
          : run
      );
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
      runWorkflow,
      previewCurrentRun,
      exportCurrentRun,
      ensureRunLoaded,
      loadRecentRuns
    }
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
