import React, { useEffect, useState } from "react";

const enc = new TextEncoder();
const DEFAULT_SERVICE_URL = "http://127.0.0.1:8080";
const DEFAULT_SYSTEM_ID = "investor-demo-system";
const DEFAULT_TEMPLATE_PROFILE = "runtime_minimum";
const PACK_TYPE = "runtime_logs";

const PROVIDER_MODELS = {
  anthropic: ["claude-sonnet-4-6", "claude-haiku-4-5"],
  openai: ["gpt-4o", "gpt-4o-mini"]
};

function encodeBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary);
}

async function sha256Prefixed(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const hex = Array.from(new Uint8Array(digest))
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
  return `sha256:${hex}`;
}

function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

function normalizeBaseUrl(value) {
  return value.trim().replace(/\/$/, "");
}

function modelOptionsFor(provider) {
  return PROVIDER_MODELS[provider] ?? PROVIDER_MODELS.openai;
}

function defaultModelFor(provider) {
  return modelOptionsFor(provider)[0];
}

function buildMockResponse(provider, systemPrompt, userPrompt, model) {
  const lead = provider === "anthropic" ? "Anthropic" : "OpenAI";
  const promptExcerpt = userPrompt.trim().slice(0, 180);
  const policyNote = systemPrompt.trim().slice(0, 70);
  return [
    `${lead} ${model} response`,
    `Prompt focus: ${promptExcerpt || "No prompt provided."}`,
    `Grounding: ${policyNote || "No system guidance provided."}`,
    "Recorded for proof-layer verification, disclosure preview, and export."
  ].join("\n\n");
}

function authHeaders(apiKey) {
  if (!apiKey.trim()) {
    return {};
  }
  return { Authorization: `Bearer ${apiKey.trim()}` };
}

async function parseJsonBody(response) {
  const text = await response.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return { error: text };
  }
}

function extractErrorMessage(payload, fallback) {
  if (!payload) {
    return fallback;
  }
  if (typeof payload === "string") {
    return payload;
  }
  if (typeof payload.error === "string") {
    return payload.error;
  }
  if (typeof payload.message === "string") {
    return payload.message;
  }
  return fallback;
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const payload = await parseJsonBody(response);
  if (!response.ok) {
    throw new Error(extractErrorMessage(payload, `${response.status} ${response.statusText}`));
  }
  return payload;
}

async function requestBinary(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const payload = await parseJsonBody(response);
    throw new Error(extractErrorMessage(payload, `${response.status} ${response.statusText}`));
  }
  const buffer = await response.arrayBuffer();
  return {
    buffer,
    contentType: response.headers.get("content-type"),
    disposition: response.headers.get("content-disposition")
  };
}

function formatBytes(byteCount) {
  if (typeof byteCount !== "number" || Number.isNaN(byteCount)) {
    return "-";
  }
  if (byteCount < 1024) {
    return `${byteCount} B`;
  }
  if (byteCount < 1024 * 1024) {
    return `${(byteCount / 1024).toFixed(1)} KB`;
  }
  return `${(byteCount / (1024 * 1024)).toFixed(1)} MB`;
}

function formatStatusTone(value) {
  if (value === "done") {
    return "good";
  }
  if (value === "warn" || value === "optional") {
    return "warn";
  }
  if (value === "error") {
    return "bad";
  }
  if (value === "active") {
    return "accent";
  }
  return "muted";
}

function capabilityValue(config, templates) {
  if (!config) {
    return [];
  }
  return [
    {
      label: "Vault",
      value: config.service.tls_enabled ? "HTTPS ready" : "HTTP demo mode",
      tone: config.service.tls_enabled ? "good" : "warn"
    },
    {
      label: "Auth",
      value: config.auth.enabled
        ? `Bearer · ${config.auth.principal_labels.join(", ")}`
        : "Open in local mode",
      tone: config.auth.enabled ? "accent" : "muted"
    },
    {
      label: "Timestamp",
      value: config.timestamp.enabled
        ? `${config.timestamp.provider} · ${config.timestamp.assurance ?? "standard"}`
        : "Disabled",
      tone: config.timestamp.enabled ? "good" : "warn"
    },
    {
      label: "Transparency",
      value: config.transparency.enabled
        ? config.transparency.provider
        : "Disabled",
      tone: config.transparency.enabled ? "good" : "warn"
    },
    {
      label: "Tenant",
      value: config.tenant.enforced
        ? config.tenant.organization_id ?? "Scoped"
        : "Single-node local",
      tone: config.tenant.enforced ? "accent" : "muted"
    },
    {
      label: "Backups",
      value: config.backup.enabled
        ? `${config.backup.retention_count} retained${config.backup.encryption.enabled ? " · encrypted" : ""}`
        : "Manual only",
      tone: config.backup.enabled ? "good" : "warn"
    },
    {
      label: "Disclosure",
      value: templates?.templates?.length
        ? `${templates.templates.length} templates`
        : "Templates unavailable",
      tone: templates?.templates?.length ? "accent" : "warn"
    }
  ];
}

function defaultTemplateName(profile) {
  return `${profile}_web_demo`;
}

function TimelineStep({ title, status, detail }) {
  return (
    <article className={`timeline-step is-${formatStatusTone(status)}`}>
      <div className="timeline-step-header">
        <h3>{title}</h3>
        <span className={`status-chip is-${formatStatusTone(status)}`}>{status}</span>
      </div>
      <p>{detail}</p>
    </article>
  );
}

function DataPanel({ title, subtitle, value, placeholder }) {
  return (
    <section className="data-panel">
      <div className="data-panel-head">
        <h3>{title}</h3>
        {subtitle ? <span>{subtitle}</span> : null}
      </div>
      <pre>{value ? prettyJson(value) : placeholder}</pre>
    </section>
  );
}

function ActivityRow({ entry }) {
  return (
    <li className={`activity-row is-${entry.tone}`}>
      <div>
        <strong>{entry.title}</strong>
        <span>{entry.detail}</span>
      </div>
      <time>{entry.time}</time>
    </li>
  );
}

export function App() {
  const [serviceUrl, setServiceUrl] = useState(DEFAULT_SERVICE_URL);
  const [apiKey, setApiKey] = useState("");
  const [publicKeyPem, setPublicKeyPem] = useState("");
  const [provider, setProvider] = useState("anthropic");
  const [model, setModel] = useState(defaultModelFor("anthropic"));
  const [actorRole, setActorRole] = useState("provider");
  const [systemId, setSystemId] = useState(DEFAULT_SYSTEM_ID);
  const [systemPrompt, setSystemPrompt] = useState(
    "You are a risk-aware operations copilot. Answer precisely and stay within policy."
  );
  const [userPrompt, setUserPrompt] = useState(
    "Draft a short summary of what this proof vault can demonstrate to an investor."
  );
  const [temperature, setTemperature] = useState("0.2");
  const [attachTimestamp, setAttachTimestamp] = useState(true);
  const [attachTransparency, setAttachTransparency] = useState(true);
  const [bundleFormat, setBundleFormat] = useState("disclosure");
  const [templateProfile, setTemplateProfile] = useState(DEFAULT_TEMPLATE_PROFILE);
  const [templateName, setTemplateName] = useState(defaultTemplateName(DEFAULT_TEMPLATE_PROFILE));
  const [selectedGroups, setSelectedGroups] = useState(["metadata"]);

  const [vaultConfig, setVaultConfig] = useState(null);
  const [templateCatalog, setTemplateCatalog] = useState(null);
  const [connectionError, setConnectionError] = useState("");
  const [workflowError, setWorkflowError] = useState("");
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [isPreviewing, setIsPreviewing] = useState(false);
  const [isExporting, setIsExporting] = useState(false);

  const [activityLog, setActivityLog] = useState([]);
  const [responseText, setResponseText] = useState("");
  const [createMeta, setCreateMeta] = useState(null);
  const [bundle, setBundle] = useState(null);
  const [verifyResponse, setVerifyResponse] = useState(null);
  const [timestampResponse, setTimestampResponse] = useState(null);
  const [timestampVerification, setTimestampVerification] = useState(null);
  const [anchorResponse, setAnchorResponse] = useState(null);
  const [receiptVerification, setReceiptVerification] = useState(null);
  const [disclosurePreview, setDisclosurePreview] = useState(null);
  const [packSummary, setPackSummary] = useState(null);
  const [packManifest, setPackManifest] = useState(null);
  const [systemSummary, setSystemSummary] = useState(null);
  const [downloadInfo, setDownloadInfo] = useState(null);

  useEffect(() => {
    void refreshVaultCapabilities();
  }, []);

  useEffect(() => {
    return () => {
      if (downloadInfo?.url) {
        URL.revokeObjectURL(downloadInfo.url);
      }
    };
  }, [downloadInfo]);

  function appendActivity(title, detail, tone = "muted") {
    const time = new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    });
    setActivityLog((current) => [{ title, detail, tone, time }, ...current].slice(0, 14));
  }

  function replaceDownload(blob, fileName) {
    setDownloadInfo((current) => {
      if (current?.url) {
        URL.revokeObjectURL(current.url);
      }
      return {
        url: URL.createObjectURL(blob),
        fileName,
        size: blob.size
      };
    });
  }

  function requestHeaders(json = true) {
    return {
      ...(json ? { "Content-Type": "application/json" } : {}),
      ...authHeaders(apiKey)
    };
  }

  function selectedTemplate() {
    return templateCatalog?.templates?.find((template) => template.profile === templateProfile) ?? null;
  }

  function buildDisclosureTemplate() {
    return {
      profile: templateProfile,
      name: templateName.trim() || defaultTemplateName(templateProfile),
      redaction_groups: selectedGroups,
      redacted_fields_by_item_type: {}
    };
  }

  async function refreshVaultCapabilities() {
    const baseUrl = normalizeBaseUrl(serviceUrl);
    if (!baseUrl) {
      setConnectionError("Enter a vault URL first.");
      return;
    }

    setIsRefreshing(true);
    setConnectionError("");

    try {
      const [configResponse, templateResponse] = await Promise.all([
        requestJson(`${baseUrl}/v1/config`, { headers: requestHeaders(false) }),
        requestJson(`${baseUrl}/v1/disclosure/templates`, { headers: requestHeaders(false) })
      ]);
      setVaultConfig(configResponse);
      setTemplateCatalog(templateResponse);

      if (templateResponse.templates.length > 0) {
        const existingTemplate =
          templateResponse.templates.find((template) => template.profile === templateProfile) ??
          templateResponse.templates[0];
        setTemplateProfile(existingTemplate.profile);
        setTemplateName((current) =>
          current.trim() ? current : defaultTemplateName(existingTemplate.profile)
        );
        setSelectedGroups((current) =>
          current.length > 0 ? current : existingTemplate.default_redaction_groups ?? []
        );
      }

      appendActivity(
        "Vault connected",
        `${configResponse.service.addr} · ${configResponse.timestamp.enabled ? "timestamp" : "signature"} assurance`,
        "good"
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setConnectionError(message);
      appendActivity("Vault connection failed", message, "bad");
    } finally {
      setIsRefreshing(false);
    }
  }

  function resetWorkflowArtifacts() {
    setWorkflowError("");
    setCreateMeta(null);
    setBundle(null);
    setVerifyResponse(null);
    setTimestampResponse(null);
    setTimestampVerification(null);
    setAnchorResponse(null);
    setReceiptVerification(null);
    setDisclosurePreview(null);
    setPackSummary(null);
    setPackManifest(null);
    setSystemSummary(null);
    setResponseText("");
    setDownloadInfo((current) => {
      if (current?.url) {
        URL.revokeObjectURL(current.url);
      }
      return null;
    });
  }

  async function createBundleAndFetch() {
    const baseUrl = normalizeBaseUrl(serviceUrl);
    const requestId = crypto.randomUUID();
    const chosenModel = model.trim() || defaultModelFor(provider);
    const systemIdValue = systemId.trim() || DEFAULT_SYSTEM_ID;
    const temperatureValue = Number.parseFloat(temperature);
    const resolvedTemperature = Number.isFinite(temperatureValue) ? temperatureValue : 0.2;
    const outputText = buildMockResponse(provider, systemPrompt, userPrompt, chosenModel);

    setResponseText(outputText);

    const promptPayload = {
      provider,
      messages: [
        { role: "system", content: systemPrompt.trim() },
        { role: "user", content: userPrompt.trim() }
      ]
    };
    const responsePayload = {
      provider,
      model: chosenModel,
      output: outputText,
      usage: {
        input_tokens: 137,
        output_tokens: 96,
        total_tokens: 233
      }
    };
    const tracePayload = {
      request_id: requestId,
      system_id: systemIdValue,
      provider,
      model: chosenModel,
      actor_role: actorRole,
      captured_at: new Date().toISOString(),
      pack_type: PACK_TYPE
    };

    const promptBytes = enc.encode(prettyJson(promptPayload));
    const responseBytes = enc.encode(prettyJson(responsePayload));
    const traceBytes = enc.encode(prettyJson(tracePayload));
    const promptCommitment = await sha256Prefixed(promptBytes);
    const responseCommitment = await sha256Prefixed(responseBytes);
    const traceCommitment = await sha256Prefixed(traceBytes);

    const capture = {
      actor: {
        issuer: "proof-layer-web-demo",
        app_id: "web-demo",
        env: "demo",
        signing_key_id: "web-demo-ui",
        role: actorRole
      },
      subject: {
        request_id: requestId,
        thread_id: `thread-${requestId.slice(0, 8)}`,
        user_ref: "demo-user",
        system_id: systemIdValue,
        model_id: `${provider}:${chosenModel}`,
        deployment_id: `${systemIdValue}-demo`,
        version: "2026.03"
      },
      context: {
        provider,
        model: chosenModel,
        parameters: {
          temperature: resolvedTemperature,
          max_tokens: 256
        },
        trace_commitment: traceCommitment,
        otel_genai_semconv_version: "1.0.0"
      },
      items: [
        {
          type: "llm_interaction",
          data: {
            provider,
            model: chosenModel,
            parameters: {
              temperature: resolvedTemperature,
              max_tokens: 256
            },
            input_commitment: promptCommitment,
            output_commitment: responseCommitment,
            token_usage: responsePayload.usage,
            latency_ms: 842,
            trace_commitment: traceCommitment,
            trace_semconv_version: "1.0.0"
          }
        }
      ],
      policy: {
        redactions: [],
        encryption: { enabled: false },
        retention_class: "runtime_logs"
      }
    };

    const createResponse = await requestJson(`${baseUrl}/v1/bundles`, {
      method: "POST",
      headers: requestHeaders(),
      body: JSON.stringify({
        capture,
        artefacts: [
          {
            name: "prompt.json",
            content_type: "application/json",
            data_base64: encodeBase64(promptBytes)
          },
          {
            name: "response.json",
            content_type: "application/json",
            data_base64: encodeBase64(responseBytes)
          },
          {
            name: "trace.json",
            content_type: "application/json",
            data_base64: encodeBase64(traceBytes)
          }
        ]
      })
    });

    const bundleResponse = await requestJson(
      `${baseUrl}/v1/bundles/${encodeURIComponent(createResponse.bundle_id)}`,
      {
        headers: requestHeaders(false)
      }
    );

    return {
      createResponse,
      bundleResponse,
      artefacts: [
        { name: "prompt.json", data_base64: encodeBase64(promptBytes) },
        { name: "response.json", data_base64: encodeBase64(responseBytes) },
        { name: "trace.json", data_base64: encodeBase64(traceBytes) }
      ]
    };
  }

  async function runOptionalVerify(currentBundle, artefacts) {
    if (!publicKeyPem.trim()) {
      setVerifyResponse({
        valid: false,
        message: "Paste a public key PEM to run service-side bundle verification.",
        artefacts_verified: 0
      });
      appendActivity("Verification skipped", "Public key PEM not supplied.", "warn");
      return null;
    }

    const baseUrl = normalizeBaseUrl(serviceUrl);
    const verifyPayload = await requestJson(`${baseUrl}/v1/verify`, {
      method: "POST",
      headers: requestHeaders(),
      body: JSON.stringify({
        bundle: currentBundle,
        artefacts,
        public_key_pem: publicKeyPem
      })
    });
    setVerifyResponse(verifyPayload);
    appendActivity(
      "Bundle verified",
      verifyPayload.valid ? verifyPayload.message : "Verification returned false.",
      verifyPayload.valid ? "good" : "warn"
    );
    return verifyPayload;
  }

  async function attachTimestampFor(bundleId) {
    const baseUrl = normalizeBaseUrl(serviceUrl);
    const timestampPayload = await requestJson(
      `${baseUrl}/v1/bundles/${encodeURIComponent(bundleId)}/timestamp`,
      {
        method: "POST",
        headers: requestHeaders(false)
      }
    );
    setTimestampResponse(timestampPayload);
    appendActivity(
      "Timestamp attached",
      `${timestampPayload.provider ?? "provider"} · ${timestampPayload.generated_at}`,
      "good"
    );

    const verificationPayload = await requestJson(`${baseUrl}/v1/verify/timestamp`, {
      method: "POST",
      headers: requestHeaders(),
      body: JSON.stringify({ bundle_id: bundleId })
    });
    setTimestampVerification(verificationPayload);
    appendActivity(
      "Timestamp checked",
      verificationPayload.valid ? verificationPayload.message : "Timestamp verification failed.",
      verificationPayload.valid ? "good" : "warn"
    );
    return { timestampPayload, verificationPayload };
  }

  async function attachTransparencyFor(bundleId) {
    const baseUrl = normalizeBaseUrl(serviceUrl);
    const anchorPayload = await requestJson(
      `${baseUrl}/v1/bundles/${encodeURIComponent(bundleId)}/anchor`,
      {
        method: "POST",
        headers: requestHeaders(false)
      }
    );
    setAnchorResponse(anchorPayload);
    appendActivity(
      "Transparency receipt anchored",
      `${anchorPayload.provider ?? "provider"} · entry ${anchorPayload.entry_uuid}`,
      "good"
    );

    const verificationPayload = await requestJson(`${baseUrl}/v1/verify/receipt`, {
      method: "POST",
      headers: requestHeaders(),
      body: JSON.stringify({ bundle_id: bundleId })
    });
    setReceiptVerification(verificationPayload);
    appendActivity(
      "Receipt checked",
      verificationPayload.valid ? verificationPayload.message : "Receipt verification failed.",
      verificationPayload.valid ? "good" : "warn"
    );
    return { anchorPayload, verificationPayload };
  }

  async function previewDisclosureFor(bundleId) {
    const baseUrl = normalizeBaseUrl(serviceUrl);
    const previewPayload = await requestJson(`${baseUrl}/v1/disclosure/preview`, {
      method: "POST",
      headers: requestHeaders(),
      body: JSON.stringify({
        bundle_id: bundleId,
        pack_type: PACK_TYPE,
        disclosure_template: buildDisclosureTemplate()
      })
    });
    setDisclosurePreview(previewPayload);
    appendActivity(
      "Disclosure preview ready",
      `${previewPayload.disclosed_item_indices.length} items · ${previewPayload.disclosed_artefact_names.length} artefacts`,
      "accent"
    );
    return previewPayload;
  }

  async function exportPackFor(bundleId, currentSystemId) {
    const baseUrl = normalizeBaseUrl(serviceUrl);
    const requestBody = {
      pack_type: PACK_TYPE,
      system_id: currentSystemId,
      bundle_format: bundleFormat
    };
    if (bundleFormat === "disclosure") {
      requestBody.disclosure_template = buildDisclosureTemplate();
    }

    const packPayload = await requestJson(`${baseUrl}/v1/packs`, {
      method: "POST",
      headers: requestHeaders(),
      body: JSON.stringify(requestBody)
    });
    setPackSummary(packPayload);

    const manifestPayload = await requestJson(
      `${baseUrl}/v1/packs/${encodeURIComponent(packPayload.pack_id)}/manifest`,
      {
        headers: requestHeaders(false)
      }
    );
    setPackManifest(manifestPayload);

    const exportPayload = await requestBinary(
      `${baseUrl}/v1/packs/${encodeURIComponent(packPayload.pack_id)}/export`,
      {
        headers: requestHeaders(false)
      }
    );
    const blob = new Blob([exportPayload.buffer], {
      type: exportPayload.contentType ?? "application/gzip"
    });
    replaceDownload(
      blob,
      `${bundleFormat === "disclosure" ? "runtime-disclosure" : "runtime-pack"}-${bundleId}.pack`
    );

    appendActivity(
      "Pack exported",
      `${packPayload.bundle_count} bundle(s) · ${formatBytes(blob.size)}`,
      "good"
    );
    return { packPayload, manifestPayload };
  }

  async function loadSystemSummary(currentSystemId) {
    const baseUrl = normalizeBaseUrl(serviceUrl);
    const summaryPayload = await requestJson(
      `${baseUrl}/v1/systems/${encodeURIComponent(currentSystemId)}/summary`,
      {
        headers: requestHeaders(false)
      }
    );
    setSystemSummary(summaryPayload);
    appendActivity(
      "System rollup loaded",
      `${summaryPayload.bundle_count} bundles tracked for ${currentSystemId}`,
      "accent"
    );
    return summaryPayload;
  }

  async function runWorkflow() {
    setIsRunning(true);
    resetWorkflowArtifacts();

    try {
      const { createResponse, bundleResponse, artefacts } = await createBundleAndFetch();
      setCreateMeta(createResponse);
      setBundle(bundleResponse);
      appendActivity(
        "Bundle sealed",
        `${createResponse.bundle_id} · ${createResponse.bundle_root}`,
        "good"
      );

      await runOptionalVerify(bundleResponse, artefacts);

      let timestampAttached = false;
      const canTimestamp = vaultConfig?.timestamp?.enabled && attachTimestamp;
      if (canTimestamp) {
        try {
          await attachTimestampFor(createResponse.bundle_id);
          timestampAttached = true;
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          setTimestampVerification({ valid: false, message, verification: null });
          appendActivity("Timestamp step failed", message, "bad");
        }
      }

      const canAnchor =
        vaultConfig?.transparency?.enabled && attachTransparency && timestampAttached;
      if (canAnchor) {
        try {
          await attachTransparencyFor(createResponse.bundle_id);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          setReceiptVerification({ valid: false, message, verification: null });
          appendActivity("Transparency step failed", message, "bad");
        }
      }

      await previewDisclosureFor(createResponse.bundle_id);
      await exportPackFor(createResponse.bundle_id, bundleResponse.subject?.system_id ?? systemId.trim());
      await loadSystemSummary(bundleResponse.subject?.system_id ?? systemId.trim());
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setWorkflowError(message);
      appendActivity("Workflow failed", message, "bad");
    } finally {
      setIsRunning(false);
    }
  }

  async function rerunDisclosurePreview() {
    if (!createMeta?.bundle_id) {
      return;
    }
    setIsPreviewing(true);
    setWorkflowError("");
    try {
      await previewDisclosureFor(createMeta.bundle_id);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setWorkflowError(message);
      appendActivity("Preview failed", message, "bad");
    } finally {
      setIsPreviewing(false);
    }
  }

  async function rerunExport() {
    if (!createMeta?.bundle_id || !bundle?.subject?.system_id) {
      return;
    }
    setIsExporting(true);
    setWorkflowError("");
    try {
      await exportPackFor(createMeta.bundle_id, bundle.subject.system_id);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setWorkflowError(message);
      appendActivity("Export failed", message, "bad");
    } finally {
      setIsExporting(false);
    }
  }

  const template = selectedTemplate();
  const capabilityChips = capabilityValue(vaultConfig, templateCatalog);
  const templateGroups = templateCatalog?.redaction_groups ?? [];
  const timeline = [
    {
      title: "Vault capabilities",
      status: vaultConfig ? "done" : connectionError ? "error" : isRefreshing ? "active" : "idle",
      detail: vaultConfig
        ? `${vaultConfig.service.addr} · ${vaultConfig.service.tls_enabled ? "TLS" : "no TLS"}`
        : connectionError || "Refresh the vault to inspect auth, assurance, and disclosure support."
    },
    {
      title: "Sealed bundle",
      status: createMeta ? "done" : isRunning ? "active" : "idle",
      detail: createMeta
        ? `${createMeta.bundle_id} · ${createMeta.created_at}`
        : "Create a v1.0 llm_interaction bundle with prompt, response, and trace artefacts."
    },
    {
      title: "Bundle verification",
      status: verifyResponse
        ? verifyResponse.valid
          ? "done"
          : "warn"
        : publicKeyPem.trim()
          ? "idle"
          : "optional",
      detail: verifyResponse?.message || "Optional: paste a public key PEM to run service-side verify."
    },
    {
      title: "RFC 3161 timestamp",
      status: timestampVerification
        ? timestampVerification.valid
          ? "done"
          : "warn"
        : attachTimestamp
          ? "idle"
          : "optional",
      detail:
        timestampVerification?.message ||
        (attachTimestamp
          ? "Attach and validate a timestamp if the vault supports it."
          : "Timestamp step not requested.")
    },
    {
      title: "Transparency receipt",
      status: receiptVerification
        ? receiptVerification.valid
          ? "done"
          : "warn"
        : attachTransparency
          ? "idle"
          : "optional",
      detail:
        receiptVerification?.message ||
        (attachTransparency
          ? "Anchor into Rekor or SCITT if the vault is configured for it."
          : "Transparency step not requested.")
    },
    {
      title: "Disclosure preview",
      status: disclosurePreview ? "done" : isPreviewing ? "active" : "idle",
      detail: disclosurePreview
        ? `${disclosurePreview.disclosed_item_indices.length} items disclosed via ${disclosurePreview.policy_name}`
        : "Render a disclosure template and preview redacted output before export."
    },
    {
      title: "Evidence pack export",
      status: downloadInfo ? "done" : isExporting ? "active" : "idle",
      detail: downloadInfo
        ? `${downloadInfo.fileName} · ${formatBytes(downloadInfo.size)}`
        : "Export a vault-assembled pack for this system in full or disclosure format."
    }
  ];

  return (
    <div className="app-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />

      <header className="hero">
        <div className="hero-copy">
          <span className="eyebrow">Proof Layer Investor Workflow</span>
          <h1>Seal one AI run, prove its integrity, preview disclosure, and export a regulator-ready pack.</h1>
          <p>
            This demo uses the real vault API surface: v1 bundle creation, optional timestamping,
            optional transparency anchoring, disclosure-template preview, pack export, and system
            rollup.
          </p>
        </div>
        <div className="hero-summary">
          <div>
            <strong>Pack profile</strong>
            <span>{PACK_TYPE}</span>
          </div>
          <div>
            <strong>Disclosure mode</strong>
            <span>{bundleFormat}</span>
          </div>
          <div>
            <strong>Template</strong>
            <span>{templateProfile}</span>
          </div>
        </div>
      </header>

      <section className="capability-strip">
        {capabilityChips.map((chip) => (
          <article key={chip.label} className={`capability-chip is-${chip.tone}`}>
            <span>{chip.label}</span>
            <strong>{chip.value}</strong>
          </article>
        ))}
      </section>

      <main className="workspace">
        <section className="composer panel">
          <div className="panel-head">
            <div>
              <span className="section-label">Command Deck</span>
              <h2>Configure the run</h2>
            </div>
            <button type="button" className="ghost-btn" onClick={refreshVaultCapabilities} disabled={isRefreshing}>
              {isRefreshing ? "Refreshing..." : "Refresh vault"}
            </button>
          </div>

          <div className="form-grid">
            <label>
              Vault URL
              <input value={serviceUrl} onChange={(event) => setServiceUrl(event.target.value)} />
            </label>
            <label>
              API key
              <input
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                placeholder="Optional bearer key"
              />
            </label>
            <label>
              Provider
              <select
                value={provider}
                onChange={(event) => {
                  const nextProvider = event.target.value;
                  setProvider(nextProvider);
                  setModel(defaultModelFor(nextProvider));
                }}
              >
                <option value="anthropic">Anthropic</option>
                <option value="openai">OpenAI</option>
              </select>
            </label>
            <label>
              Model
              <select value={model} onChange={(event) => setModel(event.target.value)}>
                {modelOptionsFor(provider).map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Actor role
              <select value={actorRole} onChange={(event) => setActorRole(event.target.value)}>
                <option value="provider">Provider</option>
                <option value="deployer">Deployer</option>
                <option value="integrator">Integrator</option>
              </select>
            </label>
            <label>
              System ID
              <input value={systemId} onChange={(event) => setSystemId(event.target.value)} />
            </label>
            <label>
              Temperature
              <input value={temperature} onChange={(event) => setTemperature(event.target.value)} />
            </label>
            <label>
              Export bundle format
              <select value={bundleFormat} onChange={(event) => setBundleFormat(event.target.value)}>
                <option value="disclosure">disclosure</option>
                <option value="full">full</option>
              </select>
            </label>
          </div>

          <label className="stacked-field">
            System prompt
            <textarea
              rows={4}
              value={systemPrompt}
              onChange={(event) => setSystemPrompt(event.target.value)}
            />
          </label>

          <label className="stacked-field">
            User prompt
            <textarea rows={5} value={userPrompt} onChange={(event) => setUserPrompt(event.target.value)} />
          </label>

          <label className="stacked-field">
            Public key PEM for verify
            <textarea
              rows={5}
              value={publicKeyPem}
              onChange={(event) => setPublicKeyPem(event.target.value)}
              placeholder="-----BEGIN PUBLIC KEY-----"
            />
          </label>

          <div className="toggle-row">
            <button
              type="button"
              className={`toggle-pill ${attachTimestamp ? "is-active" : ""}`}
              onClick={() => setAttachTimestamp((current) => !current)}
            >
              Timestamp
            </button>
            <button
              type="button"
              className={`toggle-pill ${attachTransparency ? "is-active" : ""}`}
              onClick={() => setAttachTransparency((current) => !current)}
            >
              Transparency
            </button>
          </div>

          <div className="panel-subsection">
            <div className="panel-head compact">
              <div>
                <span className="section-label">Disclosure Template</span>
                <h3>{template?.description ?? "Template profile"}</h3>
              </div>
            </div>

            <div className="form-grid">
              <label>
                Profile
                <select
                  value={templateProfile}
                  onChange={(event) => {
                    const nextProfile = event.target.value;
                    const nextTemplate =
                      templateCatalog?.templates?.find((item) => item.profile === nextProfile) ?? null;
                    setTemplateProfile(nextProfile);
                    setTemplateName(defaultTemplateName(nextProfile));
                    setSelectedGroups(nextTemplate?.default_redaction_groups ?? []);
                  }}
                >
                  {(templateCatalog?.templates ?? []).map((item) => (
                    <option key={item.profile} value={item.profile}>
                      {item.profile}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Template name
                <input value={templateName} onChange={(event) => setTemplateName(event.target.value)} />
              </label>
            </div>

            <div className="group-picker">
              {templateGroups.map((group) => {
                const active = selectedGroups.includes(group.name);
                return (
                  <button
                    key={group.name}
                    type="button"
                    className={`group-chip ${active ? "is-active" : ""}`}
                    onClick={() =>
                      setSelectedGroups((current) =>
                        current.includes(group.name)
                          ? current.filter((value) => value !== group.name)
                          : [...current, group.name]
                      )
                    }
                  >
                    <strong>{group.name}</strong>
                    <span>{group.description}</span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="button-row">
            <button type="button" onClick={runWorkflow} disabled={isRunning}>
              {isRunning ? "Running workflow..." : "Run proof workflow"}
            </button>
            <button
              type="button"
              className="secondary-btn"
              onClick={rerunDisclosurePreview}
              disabled={!createMeta || isPreviewing}
            >
              {isPreviewing ? "Previewing..." : "Preview disclosure"}
            </button>
            <button
              type="button"
              className="secondary-btn"
              onClick={rerunExport}
              disabled={!createMeta || isExporting}
            >
              {isExporting ? "Exporting..." : "Export pack"}
            </button>
          </div>

          {connectionError ? <p className="inline-error">{connectionError}</p> : null}
          {workflowError ? <p className="inline-error">{workflowError}</p> : null}
        </section>

        <aside className="ops-rail">
          <section className="panel">
            <div className="panel-head">
              <div>
                <span className="section-label">Workflow</span>
                <h2>Proof lifecycle</h2>
              </div>
            </div>
            <div className="timeline">
              {timeline.map((step) => (
                <TimelineStep key={step.title} {...step} />
              ))}
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <div>
                <span className="section-label">Activity</span>
                <h2>Recent actions</h2>
              </div>
            </div>
            <ul className="activity-list">
              {activityLog.length > 0 ? (
                activityLog.map((entry, index) => <ActivityRow key={`${entry.time}-${index}`} entry={entry} />)
              ) : (
                <li className="activity-empty">Run the workflow to populate this audit-style feed.</li>
              )}
            </ul>
            {downloadInfo ? (
              <a className="download-link" href={downloadInfo.url} download={downloadInfo.fileName}>
                Download {downloadInfo.fileName}
              </a>
            ) : null}
          </section>
        </aside>
      </main>

      <section className="snapshot-grid">
        <DataPanel
          title="Bundle overview"
          subtitle={createMeta ? createMeta.bundle_id : "Awaiting first run"}
          value={
            createMeta
              ? {
                  bundle_id: createMeta.bundle_id,
                  created_at: createMeta.created_at,
                  bundle_root: createMeta.bundle_root,
                  response_preview: responseText
                }
              : null
          }
          placeholder="Bundle metadata and the captured response will appear here after sealing."
        />
        <DataPanel
          title="Assurance checks"
          subtitle="verify, timestamp, receipt"
          value={{
            verify: verifyResponse,
            timestamp: timestampVerification,
            receipt: receiptVerification
          }}
          placeholder="Optional assurance results will appear here."
        />
        <DataPanel
          title="Disclosure preview"
          subtitle={disclosurePreview ? disclosurePreview.policy_name : templateProfile}
          value={disclosurePreview}
          placeholder="Preview the disclosed items, redacted paths, and disclosed artefacts."
        />
        <DataPanel
          title="Pack manifest"
          subtitle={packManifest ? packManifest.pack_id : PACK_TYPE}
          value={packManifest}
          placeholder="Export a pack to inspect its manifest and disclosed members."
        />
        <DataPanel
          title="System summary"
          subtitle={systemSummary ? systemSummary.system_id : systemId}
          value={systemSummary}
          placeholder="After export, the vault rollup for this system will appear here."
        />
        <DataPanel
          title="Bundle JSON"
          subtitle={bundle?.integrity?.bundle_root_algorithm ?? "v1.0 bundle"}
          value={bundle}
          placeholder="The stored proof bundle JSON will appear here after creation."
        />
      </section>
    </div>
  );
}
