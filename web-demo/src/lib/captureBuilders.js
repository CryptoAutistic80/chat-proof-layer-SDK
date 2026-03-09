const enc = new TextEncoder();

function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

function encodeBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    const slice = bytes.subarray(index, index + chunkSize);
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

function summarizeText(text, maxLength = 220) {
  const normalized = text.replace(/\s+/g, " ").trim();
  if (normalized.length <= maxLength) {
    return normalized;
  }
  return `${normalized.slice(0, maxLength - 1)}…`;
}

function buildIncidentArtefact(providerResult, requestId) {
  return {
    incident_id: `incident-${requestId.slice(0, 12)}`,
    severity: "medium",
    status: "open",
    occurred_at: new Date().toISOString(),
    summary: summarizeText(providerResult.output_text),
    metadata: {
      capture_mode: providerResult.capture_mode,
      provider: providerResult.provider,
      model: providerResult.model,
      generated_by: "web-demo-derived-incident-report"
    }
  };
}

function buildAnnexIvMarkdown(providerResult) {
  return [
    "# Annex IV Demo Summary",
    "",
    `Provider capture mode: ${providerResult.capture_mode}`,
    `Provider: ${providerResult.provider}`,
    `Model: ${providerResult.model}`,
    "",
    "## Intended purpose",
    "",
    summarizeText(providerResult.output_text, 320),
    "",
    "## Known limitations",
    "",
    "- Demo-generated technical note, not a full legal dossier.",
    "- Intended to show evidence capture, sealing, disclosure, and export mechanics.",
    "- Output content should be reviewed and extended before formal filing."
  ].join("\n");
}

async function buildDerivedEvidence(preset, providerResult, requestId) {
  const items = [];
  const artefacts = [];

  if (preset.key === "incident_review") {
    const incidentPayload = buildIncidentArtefact(providerResult, requestId);
    const incidentBytes = enc.encode(prettyJson(incidentPayload));
    const incidentCommitment = await sha256Prefixed(incidentBytes);
    artefacts.push({
      name: "incident_report.json",
      content_type: "application/json",
      data_base64: encodeBase64(incidentBytes)
    });
    items.push({
      type: "incident_report",
      data: {
        incident_id: incidentPayload.incident_id,
        severity: incidentPayload.severity,
        status: incidentPayload.status,
        occurred_at: incidentPayload.occurred_at,
        summary: incidentPayload.summary,
        report_commitment: incidentCommitment,
        metadata: incidentPayload.metadata
      }
    });
  }

  if (preset.key === "annex_iv_filing") {
    const markdown = buildAnnexIvMarkdown(providerResult);
    const docBytes = enc.encode(markdown);
    const commitment = await sha256Prefixed(docBytes);
    artefacts.push({
      name: "annex_iv_summary.md",
      content_type: "text/markdown",
      data_base64: encodeBase64(docBytes)
    });
    items.push({
      type: "technical_doc",
      data: {
        document_ref: "annex_iv_summary.md",
        section: "system_capabilities_and_limitations",
        commitment
      }
    });
  }

  return { items, artefacts };
}

export async function buildCaptureEnvelope({
  preset,
  providerResult,
  actorRole,
  systemId,
  temperature,
  maxTokens
}) {
  const requestId = providerResult.trace_payload?.request_id || crypto.randomUUID();
  const systemIdValue = systemId.trim();
  const promptPayload = providerResult.prompt_payload;
  const responsePayload = {
    provider: providerResult.provider,
    model: providerResult.model,
    output_text: providerResult.output_text,
    ...providerResult.response_payload,
    response_source: providerResult.capture_mode
  };
  const tracePayload = {
    ...providerResult.trace_payload,
    request_id: requestId,
    system_id: systemIdValue,
    actor_role: actorRole,
    pack_type: preset.packType,
    bundle_format: preset.bundleFormat,
    disclosure_profile: preset.disclosureProfile
  };

  const promptBytes = enc.encode(prettyJson(promptPayload));
  const responseBytes = enc.encode(prettyJson(responsePayload));
  const traceBytes = enc.encode(prettyJson(tracePayload));

  const promptCommitment = await sha256Prefixed(promptBytes);
  const responseCommitment = await sha256Prefixed(responseBytes);
  const traceCommitment = await sha256Prefixed(traceBytes);

  const { items: derivedItems, artefacts: derivedArtefacts } = await buildDerivedEvidence(
    preset,
    providerResult,
    requestId
  );

  return {
    responseText: providerResult.output_text,
    captureMode: providerResult.capture_mode,
    promptPayload,
    responsePayload,
    tracePayload,
    createPayload: {
      capture: {
        actor: {
          issuer: "proof-layer-web-demo",
          app_id: "web-demo",
          env: "demo",
          signing_key_id: "vault-managed",
          role: actorRole
        },
        subject: {
          request_id: requestId,
          thread_id: `thread-${requestId.slice(0, 8)}`,
          user_ref: "demo-user",
          system_id: systemIdValue,
          model_id: `${providerResult.provider}:${providerResult.model}`,
          deployment_id: `${systemIdValue}-demo`,
          version: "2026.03"
        },
        context: {
          provider: providerResult.provider,
          model: providerResult.model,
          parameters: {
            temperature,
            max_tokens: maxTokens,
            capture_mode: providerResult.capture_mode
          },
          trace_commitment: traceCommitment,
          otel_genai_semconv_version: "1.0.0"
        },
        items: [
          {
            type: "llm_interaction",
            data: {
              provider: providerResult.provider,
              model: providerResult.model,
              parameters: {
                temperature,
                max_tokens: maxTokens,
                capture_mode: providerResult.capture_mode
              },
              input_commitment: promptCommitment,
              output_commitment: responseCommitment,
              token_usage: providerResult.usage,
              latency_ms: providerResult.latency_ms,
              trace_commitment: traceCommitment,
              trace_semconv_version: "1.0.0"
            }
          },
          ...derivedItems
        ],
        policy: {
          redactions: [],
          encryption: { enabled: false },
          retention_class: preset.retentionClass
        }
      },
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
        },
        ...derivedArtefacts
      ]
    }
  };
}

export function decodeJsonBytes(arrayBuffer) {
  const text = new TextDecoder().decode(arrayBuffer);
  return JSON.parse(text);
}
