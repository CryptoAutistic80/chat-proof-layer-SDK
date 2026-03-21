const DEFAULT_SERVICE_URL = "http://127.0.0.1:8080";

export function normalizeBaseUrl(value) {
  return (value || DEFAULT_SERVICE_URL).trim().replace(/\/$/, "");
}

export function authHeaders(apiKey) {
  if (!apiKey || !apiKey.trim()) {
    return {};
  }
  return {
    Authorization: `Bearer ${apiKey.trim()}`
  };
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
  if (typeof payload.error?.message === "string") {
    return payload.error.message;
  }
  return fallback;
}

export async function requestJson(serviceUrl, apiKey, path, options = {}) {
  const response = await fetch(`${normalizeBaseUrl(serviceUrl)}${path}`, {
    ...options,
    headers: {
      ...(options.json === false ? {} : { "Content-Type": "application/json" }),
      ...authHeaders(apiKey),
      ...(options.headers ?? {})
    }
  });
  const payload = await parseJsonBody(response);
  if (!response.ok) {
    throw new Error(extractErrorMessage(payload, `${response.status} ${response.statusText}`));
  }
  return payload;
}

export async function requestBinary(serviceUrl, apiKey, path, options = {}) {
  const response = await fetch(`${normalizeBaseUrl(serviceUrl)}${path}`, {
    ...options,
    headers: {
      ...authHeaders(apiKey),
      ...(options.headers ?? {})
    }
  });
  if (!response.ok) {
    const payload = await parseJsonBody(response);
    throw new Error(extractErrorMessage(payload, `${response.status} ${response.statusText}`));
  }
  return {
    buffer: await response.arrayBuffer(),
    contentType: response.headers.get("content-type"),
    disposition: response.headers.get("content-disposition")
  };
}

export function formatBytes(byteCount) {
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

export async function fetchVaultConfig(serviceUrl, apiKey) {
  return requestJson(serviceUrl, apiKey, "/v1/config", { json: false });
}

export async function fetchDisclosureTemplates(serviceUrl, apiKey) {
  return requestJson(serviceUrl, apiKey, "/v1/disclosure/templates", { json: false });
}

export async function fetchDemoProviderResponse(serviceUrl, apiKey, payload) {
  return requestJson(serviceUrl, apiKey, "/v1/demo/provider-response", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function createBundle(serviceUrl, apiKey, payload) {
  return requestJson(serviceUrl, apiKey, "/v1/bundles", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function fetchBundle(serviceUrl, apiKey, bundleId) {
  return requestJson(
    serviceUrl,
    apiKey,
    `/v1/bundles/${encodeURIComponent(bundleId)}`,
    { json: false }
  );
}

export async function fetchBundleArtefact(serviceUrl, apiKey, bundleId, name) {
  return requestBinary(
    serviceUrl,
    apiKey,
    `/v1/bundles/${encodeURIComponent(bundleId)}/artefacts/${encodeURIComponent(name)}`
  );
}

export async function verifyBundle(serviceUrl, apiKey, payload) {
  return requestJson(serviceUrl, apiKey, "/v1/verify", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function attachTimestamp(serviceUrl, apiKey, bundleId) {
  return requestJson(
    serviceUrl,
    apiKey,
    `/v1/bundles/${encodeURIComponent(bundleId)}/timestamp`,
    {
      method: "POST",
      json: false
    }
  );
}

export async function verifyTimestamp(serviceUrl, apiKey, bundleId) {
  return requestJson(serviceUrl, apiKey, "/v1/verify/timestamp", {
    method: "POST",
    body: JSON.stringify({ bundle_id: bundleId })
  });
}

export async function anchorBundle(serviceUrl, apiKey, bundleId) {
  return requestJson(
    serviceUrl,
    apiKey,
    `/v1/bundles/${encodeURIComponent(bundleId)}/anchor`,
    {
      method: "POST",
      json: false
    }
  );
}

export async function verifyReceipt(serviceUrl, apiKey, bundleId) {
  return requestJson(serviceUrl, apiKey, "/v1/verify/receipt", {
    method: "POST",
    body: JSON.stringify({ bundle_id: bundleId })
  });
}

export async function previewDisclosure(serviceUrl, apiKey, payload) {
  return requestJson(serviceUrl, apiKey, "/v1/disclosure/preview", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function evaluateCompleteness(serviceUrl, apiKey, payload) {
  return requestJson(serviceUrl, apiKey, "/v1/completeness/evaluate", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function createPack(serviceUrl, apiKey, payload) {
  return requestJson(serviceUrl, apiKey, "/v1/packs", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function fetchPackManifest(serviceUrl, apiKey, packId) {
  return requestJson(
    serviceUrl,
    apiKey,
    `/v1/packs/${encodeURIComponent(packId)}/manifest`,
    { json: false }
  );
}

export async function downloadPackExport(serviceUrl, apiKey, packId) {
  return requestBinary(
    serviceUrl,
    apiKey,
    `/v1/packs/${encodeURIComponent(packId)}/export`
  );
}

export async function fetchSystemSummary(serviceUrl, apiKey, systemId) {
  return requestJson(
    serviceUrl,
    apiKey,
    `/v1/systems/${encodeURIComponent(systemId)}/summary`,
    { json: false }
  );
}

export async function listBundles(serviceUrl, apiKey, query = {}) {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      params.set(key, String(value));
    }
  });
  const search = params.toString();
  return requestJson(
    serviceUrl,
    apiKey,
    `/v1/bundles${search ? `?${search}` : ""}`,
    { json: false }
  );
}
