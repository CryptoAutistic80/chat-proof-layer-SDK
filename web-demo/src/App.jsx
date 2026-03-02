import React, { useMemo, useState } from "react";

const enc = new TextEncoder();

function encodeBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    const slice = bytes.subarray(i, i + chunk);
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary);
}

async function sha256Prefixed(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const hex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `sha256:${hex}`;
}

async function gzipBytes(bytes) {
  if (typeof CompressionStream === "undefined") {
    return bytes;
  }
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream("gzip"));
  const compressed = await new Response(stream).arrayBuffer();
  return new Uint8Array(compressed);
}

function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

function buildMockResponse(provider, prompt) {
  const lead = provider === "anthropic" ? "Anthropic" : "OpenAI";
  return `${lead} demo response: ${prompt.slice(0, 180)}`;
}

export function App() {
  const [serviceUrl, setServiceUrl] = useState("http://127.0.0.1:8080");
  const [provider, setProvider] = useState("anthropic");
  const [systemPrompt, setSystemPrompt] = useState("You are precise and concise.");
  const [userPrompt, setUserPrompt] = useState("Explain what this proof bundle records.");
  const [publicKeyPem, setPublicKeyPem] = useState("");
  const [responseText, setResponseText] = useState("");
  const [bundle, setBundle] = useState(null);
  const [verify, setVerify] = useState(null);
  const [bundleMeta, setBundleMeta] = useState(null);
  const [downloadUrl, setDownloadUrl] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const canRun = useMemo(
    () => userPrompt.trim().length > 0 && serviceUrl.trim().length > 0,
    [userPrompt, serviceUrl]
  );

  async function runAndSeal() {
    setLoading(true);
    setError("");
    setVerify(null);
    setDownloadUrl(null);
    try {
      const mockResponse = buildMockResponse(provider, userPrompt);
      setResponseText(mockResponse);

      const promptPayload = {
        provider,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt }
        ]
      };
      const responsePayload = {
        output: [{ type: "text", text: mockResponse }],
        usage: { input_tokens: 42, output_tokens: 29 }
      };

      const promptBytes = enc.encode(prettyJson(promptPayload));
      const responseBytes = enc.encode(prettyJson(responsePayload));
      const traceBytes = enc.encode(prettyJson({ provider, kind: "web-demo" }));

      const capture = {
        actor: {
          issuer: "proof-layer-web-demo",
          app_id: "web-demo",
          env: "dev",
          signing_key_id: "kid-dev-01"
        },
        subject: {
          request_id: crypto.randomUUID(),
          thread_id: null,
          user_ref: null
        },
        model: {
          provider,
          model: provider === "anthropic" ? "claude-sonnet-4-6" : "gpt-4o-mini",
          parameters: { temperature: 0.2 }
        },
        inputs: {
          messages_commitment: await sha256Prefixed(promptBytes),
          retrieval_commitment: null
        },
        outputs: {
          assistant_text_commitment: await sha256Prefixed(responseBytes),
          tool_outputs_commitment: null
        },
        trace: {
          otel_genai_semconv_version: "1.0.0",
          trace_commitment: await sha256Prefixed(traceBytes)
        },
        policy: {
          redactions: [],
          encryption: { enabled: false }
        }
      };

      const createRes = await fetch(`${serviceUrl.replace(/\/$/, "")}/v1/bundles`, {
        method: "POST",
        headers: { "content-type": "application/json" },
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
            }
          ]
        })
      });
      const createBody = await createRes.json();
      if (!createRes.ok) {
        throw new Error(createBody?.error ?? "failed to create bundle");
      }
      setBundleMeta(createBody);

      const bundleRes = await fetch(
        `${serviceUrl.replace(/\/$/, "")}/v1/bundles/${encodeURIComponent(createBody.bundle_id)}`
      );
      const bundleBody = await bundleRes.json();
      if (!bundleRes.ok) {
        throw new Error(bundleBody?.error ?? "failed to fetch bundle");
      }
      setBundle(bundleBody);

      if (publicKeyPem.trim().length > 0) {
        const verifyRes = await fetch(`${serviceUrl.replace(/\/$/, "")}/v1/verify`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            bundle: bundleBody,
            artefacts: [
              { name: "prompt.json", data_base64: encodeBase64(promptBytes) },
              { name: "response.json", data_base64: encodeBase64(responseBytes) }
            ],
            public_key_pem: publicKeyPem
          })
        });
        const verifyBody = await verifyRes.json();
        if (!verifyRes.ok) {
          throw new Error(verifyBody?.error ?? "verification request failed");
        }
        setVerify(verifyBody);
      } else {
        setVerify({ valid: false, message: "Paste public key to run live verify", artefacts_verified: 0 });
      }

      const files = {
        "proof_bundle.json": enc.encode(prettyJson(bundleBody)),
        "proof_bundle.canonical.json": enc.encode(prettyJson(bundleBody)),
        "proof_bundle.sig": enc.encode(bundleBody.integrity.signature.value),
        "artefacts/prompt.json": promptBytes,
        "artefacts/response.json": responseBytes
      };

      const manifestFiles = [];
      for (const [name, bytes] of Object.entries(files)) {
        manifestFiles.push({
          name,
          digest: await sha256Prefixed(bytes),
          size: bytes.length
        });
      }
      files["manifest.json"] = enc.encode(prettyJson({ files: manifestFiles }));

      const packageJson = {
        format: "pl-bundle-pkg-v1",
        files: Object.entries(files).map(([name, bytes]) => ({
          name,
          data_base64: encodeBase64(bytes)
        }))
      };
      const packageBytes = await gzipBytes(enc.encode(prettyJson(packageJson)));
      const blob = new Blob([packageBytes], { type: "application/gzip" });
      setDownloadUrl(URL.createObjectURL(blob));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page">
      <div className="glow glow-a" />
      <div className="glow glow-b" />
      <header className="hero">
        <h1>AI Output Proof Layer</h1>
        <p>Generate, inspect, and verify cryptographic evidence for one model interaction.</p>
      </header>

      <main className="grid">
        <section className="panel input-panel">
          <h2>Run & Seal</h2>
          <label>
            Proof Service URL
            <input value={serviceUrl} onChange={(e) => setServiceUrl(e.target.value)} />
          </label>
          <label>
            Provider
            <select value={provider} onChange={(e) => setProvider(e.target.value)}>
              <option value="anthropic">Anthropic</option>
              <option value="openai">OpenAI</option>
            </select>
          </label>
          <label>
            System Prompt
            <textarea value={systemPrompt} onChange={(e) => setSystemPrompt(e.target.value)} rows={4} />
          </label>
          <label>
            User Prompt
            <textarea value={userPrompt} onChange={(e) => setUserPrompt(e.target.value)} rows={5} />
          </label>
          <label>
            Public Key PEM (optional for live verify)
            <textarea
              value={publicKeyPem}
              onChange={(e) => setPublicKeyPem(e.target.value)}
              rows={6}
              placeholder="-----BEGIN PUBLIC KEY-----"
            />
          </label>
          <button disabled={!canRun || loading} onClick={runAndSeal}>
            {loading ? "Sealing..." : "Run & Seal"}
          </button>
          {error ? <p className="error">{error}</p> : null}
        </section>

        <section className="panel output-panel">
          <h2>Proof Bundle</h2>
          <div className="meta">
            <div><strong>bundle_id</strong><span>{bundleMeta?.bundle_id ?? "-"}</span></div>
            <div><strong>created_at</strong><span>{bundleMeta?.created_at ?? "-"}</span></div>
            <div><strong>bundle_root</strong><span>{bundleMeta?.bundle_root ?? "-"}</span></div>
          </div>
          <h3>Response</h3>
          <pre>{responseText || "(response will appear here)"}</pre>
          <h3>Verification</h3>
          <p className={verify?.valid ? "ok" : "warn"}>{verify?.message ?? "No verification yet"}</p>
          <p>Artefacts verified: {verify?.artefacts_verified ?? 0}</p>
          {downloadUrl ? (
            <a href={downloadUrl} download="bundle.pkg" className="download-btn">
              Download bundle.pkg
            </a>
          ) : null}
        </section>
      </main>

      <section className="panel json-panel">
        <h2>Bundle JSON</h2>
        <pre>{bundle ? prettyJson(bundle) : "(bundle JSON appears after Run & Seal)"}</pre>
      </section>
    </div>
  );
}
