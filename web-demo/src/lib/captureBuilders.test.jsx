import { describe, expect, test } from "vitest";
import { buildCaptureEnvelope } from "./captureBuilders";
import { getPreset } from "./presets";

describe("buildCaptureEnvelope", () => {
  test("adds derived incident evidence for the incident preset", async () => {
    const envelope = await buildCaptureEnvelope({
      preset: getPreset("incident_review"),
      providerResult: {
        capture_mode: "synthetic_demo_capture",
        provider: "openai",
        model: "gpt-5-mini",
        output_text: "An anomaly occurred and needs investigation.",
        usage: { input_tokens: 10, output_tokens: 12, total_tokens: 22 },
        latency_ms: 210,
        prompt_payload: { hello: "world" },
        response_payload: { output_text: "An anomaly occurred and needs investigation." },
        trace_payload: { request_id: "req-incident-01" }
      },
      actorRole: "integrator",
      systemId: "system-demo",
      temperature: 0.2,
      maxTokens: 256
    });

    expect(
      envelope.createPayload.capture.items.some((item) => item.type === "incident_report")
    ).toBe(true);
    expect(
      envelope.createPayload.artefacts.some((artefact) => artefact.name === "incident_report.json")
    ).toBe(true);
  });

  test("adds derived technical documentation for the annex iv preset", async () => {
    const envelope = await buildCaptureEnvelope({
      preset: getPreset("annex_iv_filing"),
      providerResult: {
        capture_mode: "live_provider_capture",
        provider: "openai",
        model: "gpt-5.2",
        output_text: "The system supports classification and summarization with known recall limits.",
        usage: { input_tokens: 10, output_tokens: 18, total_tokens: 28 },
        latency_ms: 330,
        prompt_payload: { hello: "world" },
        response_payload: { output_text: "The system supports classification and summarization with known recall limits." },
        trace_payload: { request_id: "req-annex-01" }
      },
      actorRole: "provider",
      systemId: "system-demo",
      temperature: 0.2,
      maxTokens: 256
    });

    expect(
      envelope.createPayload.capture.items.some((item) => item.type === "technical_doc")
    ).toBe(true);
    expect(
      envelope.createPayload.artefacts.some((artefact) => artefact.name === "annex_iv_summary.md")
    ).toBe(true);
  });
});
