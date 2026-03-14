import React from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DemoProvider } from "./DemoContext";
import { AppRoutes } from "./routes";

const mocks = vi.hoisted(() => {
  const state = {
    bundles: new Map(),
    counter: 0
  };

  function reset() {
    state.bundles = new Map();
    state.counter = 0;
  }

  function decodeBase64(data) {
    const binary = atob(data);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  }

  function bundleFromPayload(bundleId, payload) {
    return {
      bundle_version: "1.0",
      bundle_id: bundleId,
      created_at: "2026-03-14T10:00:00Z",
      actor: payload.capture.actor,
      subject: payload.capture.subject,
      compliance_profile: payload.capture.compliance_profile ?? null,
      context: payload.capture.context ?? {},
      items: payload.capture.items,
      artefacts: payload.artefacts.map((artefact) => ({
        name: artefact.name,
        content_type: artefact.content_type,
        size: decodeBase64(artefact.data_base64).byteLength,
        digest: `sha256:${artefact.name}`
      })),
      policy: payload.capture.policy,
      integrity: {
        bundle_root: `root-${bundleId}`,
        bundle_root_algorithm: "pl-merkle-sha256-v4"
      },
      timestamp: null,
      receipt: null
    };
  }

  return {
    state,
    reset,
    fetchVaultConfig: vi.fn(async () => ({
      service: { addr: "127.0.0.1:8080", max_payload_bytes: 10485760, tls_enabled: false },
      signing: {
        key_id: "kid-demo",
        algorithm: "ed25519",
        public_key_pem: "demo-key",
        ephemeral: false
      },
      storage: { metadata_backend: "sqlite", blob_backend: "filesystem" },
      retention: { grace_period_days: 30, scan_interval_hours: 24, policies: [] },
      backup: {
        enabled: false,
        directory: "./backups",
        interval_hours: 0,
        retention_count: 7,
        encryption: { enabled: false, algorithm: null, key_id: null }
      },
      timestamp: {
        enabled: false,
        provider: "none",
        url: "",
        assurance: null,
        trust_anchor_pems: [],
        crl_pems: [],
        ocsp_responder_urls: [],
        qualified_signer_pems: [],
        policy_oids: []
      },
      transparency: {
        enabled: false,
        provider: "none",
        url: null,
        log_public_key_pem: null
      },
      disclosure: { policies: [] },
      audit: { enabled: true },
      auth: { enabled: false, scheme: "bearer", principal_labels: [] },
      tenant: { organization_id: null, enforced: false },
      demo: {
        capture_modes: ["synthetic", "live"],
        providers: {
          openai: { live_enabled: false },
          anthropic: { live_enabled: false }
        }
      }
    })),
    fetchDisclosureTemplates: vi.fn(async () => ({
      templates: [
        {
          profile: "regulator_minimum",
          description: "Minimal disclosure suitable for regulator review.",
          default_redaction_groups: [],
          policy: { name: "regulator_minimum_web_demo" }
        },
        {
          profile: "runtime_minimum",
          description: "Runtime evidence disclosure.",
          default_redaction_groups: ["commitments"],
          policy: { name: "runtime_minimum_web_demo" }
        },
        {
          profile: "incident_summary",
          description: "Incident-focused disclosure.",
          default_redaction_groups: [],
          policy: { name: "incident_summary_web_demo" }
        },
        {
          profile: "annex_iv_redacted",
          description: "Annex IV disclosure.",
          default_redaction_groups: [],
          policy: { name: "annex_iv_redacted_web_demo" }
        }
      ],
      redaction_groups: [
        { name: "metadata", description: "Hide metadata" },
        { name: "commitments", description: "Hide commitments" }
      ]
    })),
    fetchDemoProviderResponse: vi.fn(async (_serviceUrl, _apiKey, payload) => ({
      capture_mode:
        payload.mode === "live" ? "live_provider_capture" : "synthetic_demo_capture",
      provider: payload.provider,
      model: payload.model,
      output_text: `Synthetic response for ${payload.user_prompt}`,
      usage: { input_tokens: 12, output_tokens: 18, total_tokens: 30 },
      latency_ms: 210,
      prompt_payload: {
        system_prompt: payload.system_prompt,
        user_prompt: payload.user_prompt
      },
      response_payload: {
        output_text: `Synthetic response for ${payload.user_prompt}`
      },
      trace_payload: {
        request_id: `req-${payload.provider}-${payload.model}`
      }
    })),
    createBundle: vi.fn(async (_serviceUrl, _apiKey, payload) => {
      state.counter += 1;
      const bundleId = `bundle-${state.counter}`;
      state.bundles.set(bundleId, payload);
      return {
        bundle_id: bundleId,
        bundle_root: `root-${bundleId}`,
        created_at: "2026-03-14T10:00:00Z"
      };
    }),
    fetchBundle: vi.fn(async (_serviceUrl, _apiKey, bundleId) => {
      const payload = state.bundles.get(bundleId);
      return bundleFromPayload(bundleId, payload);
    }),
    fetchBundleArtefact: vi.fn(async (_serviceUrl, _apiKey, bundleId, artefactName) => {
      const payload = state.bundles.get(bundleId);
      const artefact = payload.artefacts.find((entry) => entry.name === artefactName);
      return {
        buffer: decodeBase64(artefact.data_base64).buffer,
        contentType: artefact.content_type
      };
    }),
    verifyBundle: vi.fn(async () => ({
      valid: true,
      message: "ok",
      artefacts_verified: 1
    })),
    previewDisclosure: vi.fn(async () => ({
      policy_name: "playground_preview",
      disclosed_item_indices: [0],
      disclosed_artefact_names: ["response.json"]
    })),
    createPack: vi.fn(async (_serviceUrl, _apiKey, payload) => ({
      pack_id: `pack-${payload.pack_type}`,
      bundle_count: state.bundles.size
    })),
    fetchPackManifest: vi.fn(async (_serviceUrl, _apiKey, packId) => ({
      pack_id: packId,
      pack_type: packId.replace("pack-", ""),
      bundles: Array.from(state.bundles.entries()).map(([bundleId, payload]) => ({
        bundle_id: bundleId,
        item_types: payload.capture.items.map((item) => item.type)
      }))
    })),
    downloadPackExport: vi.fn(async () => ({
      buffer: new TextEncoder().encode("pack-bytes").buffer,
      contentType: "application/gzip"
    })),
    fetchSystemSummary: vi.fn(async (_serviceUrl, _apiKey, systemId) => ({
      system_id: systemId,
      bundle_count: state.bundles.size,
      pack_types: ["provider_governance"]
    })),
    listBundles: vi.fn(async () => ({
      items: Array.from(state.bundles.keys()).map((bundleId) => ({
        bundle_id: bundleId
      }))
    }))
  };
});

vi.mock("../lib/vaultApi", async () => {
  const actual = await vi.importActual("../lib/vaultApi");
  return {
    ...actual,
    fetchVaultConfig: mocks.fetchVaultConfig,
    fetchDisclosureTemplates: mocks.fetchDisclosureTemplates,
    fetchDemoProviderResponse: mocks.fetchDemoProviderResponse,
    createBundle: mocks.createBundle,
    fetchBundle: mocks.fetchBundle,
    fetchBundleArtefact: mocks.fetchBundleArtefact,
    verifyBundle: mocks.verifyBundle,
    previewDisclosure: mocks.previewDisclosure,
    createPack: mocks.createPack,
    fetchPackManifest: mocks.fetchPackManifest,
    downloadPackExport: mocks.downloadPackExport,
    fetchSystemSummary: mocks.fetchSystemSummary,
    listBundles: mocks.listBundles
  };
});

function renderApp(initialEntries = ["/"]) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <DemoProvider>
        <AppRoutes />
      </DemoProvider>
    </MemoryRouter>
  );
}

beforeEach(() => {
  mocks.reset();
  vi.clearAllMocks();
});

afterEach(() => {
  cleanup();
});

describe("AppRoutes", () => {
  test("loads the unified landing page on /", async () => {
    renderApp(["/"]);
    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "Keep a clear record of what your AI system did and what controls were around it."
      })
    ).toBeTruthy();
  });

  test("legacy guided and docs routes redirect into the simplified app", async () => {
    renderApp(["/guided"]);
    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "See how Proof Layer fits into common AI workflows"
      })
    ).toBeTruthy();

    cleanup();
    renderApp(["/docs/what-is-proof-layer"]);
    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "Keep a clear record of what your AI system did and what controls were around it."
      })
    ).toBeTruthy();
  });

  test("playground loads the sdk view and advanced route keeps raw controls", async () => {
    renderApp(["/playground"]);
    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "See how Proof Layer fits into common AI workflows"
      })
    ).toBeTruthy();
    expect(screen.getByRole("link", { name: /advanced playground/i })).toBeTruthy();

    cleanup();

    renderApp(["/playground/advanced"]);
    expect(
      await screen.findByRole("heading", {
        level: 2,
        name: "Configure the full proof workflow"
      })
    ).toBeTruthy();
  });

  test("playground lane switching updates scenario cards and script pane", async () => {
    const user = userEvent.setup();
    renderApp(["/playground"]);

    expect(
      await screen.findByRole("heading", { level: 2, name: "Customer support chatbot" })
    ).toBeTruthy();
    expect(screen.getByText(/await proofLayer\.capture/)).toBeTruthy();

    await user.click(
      screen.getByRole("tab", {
        name: /Python Use the Python SDK for reviewed workflows and incident handling/
      })
    );

    expect(
      await screen.findByRole("heading", { level: 2, name: "Hiring review assistant" })
    ).toBeTruthy();
    expect(screen.getByText(/capture_fundamental_rights_assessment/)).toBeTruthy();
  });

  test("running a packless playground scenario reveals record and compliance views", async () => {
    const user = userEvent.setup();
    renderApp(["/playground"]);

    await screen.findByRole("heading", {
      level: 1,
      name: "See how Proof Layer fits into common AI workflows"
    });

    await user.click(screen.getByRole("button", { name: "Run example" }));

    expect(
      await screen.findByRole("heading", { level: 2, name: "What was recorded" })
    ).toBeTruthy();
    expect(screen.getByText("Bundle-by-bundle view")).toBeTruthy();
    expect(mocks.createPack).not.toHaveBeenCalled();

    await user.click(screen.getByRole("tab", { name: "Why this helps with compliance" }));
    expect(await screen.findByText("Customer support chatbot evidence map")).toBeTruthy();

    await user.click(screen.getByRole("tab", { name: "Open in record explorer" }));
    expect(await screen.findByRole("link", { name: "Open record explorer" })).toBeTruthy();
  });

  test("records explorer loads a bundle and honors the selected view", async () => {
    const user = userEvent.setup();
    renderApp(["/playground"]);

    await screen.findByRole("heading", {
      level: 1,
      name: "See how Proof Layer fits into common AI workflows"
    });
    await user.click(screen.getByRole("button", { name: "Run example" }));
    await screen.findByRole("heading", { level: 2, name: "What was recorded" });

    cleanup();

    renderApp(["/records/bundle-1?view=proof"]);
    expect(await screen.findByRole("heading", { level: 1, name: "Customer support chatbot completed" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "Proof" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByText("Verification and disclosure payloads")).toBeTruthy();
  });
});
