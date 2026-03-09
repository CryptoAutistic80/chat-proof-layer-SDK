import React from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, test, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DemoProvider } from "./DemoContext";
import { AppRoutes } from "./routes";

vi.mock("../lib/vaultApi", async () => {
  const actual = await vi.importActual("../lib/vaultApi");
  return {
    ...actual,
    fetchVaultConfig: vi.fn(async () => ({
      service: { addr: "127.0.0.1:8080", max_payload_bytes: 10485760, tls_enabled: false },
      signing: { key_id: "kid-demo", algorithm: "ed25519", public_key_pem: "demo-key", ephemeral: false },
      storage: { metadata_backend: "sqlite", blob_backend: "filesystem" },
      retention: { grace_period_days: 30, scan_interval_hours: 24, policies: [] },
      backup: { enabled: false, directory: "./backups", interval_hours: 0, retention_count: 7, encryption: { enabled: false, algorithm: null, key_id: null } },
      timestamp: { enabled: false, provider: "none", url: "", assurance: null, trust_anchor_pems: [], crl_pems: [], ocsp_responder_urls: [], qualified_signer_pems: [], policy_oids: [] },
      transparency: { enabled: false, provider: "none", url: null, log_public_key_pem: null },
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
    listBundles: vi.fn(async () => ({ items: [] }))
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

afterEach(() => {
  cleanup();
});

describe("AppRoutes", () => {
  test("redirects / to /playground", async () => {
    renderApp(["/"]);
    expect(
      await screen.findByRole("heading", { level: 2, name: "Configure the run" })
    ).toBeTruthy();
  });

  test("preset selection updates actor role and disclosure defaults", async () => {
    const user = userEvent.setup();
    renderApp(["/playground"]);
    expect(
      await screen.findByRole("heading", { level: 2, name: "Configure the run" })
    ).toBeTruthy();

    await user.click(screen.getByRole("button", { name: /incident review/i }));

    await waitFor(() => {
      expect(screen.getByLabelText("Actor role").value).toBe("integrator");
    });
    expect(screen.getByLabelText("Disclosure profile").value).toBe("incident_summary");
    expect(screen.getByLabelText("Bundle format").value).toBe("disclosure");
  });

  test("shows temporary provider key guidance when vault live support is unavailable", async () => {
    const user = userEvent.setup();
    renderApp(["/playground"]);
    expect(
      await screen.findByRole("heading", { level: 2, name: "Configure the run" })
    ).toBeTruthy();
    expect(screen.getByRole("option", { name: "Live provider" }).disabled).toBe(false);
    expect(screen.getByText(/Vault API key is only needed when the vault has bearer auth enabled/i)).toBeTruthy();

    await user.selectOptions(screen.getByLabelText("Capture mode"), "live");
    expect(screen.getByLabelText("Temporary provider API key")).toBeTruthy();
  });
});
