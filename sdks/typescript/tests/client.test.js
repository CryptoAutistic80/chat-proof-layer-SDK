import test from "node:test";
import assert from "node:assert/strict";
import { ProofLayerClient } from "../dist/index.js";

test("createBundle posts normalized payload", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return new Response(
      JSON.stringify({ bundle_id: "B1", bundle_root: "sha256:abc", signature: "sig" }),
      { status: 201, headers: { "content-type": "application/json" } }
    );
  };

  const client = new ProofLayerClient({ baseUrl: "http://127.0.0.1:8080", fetchImpl });
  const result = await client.createBundle({
    capture: { foo: "bar" },
    artefacts: [{ name: "prompt.json", contentType: "application/json", data: "{\"x\":1}" }]
  });

  assert.equal(result.bundle_id, "B1");
  assert.equal(captured.url, "http://127.0.0.1:8080/v1/bundles");
  const body = JSON.parse(captured.init.body);
  assert.equal(body.artefacts[0].name, "prompt.json");
  assert.equal(body.artefacts[0].content_type, "application/json");
  assert.ok(typeof body.artefacts[0].data_base64 === "string");
});

test("createPack posts vault pack filters including disclosure bundle_format", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return new Response(
      JSON.stringify({
        pack_id: "P1",
        pack_type: "annex_iv",
        created_at: "2026-03-08T12:00:00Z",
        bundle_format: "disclosure",
        disclosure_policy: "annex_iv_redacted",
        bundle_count: 1,
        bundle_ids: ["B1"]
      }),
      { status: 201, headers: { "content-type": "application/json" } }
    );
  };

  const client = new ProofLayerClient({ baseUrl: "http://127.0.0.1:8080", fetchImpl });
  const result = await client.createPack({
    packType: "annex_iv",
    systemId: "system-123",
    from: "2026-03-01",
    to: "2026-03-08",
    bundleFormat: "disclosure",
    disclosurePolicy: "annex_iv_redacted"
  });

  assert.equal(result.pack_id, "P1");
  assert.equal(captured.url, "http://127.0.0.1:8080/v1/packs");
  const body = JSON.parse(captured.init.body);
  assert.deepEqual(body, {
    pack_type: "annex_iv",
    system_id: "system-123",
    from: "2026-03-01",
    to: "2026-03-08",
    bundle_format: "disclosure",
    disclosure_policy: "annex_iv_redacted"
  });
});

test("downloadPackExport returns raw archive bytes", async () => {
  const payload = new Uint8Array([1, 2, 3, 4]);
  const fetchImpl = async () =>
    new Response(payload, {
      status: 200,
      headers: { "content-type": "application/gzip" }
    });

  const client = new ProofLayerClient({ baseUrl: "http://127.0.0.1:8080", fetchImpl });
  const bytes = await client.downloadPackExport("P1");

  assert.deepEqual(Array.from(bytes), [1, 2, 3, 4]);
});

test("getDisclosureConfig returns disclosure policies from vault config", async () => {
  const fetchImpl = async () =>
    new Response(
      JSON.stringify({
        service: { addr: "127.0.0.1:8080", max_payload_bytes: 10485760 },
        signing: { key_id: "kid-dev-01", algorithm: "ed25519-jws" },
        storage: { metadata_backend: "sqlite", blob_backend: "fs" },
        retention: { grace_period_days: 30, scan_interval_hours: 24, policies: [] },
        timestamp: { enabled: false, provider: "rfc3161", url: "https://tsa.example.test" },
        transparency: { enabled: false, provider: "rekor" },
        disclosure: {
          policies: [
            {
              name: "annex_iv_redacted",
              include_artefact_metadata: true,
              include_artefact_bytes: true,
              artefact_names: ["doc.json"]
            }
          ]
        },
        audit: { enabled: true }
      }),
      { status: 200, headers: { "content-type": "application/json" } }
    );

  const client = new ProofLayerClient({ baseUrl: "http://127.0.0.1:8080", fetchImpl });
  const disclosure = await client.getDisclosureConfig();

  assert.equal(disclosure.policies[0].name, "annex_iv_redacted");
  assert.equal(disclosure.policies[0].include_artefact_bytes, true);
});

test("updateDisclosureConfig issues PUT with policy payload", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return new Response(init.body, {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };

  const client = new ProofLayerClient({ baseUrl: "http://127.0.0.1:8080", fetchImpl });
  const result = await client.updateDisclosureConfig({
    policies: [
      {
        name: "incident_summary",
        allowed_item_types: ["incident_report"],
        include_artefact_metadata: true,
        include_artefact_bytes: false,
        artefact_names: ["incident.json"]
      }
    ]
  });

  assert.equal(captured.url, "http://127.0.0.1:8080/v1/config/disclosure");
  assert.equal(captured.init.method, "PUT");
  assert.equal(result.policies[0].name, "incident_summary");
  assert.equal(result.policies[0].include_artefact_metadata, true);
});

test("previewDisclosure posts named or inline disclosure policy selection", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return new Response(
      JSON.stringify({
        bundle_id: "B1",
        policy_name: "risk_only",
        pack_type: "annex_iv",
        candidate_item_indices: [0, 1],
        disclosed_item_indices: [1],
        disclosed_item_types: ["risk_assessment"],
        disclosed_item_obligation_refs: ["art9"],
        disclosed_artefact_indices: [],
        disclosed_artefact_names: [],
        disclosed_artefact_bytes_included: false
      }),
      { status: 200, headers: { "content-type": "application/json" } }
    );
  };

  const client = new ProofLayerClient({ baseUrl: "http://127.0.0.1:8080", fetchImpl });
  const result = await client.previewDisclosure({
    bundleId: "B1",
    packType: "annex_iv",
    policy: {
      name: "risk_only",
      allowed_obligation_refs: ["art9"],
      include_artefact_metadata: false,
      include_artefact_bytes: false
    }
  });

  assert.equal(captured.url, "http://127.0.0.1:8080/v1/disclosure/preview");
  assert.equal(captured.init.method, "POST");
  const body = JSON.parse(captured.init.body);
  assert.deepEqual(body, {
    bundle_id: "B1",
    pack_type: "annex_iv",
    policy: {
      name: "risk_only",
      allowed_obligation_refs: ["art9"],
      include_artefact_metadata: false,
      include_artefact_bytes: false
    }
  });
  assert.deepEqual(result.disclosed_item_indices, [1]);
});
