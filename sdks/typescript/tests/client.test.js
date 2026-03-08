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
    bundleFormat: "disclosure"
  });

  assert.equal(result.pack_id, "P1");
  assert.equal(captured.url, "http://127.0.0.1:8080/v1/packs");
  const body = JSON.parse(captured.init.body);
  assert.deepEqual(body, {
    pack_type: "annex_iv",
    system_id: "system-123",
    from: "2026-03-01",
    to: "2026-03-08",
    bundle_format: "disclosure"
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
