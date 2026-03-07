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
