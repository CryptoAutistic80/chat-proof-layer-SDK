import { Buffer } from "node:buffer";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const moduleDir = path.dirname(fileURLToPath(import.meta.url));
const nativePath = path.join(moduleDir, "..", "native", "proof-layer-napi.node");

function loadNativeModule() {
  try {
    return require(nativePath);
  } catch (error) {
    throw new Error(
      `Failed to load native proof-layer bindings from ${nativePath}. Run \`npm run build:native\` first.\n${error.message}`
    );
  }
}

const native = loadNativeModule();

function toBytes(value) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }
  if (typeof value === "string") {
    return Buffer.from(value, "utf8");
  }
  return Buffer.from(JSON.stringify(value), "utf8");
}

function toBase64(value) {
  return toBytes(value).toString("base64");
}

function normalizeArtefacts(artefacts) {
  if (Array.isArray(artefacts)) {
    return artefacts.map((artefact) => ({
      name: artefact.name,
      data_base64: toBase64(artefact.data)
    }));
  }

  if (artefacts && typeof artefacts === "object") {
    return Object.entries(artefacts).map(([name, data]) => ({
      name,
      data_base64: toBase64(data)
    }));
  }

  throw new Error("artefacts must be an array of {name, data} or a name->data object");
}

export function canonicalizeJson(value) {
  return Buffer.from(native.canonicalizeJson(toBytes(value)));
}

export function hashSha256(value) {
  return native.hashSha256(toBytes(value));
}

export function computeMerkleRoot(digests) {
  return native.computeMerkleRoot(digests);
}

export function signBundleRoot(bundleRoot, keyPem, kid) {
  return native.signBundleRoot(bundleRoot, keyPem, kid);
}

export function verifyBundleRoot(jws, bundleRoot, publicKeyPem) {
  return native.verifyBundleRoot(jws, bundleRoot, publicKeyPem);
}

export function verifyBundle({ bundle, artefacts, publicKeyPem }) {
  const bundleJson = typeof bundle === "string" ? bundle : JSON.stringify(bundle);
  const artefactsJson = JSON.stringify(normalizeArtefacts(artefacts));
  return JSON.parse(native.verifyBundle(bundleJson, artefactsJson, publicKeyPem));
}
