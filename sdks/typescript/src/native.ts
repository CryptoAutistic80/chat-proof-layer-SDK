import { Buffer } from "node:buffer";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type {
  BinaryLike,
  CompletenessReport,
  EvaluateCompletenessRequest,
  LocalBuildOptions,
  ProofArtefactInput,
  ProofBundle,
  RedactBundleRequest,
  RedactedBundle,
  VerifyBundleRequest,
  VerifyBundleSummary,
  VerifyRedactedBundleRequest,
  VerifyRedactedBundleSummary
} from "./types.js";

interface NativeModule {
  canonicalizeJson(input: Buffer): Uint8Array;
  hashSha256(input: Buffer): string;
  computeMerkleRoot(digests: string[]): string;
  signBundleRoot(bundleRoot: string, keyPem: string, kid: string): string;
  verifyBundleRoot(jws: string, bundleRoot: string, publicKeyPem: string): boolean;
  buildBundle(
    captureJson: string,
    artefactsJson: string,
    keyPem: string,
    kid: string,
    bundleId: string,
    createdAt: string
  ): string;
  verifyBundle(bundleJson: string, artefactsJson: string, publicKeyPem: string): string;
  redactBundle(
    bundleJson: string,
    itemIndicesJson: string,
    artefactIndicesJson: string,
    fieldRedactionsJson: string
  ): string;
  verifyRedactedBundle(bundleJson: string, artefactsJson: string, publicKeyPem: string): string;
  evaluateCompleteness(bundleJson: string, profile: string): string;
}

type NamedBinaryArtefact = { name: string; data: BinaryLike };

const require = createRequire(import.meta.url);
const moduleDir = path.dirname(fileURLToPath(import.meta.url));
const nativePath = path.join(moduleDir, "..", "native", "proof-layer-napi.node");

function loadNativeModule(): NativeModule {
  try {
    return require(nativePath) as NativeModule;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Failed to load native proof-layer bindings from ${nativePath}. Run \`npm run build:native\` first.\n${message}`
    );
  }
}

const native = loadNativeModule();

function toBytes(value: BinaryLike): Buffer {
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

function toBase64(value: BinaryLike): string {
  return toBytes(value).toString("base64");
}

function normalizeArtefacts(
  artefacts: ProofArtefactInput[] | Record<string, BinaryLike>
): Array<{ name: string; data_base64: string }> {
  if (Array.isArray(artefacts)) {
    return artefacts.map((artefact) => ({
      name: artefact.name,
      data_base64: toBase64(artefact.data)
    }));
  }

  return Object.entries(artefacts).map(([name, data]) => ({
    name,
    data_base64: toBase64(data)
  }));
}

function normalizeBuildArtefacts(artefacts: ProofArtefactInput[]): Array<{
  name: string;
  content_type: string;
  data_base64: string;
}> {
  return artefacts.map((artefact) => ({
    name: artefact.name,
    content_type: artefact.contentType ?? "application/octet-stream",
    data_base64: toBase64(artefact.data)
  }));
}

export function canonicalizeJson(value: BinaryLike): Buffer {
  return Buffer.from(native.canonicalizeJson(toBytes(value)));
}

export function hashSha256(value: BinaryLike): string {
  return native.hashSha256(toBytes(value));
}

export function computeMerkleRoot(digests: string[]): string {
  return native.computeMerkleRoot(digests);
}

export function signBundleRoot(bundleRoot: string, keyPem: string, kid: string): string {
  return native.signBundleRoot(bundleRoot, keyPem, kid);
}

export function verifyBundleRoot(jws: string, bundleRoot: string, publicKeyPem: string): boolean {
  return native.verifyBundleRoot(jws, bundleRoot, publicKeyPem);
}

export function buildBundle({
  capture,
  artefacts,
  keyPem,
  kid,
  bundleId,
  createdAt
}: LocalBuildOptions): ProofBundle {
  const captureJson = typeof capture === "string" ? capture : JSON.stringify(capture);
  const artefactsJson = JSON.stringify(normalizeBuildArtefacts(artefacts));
  return JSON.parse(native.buildBundle(captureJson, artefactsJson, keyPem, kid, bundleId, createdAt)) as ProofBundle;
}

export function verifyBundle({
  bundle,
  artefacts,
  publicKeyPem
}: VerifyBundleRequest): VerifyBundleSummary {
  const bundleJson = typeof bundle === "string" ? bundle : JSON.stringify(bundle);
  const artefactsJson = JSON.stringify(
    normalizeArtefacts(artefacts as NamedBinaryArtefact[])
  );
  return JSON.parse(native.verifyBundle(bundleJson, artefactsJson, publicKeyPem)) as VerifyBundleSummary;
}

export function redactBundle({
  bundle,
  itemIndices,
  artefactIndices = [],
  fieldRedactions = {}
}: RedactBundleRequest): RedactedBundle {
  const bundleJson = typeof bundle === "string" ? bundle : JSON.stringify(bundle);
  return JSON.parse(
    native.redactBundle(
      bundleJson,
      JSON.stringify(itemIndices),
      JSON.stringify(artefactIndices),
      JSON.stringify(fieldRedactions)
    )
  ) as RedactedBundle;
}

export function verifyRedactedBundle({
  bundle,
  artefacts,
  publicKeyPem
}: VerifyRedactedBundleRequest): VerifyRedactedBundleSummary {
  const bundleJson = typeof bundle === "string" ? bundle : JSON.stringify(bundle);
  const artefactsJson = JSON.stringify(normalizeArtefacts(artefacts as NamedBinaryArtefact[]));
  return JSON.parse(
    native.verifyRedactedBundle(bundleJson, artefactsJson, publicKeyPem)
  ) as VerifyRedactedBundleSummary;
}

export function evaluateCompleteness({
  bundle,
  profile
}: EvaluateCompletenessRequest): CompletenessReport {
  if (!bundle) {
    throw new Error("bundle is required for local completeness evaluation");
  }
  const bundleJson = typeof bundle === "string" ? bundle : JSON.stringify(bundle);
  return JSON.parse(native.evaluateCompleteness(bundleJson, profile)) as CompletenessReport;
}
