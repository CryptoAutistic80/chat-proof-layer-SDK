import { mkdir, copyFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(scriptDir, "..");
const repoRoot = path.resolve(packageRoot, "..", "..");
const nativeDir = path.join(packageRoot, "native");
const profile = process.env.PROOF_SDK_NATIVE_PROFILE === "release" ? "release" : "debug";
const targetDir = path.join(repoRoot, "target", profile);

function sharedLibraryPath() {
  switch (process.platform) {
    case "linux":
      return path.join(targetDir, "libproof_layer_napi.so");
    case "darwin":
      return path.join(targetDir, "libproof_layer_napi.dylib");
    case "win32":
      return path.join(targetDir, "proof_layer_napi.dll");
    default:
      throw new Error(`unsupported platform: ${process.platform}`);
  }
}

async function main() {
  const cargoArgs = ["build", "-p", "proof-layer-napi"];
  if (profile === "release") {
    cargoArgs.push("--release");
  }

  await execFileAsync("cargo", cargoArgs, {
    cwd: repoRoot,
    env: process.env,
  });

  const builtLibrary = sharedLibraryPath();
  await stat(builtLibrary);
  await mkdir(nativeDir, { recursive: true });
  await copyFile(builtLibrary, path.join(nativeDir, "proof-layer-napi.node"));
}

await main();
