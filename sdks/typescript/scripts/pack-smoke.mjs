import { execFile } from "node:child_process";
import { mkdir, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(scriptDir, "..");
const artifactDir = path.join(packageRoot, "dist", "artifacts");
const tarExecutable = process.platform === "win32" ? "tar.exe" : "tar";

function npmInvocation(args) {
  if (process.env.npm_execpath) {
    return {
      file: process.execPath,
      args: [process.env.npm_execpath, ...args],
    };
  }

  return {
    file: process.platform === "win32" ? "npm.cmd" : "npm",
    args,
  };
}

const requiredEntries = [
  "package/package.json",
  "package/README.md",
  "package/dist/index.js",
  "package/dist/index.d.ts",
  "package/native/proof-layer-napi.node",
];

async function main() {
  await rm(artifactDir, { recursive: true, force: true });
  await mkdir(artifactDir, { recursive: true });
  const env = { ...process.env };
  env.PROOF_SDK_NATIVE_PROFILE ??= "release";

  const npmPack = npmInvocation(["pack", "--json", "--pack-destination", artifactDir]);
  const { stdout } = await execFileAsync(npmPack.file, npmPack.args, {
    cwd: packageRoot,
    env,
  });
  const output = JSON.parse(stdout);
  const tarballName = output[0]?.filename;
  if (!tarballName) {
    throw new Error(`npm pack did not report a tarball filename: ${stdout}`);
  }

  const tarballPath = path.join(artifactDir, tarballName);
  const listing = await execFileAsync(tarExecutable, ["-tzf", tarballPath], {
    cwd: packageRoot,
    env: process.env,
  });
  const members = new Set(
    listing.stdout
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
  );

  for (const entry of requiredEntries) {
    if (!members.has(entry)) {
      throw new Error(`npm package artifact is missing ${entry}`);
    }
  }

  const packageJson = JSON.parse(
    await readFile(path.join(packageRoot, "package.json"), "utf8")
  );

  console.log(
    JSON.stringify(
      {
        package: packageJson.name,
        version: packageJson.version,
        tarball: tarballPath,
        checked_entries: requiredEntries,
      },
      null,
      2
    )
  );
}

await main();
