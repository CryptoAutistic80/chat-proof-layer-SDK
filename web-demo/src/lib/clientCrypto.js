/**
 * Client-side cryptographic utilities using Web Crypto API.
 * Powers the bundle visualizer, tamper playground, and hero demo
 * without requiring a vault connection.
 */

const encoder = new TextEncoder();

/** SHA-256 hash of a string, returned as hex. */
export async function sha256Hex(input) {
  const data = typeof input === "string" ? encoder.encode(input) : input;
  const buffer = await crypto.subtle.digest("SHA-256", data);
  return arrayBufferToHex(buffer);
}

/** Convert ArrayBuffer to lowercase hex string. */
export function arrayBufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

/** Truncate a hex hash for display. */
export function shortHash(hash, len = 12) {
  if (!hash || hash.length < len) return hash ?? "";
  return hash.slice(0, len) + "\u2026";
}

/**
 * RFC 8785-style JSON canonicalization (simplified).
 * Sorts object keys recursively, produces deterministic JSON.
 */
export function canonicalize(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  const keys = Object.keys(value).sort();
  const pairs = keys.map((k) => JSON.stringify(k) + ":" + canonicalize(value[k]));
  return "{" + pairs.join(",") + "}";
}

/**
 * Compute the hash of a canonicalized evidence item.
 * Mirrors the Rust core: canonical JSON bytes -> SHA-256.
 */
export async function hashItem(item) {
  const canonical = canonicalize(item);
  return sha256Hex(canonical);
}

/**
 * Compute a Merkle root from an array of hex leaf hashes.
 * Uses the same pairwise-hash-with-odd-promotion approach as the Rust core.
 */
export async function computeMerkleRoot(leafHashes) {
  if (leafHashes.length === 0) return null;
  if (leafHashes.length === 1) return leafHashes[0];

  let level = [...leafHashes];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(await sha256Hex(level[i] + level[i + 1]));
      } else {
        next.push(level[i]);
      }
    }
    level = next;
  }
  return level[0];
}

/**
 * Build the full Merkle tree structure for visualization.
 * Returns an array of levels, from leaves to root.
 * Each node includes { hash, left, right, isPromotion }.
 */
export async function buildMerkleTree(leafHashes) {
  if (leafHashes.length === 0) return { levels: [], root: null };

  const levels = [leafHashes.map((h) => ({ hash: h, leaf: true }))];

  let current = leafHashes;
  while (current.length > 1) {
    const nextLevel = [];
    const nextHashes = [];
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 < current.length) {
        const combined = await sha256Hex(current[i] + current[i + 1]);
        nextLevel.push({
          hash: combined,
          leftChild: i,
          rightChild: i + 1,
          isPromotion: false
        });
        nextHashes.push(combined);
      } else {
        nextLevel.push({
          hash: current[i],
          leftChild: i,
          rightChild: null,
          isPromotion: true
        });
        nextHashes.push(current[i]);
      }
    }
    levels.push(nextLevel);
    current = nextHashes;
  }

  return { levels, root: current[0] };
}

/**
 * Verify a bundle's integrity client-side.
 * Recomputes artefact hashes, item hashes, and the Merkle root.
 * Returns { valid, rootMatch, artefactResults, itemResults, computedRoot, expectedRoot }.
 */
export async function verifyBundleIntegrity(bundle) {
  const artefactResults = await Promise.all(
    (bundle.artefacts ?? []).map(async (a) => {
      const computed = await sha256Hex(canonicalize(a.content));
      return {
        name: a.name,
        expected: a.sha256,
        computed,
        valid: computed === a.sha256
      };
    })
  );

  const itemResults = await Promise.all(
    (bundle.items ?? []).map(async (item) => {
      const computed = await hashItem(item.data);
      return {
        type: item.type,
        expected: item.hash,
        computed,
        valid: computed === item.hash
      };
    })
  );

  const allLeafHashes = [
    ...itemResults.map((r) => r.computed),
    ...artefactResults.map((r) => r.computed)
  ];

  const computedRoot = await computeMerkleRoot(allLeafHashes);
  const rootMatch = computedRoot === bundle.root;

  return {
    valid: rootMatch && artefactResults.every((r) => r.valid) && itemResults.every((r) => r.valid),
    rootMatch,
    artefactResults,
    itemResults,
    computedRoot,
    expectedRoot: bundle.root
  };
}
