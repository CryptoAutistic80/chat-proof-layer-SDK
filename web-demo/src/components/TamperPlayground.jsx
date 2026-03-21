import React, { useCallback, useEffect, useRef, useState } from "react";
import { sha256Hex, canonicalize, computeMerkleRoot, shortHash } from "../lib/clientCrypto";

/**
 * Interactive tamper-and-verify playground.
 * Shows a sealed bundle, lets the user edit fields, and
 * re-verifies in real time so they can see the proof break.
 *
 * Props:
 *   bundle          - the original sealed bundle (from buildSampleBundle)
 *   onVerifyChange  - optional callback({ valid, detail }) when verification state changes
 *   compact         - smaller variant for embedding in the hero
 */
export function TamperPlayground({ bundle, onVerifyChange, compact }) {
  const [editedOutput, setEditedOutput] = useState("");
  const [originalOutput, setOriginalOutput] = useState("");
  const [verifyState, setVerifyState] = useState(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [tampered, setTampered] = useState(false);
  const [showAnimation, setShowAnimation] = useState(false);
  const debounceRef = useRef(null);

  useEffect(() => {
    if (!bundle) return;
    const output = bundle.items?.[0]?.data?.output ?? "";
    setEditedOutput(output);
    setOriginalOutput(output);
    runVerification(bundle, output);
  }, [bundle]);

  const runVerification = useCallback(
    async (b, currentOutput) => {
      if (!b) return;
      setIsVerifying(true);
      setShowAnimation(true);

      try {
        const modifiedItem = {
          ...b.items[0].data,
          output: currentOutput
        };
        const newItemHash = await sha256Hex(canonicalize(modifiedItem));
        const itemHashMatch = newItemHash === b.items[0].hash;

        const allLeafHashes = [
          newItemHash,
          ...b.items.slice(1).map((i) => i.hash),
          ...b.artefacts.map((a) => a.sha256)
        ];
        const newRoot = await computeMerkleRoot(allLeafHashes);
        const rootMatch = newRoot === b.root;

        const isTampered = currentOutput !== originalOutput;
        const valid = itemHashMatch && rootMatch;

        const result = {
          valid,
          tampered: isTampered,
          originalItemHash: b.items[0].hash,
          newItemHash,
          itemHashMatch,
          originalRoot: b.root,
          newRoot,
          rootMatch
        };

        setVerifyState(result);
        setTampered(isTampered);
        onVerifyChange?.(result);
      } finally {
        setIsVerifying(false);
        setTimeout(() => setShowAnimation(false), 600);
      }
    },
    [bundle, originalOutput, onVerifyChange]
  );

  const handleOutputChange = (e) => {
    const value = e.target.value;
    setEditedOutput(value);

    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      runVerification(bundle, value);
    }, 200);
  };

  const handleReset = () => {
    setEditedOutput(originalOutput);
    runVerification(bundle, originalOutput);
  };

  if (!bundle) {
    return null;
  }

  const status = verifyState?.valid ? "pass" : "fail";

  return (
    <div className={`tamper-container ${compact ? "tamper-compact" : ""}`}>
      {!compact && (
        <div className="tamper-header">
          <div>
            <span className="section-label">Tamper playground</span>
            <h3>Edit the model output and watch the proof break</h3>
          </div>
          <p className="tamper-lead">
            The text below is the AI response sealed inside this evidence bundle.
            Try changing it. The cryptographic verification runs in your browser in real time.
          </p>
        </div>
      )}

      <div className="tamper-workspace">
        {/* Editable response */}
        <div className="tamper-editor">
          <div className="tamper-editor-head">
            <span className="section-label">Model output</span>
            {tampered && (
              <button type="button" className="ghost-btn tamper-reset-btn" onClick={handleReset}>
                Reset to original
              </button>
            )}
          </div>
          <textarea
            className="tamper-textarea"
            value={editedOutput}
            onChange={handleOutputChange}
            rows={compact ? 4 : 7}
            spellCheck={false}
          />
          {tampered && (
            <span className="tamper-warning-badge">Modified</span>
          )}
        </div>

        {/* Verification result */}
        <div className={`tamper-verify ${showAnimation ? "tamper-verify-animating" : ""}`}>
          <div className={`tamper-seal tamper-seal-${status}`}>
            <div className="tamper-seal-icon">{verifyState?.valid ? "\u2713" : "\u2717"}</div>
            <strong>{verifyState?.valid ? "Integrity verified" : "Integrity broken"}</strong>
            <span>
              {verifyState?.valid
                ? "The content matches the sealed record."
                : "The content has been modified. The cryptographic proof no longer matches."}
            </span>
          </div>

          <div className="tamper-hash-chain">
            <TamperHashRow
              label="Item hash"
              original={shortHash(verifyState?.originalItemHash, 20)}
              current={shortHash(verifyState?.newItemHash, 20)}
              match={verifyState?.itemHashMatch}
            />
            <TamperHashRow
              label="Merkle root"
              original={shortHash(verifyState?.originalRoot, 20)}
              current={shortHash(verifyState?.newRoot, 20)}
              match={verifyState?.rootMatch}
            />
          </div>

          {!compact && tampered && (
            <div className="tamper-explain">
              <strong>What happened</strong>
              <p>
                When you changed the text, the SHA-256 hash of the item changed.
                That new hash produced a different Merkle root.
                Since the Ed25519 signature was computed over the original root,
                any verifier can now detect that this record was modified after sealing.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function TamperHashRow({ label, original, current, match }) {
  return (
    <div className={`tamper-hash-row ${match ? "tamper-hash-match" : "tamper-hash-mismatch"}`}>
      <span className="tamper-hash-label">{label}</span>
      <div className="tamper-hash-values">
        <div className="tamper-hash-pair">
          <span className="tamper-hash-tag">sealed</span>
          <code>{original}</code>
        </div>
        <div className="tamper-hash-pair">
          <span className="tamper-hash-tag">current</span>
          <code className={match ? "" : "tamper-hash-changed"}>{current}</code>
        </div>
      </div>
      <span className={`status-pill is-${match ? "good" : "warn"}`}>
        {match ? "match" : "mismatch"}
      </span>
    </div>
  );
}
