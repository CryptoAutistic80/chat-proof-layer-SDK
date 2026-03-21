import React, { useEffect, useMemo, useState } from "react";
import { shortHash } from "../lib/clientCrypto";

/**
 * Interactive visualization of a bundle's cryptographic structure.
 * Shows: artefacts + items -> leaf hashes -> Merkle tree -> root -> signature -> timestamp/anchor.
 *
 * Props:
 *   bundle       - { items, artefacts, root, signature, timestamp, receipt }
 *   merkleTree   - result from buildMerkleTree()
 *   onNodeSelect - optional callback when a node is clicked
 *   highlightNode - optional node hash to highlight
 *   compact      - boolean, smaller variant for embedding
 */
export function BundleVisualizer({ bundle, merkleTree, onNodeSelect, highlightNode, compact }) {
  const [selected, setSelected] = useState(null);

  const handleSelect = (node) => {
    setSelected((prev) => (prev?.hash === node.hash ? null : node));
    onNodeSelect?.(node);
  };

  const activeHash = highlightNode ?? selected?.hash;

  if (!bundle || !merkleTree) {
    return (
      <div className="viz-empty">
        <span className="section-label">Bundle structure</span>
        <p>Run a workflow or load a bundle to see its cryptographic structure.</p>
      </div>
    );
  }

  return (
    <div className={`viz-container ${compact ? "viz-compact" : ""}`}>
      <div className="viz-header">
        <span className="section-label">Cryptographic structure</span>
      </div>

      {/* Assurance chain: signature <- root <- tree */}
      <div className="viz-chain">
        {/* Signature */}
        <div className="viz-chain-row">
          <VizNode
            kind="signature"
            label="Ed25519 Signature"
            hash={bundle.signature}
            sublabel={bundle.signing_key_id ?? "signing key"}
            active={false}
            sealed
          />
          {bundle.timestamp ? (
            <VizNode
              kind="timestamp"
              label="RFC 3161 Timestamp"
              hash={bundle.timestamp.sealed_at ?? "attached"}
              sublabel={bundle.timestamp.tsa ?? "TSA"}
              active={false}
              sealed
            />
          ) : (
            <VizNodePlaceholder label="Timestamp" sublabel="not attached" />
          )}
          {bundle.receipt ? (
            <VizNode
              kind="anchor"
              label="Transparency Receipt"
              hash="anchored"
              sublabel="Rekor log"
              active={false}
              sealed
            />
          ) : (
            <VizNodePlaceholder label="Transparency" sublabel="not anchored" />
          )}
        </div>

        {/* Connector */}
        <div className="viz-connector" aria-hidden>
          <div className="viz-connector-line" />
          <span className="viz-connector-label">signs</span>
        </div>

        {/* Merkle root */}
        <div className="viz-chain-row viz-chain-row-center">
          <VizNode
            kind="root"
            label="Merkle Root"
            hash={bundle.root}
            active={activeHash === bundle.root}
            onClick={() => handleSelect({ hash: bundle.root, kind: "root" })}
          />
        </div>

        {/* Connector */}
        <div className="viz-connector" aria-hidden>
          <div className="viz-connector-line" />
          <span className="viz-connector-label">computed from</span>
        </div>

        {/* Intermediate tree levels (if any, in reverse order) */}
        {merkleTree.levels.length > 2 &&
          merkleTree.levels
            .slice(1, -1)
            .reverse()
            .map((level, levelIndex) => (
              <React.Fragment key={`mid-${levelIndex}`}>
                <div className="viz-chain-row">
                  {level.map((node, i) => (
                    <VizNode
                      key={`mid-${levelIndex}-${i}`}
                      kind="intermediate"
                      label={node.isPromotion ? "promoted" : `hash pair`}
                      hash={node.hash}
                      active={activeHash === node.hash}
                      onClick={() => handleSelect({ ...node, kind: "intermediate" })}
                      dimmed={node.isPromotion}
                    />
                  ))}
                </div>
                <div className="viz-connector" aria-hidden>
                  <div className="viz-connector-line" />
                </div>
              </React.Fragment>
            ))}

        {/* Leaf hashes */}
        <div className="viz-chain-row viz-leaf-row">
          {(bundle.items ?? []).map((item, i) => (
            <VizNode
              key={`item-${i}`}
              kind="item"
              label={item.type}
              hash={item.hash}
              active={activeHash === item.hash}
              onClick={() => handleSelect({ ...item, kind: "item", index: i })}
            />
          ))}
          {(bundle.artefacts ?? []).map((a, i) => (
            <VizNode
              key={`art-${i}`}
              kind="artefact"
              label={a.name}
              hash={a.sha256}
              active={activeHash === a.sha256}
              onClick={() => handleSelect({ ...a, kind: "artefact", index: i })}
            />
          ))}
        </div>
      </div>

      {/* Detail panel for selected node */}
      {selected && (
        <div className="viz-detail">
          <div className="viz-detail-head">
            <strong>{selected.kind === "item" ? selected.type : selected.kind === "artefact" ? selected.name : selected.kind}</strong>
            <button type="button" className="ghost-btn" onClick={() => setSelected(null)}>
              Close
            </button>
          </div>
          <div className="viz-detail-hash">
            <span className="section-label">Hash</span>
            <code>{selected.hash ?? selected.sha256 ?? "N/A"}</code>
          </div>
          {selected.data && (
            <pre className="pre--compact">{JSON.stringify(selected.data, null, 2)}</pre>
          )}
          {selected.content && (
            <pre className="pre--compact">{JSON.stringify(selected.content, null, 2)}</pre>
          )}
        </div>
      )}
    </div>
  );
}

function VizNode({ kind, label, hash, sublabel, active, onClick, sealed, dimmed }) {
  const kindClass = `viz-node-${kind}`;
  return (
    <button
      type="button"
      className={`viz-node ${kindClass} ${active ? "viz-node-active" : ""} ${sealed ? "viz-node-sealed" : ""} ${dimmed ? "viz-node-dimmed" : ""}`}
      onClick={onClick}
      disabled={!onClick}
    >
      <span className="viz-node-kind">{label}</span>
      <span className="viz-node-hash">{shortHash(hash, 16)}</span>
      {sublabel && <span className="viz-node-sublabel">{sublabel}</span>}
    </button>
  );
}

function VizNodePlaceholder({ label, sublabel }) {
  return (
    <div className="viz-node viz-node-placeholder">
      <span className="viz-node-kind">{label}</span>
      <span className="viz-node-sublabel">{sublabel}</span>
    </div>
  );
}
