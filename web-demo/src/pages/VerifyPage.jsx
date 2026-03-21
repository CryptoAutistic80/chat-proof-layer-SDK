import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { buildMerkleTree } from "../lib/clientCrypto";
import { buildSampleBundle } from "../lib/sampleBundle";
import { BundleVisualizer } from "../components/BundleVisualizer";
import { TamperPlayground } from "../components/TamperPlayground";
import { DisclosureComparison } from "../components/DisclosureComparison";
import { LEGAL_BOUNDARY } from "../lib/siteContent";

/**
 * Standalone page for the tamper playground, bundle visualizer,
 * and disclosure comparison. Runs entirely offline using the
 * sample bundle and Web Crypto API.
 */
export function VerifyPage() {
  const [bundle, setBundle] = useState(null);
  const [merkleTree, setMerkleTree] = useState(null);
  const [activeTab, setActiveTab] = useState("tamper");

  useEffect(() => {
    let cancelled = false;
    async function init() {
      const b = await buildSampleBundle();
      if (cancelled) return;
      setBundle(b);
      const leafHashes = [
        ...b.items.map((i) => i.hash),
        ...b.artefacts.map((a) => a.sha256)
      ];
      const tree = await buildMerkleTree(leafHashes);
      if (cancelled) return;
      setMerkleTree(tree);
    }
    init();
    return () => { cancelled = true; };
  }, []);

  return (
    <section className="page-stack verify-page">
      <section className="panel studio-hero">
        <div className="studio-hero-copy">
          <span className="section-label">Verify and explore</span>
          <h1>See tamper evidence in action</h1>
          <p className="studio-lead">
            This page runs entirely in your browser using the Web Crypto API.
            No vault connection needed. Explore the cryptographic structure of a
            sealed evidence bundle, try tampering with it, and see how selective
            disclosure works.
          </p>
        </div>
        <aside className="studio-hero-side">
          <span className="section-label">Boundary</span>
          <p>{LEGAL_BOUNDARY}</p>
          <Link to="/playground" className="text-link">
            Need the full vault-connected playground?
          </Link>
        </aside>
      </section>

      <div className="verify-tabs" role="tablist" aria-label="Verify page tabs">
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "tamper"}
          className={`hero-demo-tab ${activeTab === "tamper" ? "is-active" : ""}`}
          onClick={() => setActiveTab("tamper")}
        >
          <span className="hero-demo-tab-number">01</span>
          <strong>Tamper playground</strong>
          <span>Edit sealed evidence, watch verification break</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "structure"}
          className={`hero-demo-tab ${activeTab === "structure" ? "is-active" : ""}`}
          onClick={() => setActiveTab("structure")}
        >
          <span className="hero-demo-tab-number">02</span>
          <strong>Bundle structure</strong>
          <span>Interactive Merkle tree and hash chain</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "disclosure"}
          className={`hero-demo-tab ${activeTab === "disclosure" ? "is-active" : ""}`}
          onClick={() => setActiveTab("disclosure")}
        >
          <span className="hero-demo-tab-number">03</span>
          <strong>Selective disclosure</strong>
          <span>Same record, different audiences</span>
        </button>
      </div>

      {!bundle ? (
        <section className="panel empty-state">
          <div className="hero-demo-spinner" />
          <span>Building sample bundle...</span>
        </section>
      ) : (
        <>
          {activeTab === "tamper" && (
            <section className="panel">
              <TamperPlayground bundle={bundle} />
            </section>
          )}

          {activeTab === "structure" && (
            <section className="panel">
              <div className="panel-head compact">
                <div>
                  <span className="section-label">Cryptographic structure</span>
                  <h2>How the bundle is assembled</h2>
                </div>
              </div>
              <p className="section-intro" style={{ marginBottom: 18 }}>
                Each evidence item and artefact is hashed individually. Those leaf hashes
                are combined pairwise into a Merkle tree. The root is signed with Ed25519.
                Click any node to inspect it.
              </p>
              <BundleVisualizer bundle={bundle} merkleTree={merkleTree} />
            </section>
          )}

          {activeTab === "disclosure" && (
            <section className="panel">
              <DisclosureComparison bundle={bundle} />
            </section>
          )}
        </>
      )}
    </section>
  );
}
