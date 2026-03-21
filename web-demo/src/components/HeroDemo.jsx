import React, { useCallback, useEffect, useState } from "react";
import { buildMerkleTree, shortHash } from "../lib/clientCrypto";
import { buildSampleBundle } from "../lib/sampleBundle";
import { BundleVisualizer } from "./BundleVisualizer";
import { TamperPlayground } from "./TamperPlayground";
import { DisclosureComparison } from "./DisclosureComparison";

const STEPS = [
  { id: "seal", label: "Seal", description: "Evidence is hashed, arranged into a Merkle tree, and signed." },
  { id: "tamper", label: "Tamper", description: "Try editing the response. Watch the proof break in real time." },
  { id: "disclose", label: "Disclose", description: "Same record, different views. The proof still holds." }
];

/**
 * Interactive hero demo for the homepage.
 * Zero-config: builds a sample bundle client-side, then walks through
 * seal -> tamper -> disclose in three tabs.
 */
export function HeroDemo() {
  const [bundle, setBundle] = useState(null);
  const [merkleTree, setMerkleTree] = useState(null);
  const [activeStep, setActiveStep] = useState("seal");
  const [sealPhase, setSealPhase] = useState("idle");
  const [verifyResult, setVerifyResult] = useState(null);

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

  const handleSeal = useCallback(() => {
    setSealPhase("hashing");
    setTimeout(() => setSealPhase("tree"), 600);
    setTimeout(() => setSealPhase("signing"), 1200);
    setTimeout(() => setSealPhase("sealed"), 1800);
  }, []);

  const handleVerifyChange = useCallback((result) => {
    setVerifyResult(result);
  }, []);

  if (!bundle) {
    return (
      <div className="hero-demo hero-demo-loading">
        <div className="hero-demo-spinner" />
        <span>Building sample evidence bundle...</span>
      </div>
    );
  }

  return (
    <div className="hero-demo">
      <div className="hero-demo-head">
        <span className="section-label">Interactive demo</span>
        <h2>See how tamper-evident evidence works</h2>
        <p className="hero-demo-lead">
          This runs entirely in your browser. No vault, no API keys, no setup required.
        </p>
      </div>

      {/* Step tabs */}
      <div className="hero-demo-tabs" role="tablist" aria-label="Demo steps">
        {STEPS.map((step, i) => (
          <button
            key={step.id}
            type="button"
            role="tab"
            aria-selected={activeStep === step.id}
            className={`hero-demo-tab ${activeStep === step.id ? "is-active" : ""}`}
            onClick={() => setActiveStep(step.id)}
          >
            <span className="hero-demo-tab-number">{String(i + 1).padStart(2, "0")}</span>
            <strong>{step.label}</strong>
            <span>{step.description}</span>
          </button>
        ))}
      </div>

      {/* Step content */}
      <div className="hero-demo-content">
        {activeStep === "seal" && (
          <div className="hero-demo-seal">
            <div className="hero-demo-seal-top">
              <div className="hero-demo-seal-info">
                <strong>This bundle contains:</strong>
                <ul className="hero-demo-evidence-list">
                  {bundle.items.map((item, i) => (
                    <li key={i}>
                      <span className={`status-pill is-${i === 0 ? "accent" : "good"}`}>{item.type}</span>
                    </li>
                  ))}
                  {bundle.artefacts.map((a, i) => (
                    <li key={`a-${i}`}>
                      <span className="status-pill is-muted">{a.name}</span>
                    </li>
                  ))}
                </ul>
                {sealPhase === "idle" && (
                  <button type="button" className="primary-cta" onClick={handleSeal}>
                    Seal this evidence
                  </button>
                )}
                {sealPhase !== "idle" && (
                  <div className="hero-seal-progress">
                    <SealStep label="Hashing items and artefacts" done={sealPhase !== "hashing"} active={sealPhase === "hashing"} />
                    <SealStep label="Building Merkle tree" done={sealPhase === "signing" || sealPhase === "sealed"} active={sealPhase === "tree"} />
                    <SealStep label="Signing root with Ed25519" done={sealPhase === "sealed"} active={sealPhase === "signing"} />
                    {sealPhase === "sealed" && (
                      <div className="hero-seal-done">
                        <span className="status-pill is-good">sealed</span>
                        <span>Bundle root: <code>{shortHash(bundle.root, 20)}</code></span>
                      </div>
                    )}
                  </div>
                )}
              </div>
              <div className="hero-demo-viz-wrap">
                <BundleVisualizer
                  bundle={bundle}
                  merkleTree={merkleTree}
                  compact
                />
              </div>
            </div>
          </div>
        )}

        {activeStep === "tamper" && (
          <TamperPlayground
            bundle={bundle}
            onVerifyChange={handleVerifyChange}
          />
        )}

        {activeStep === "disclose" && (
          <DisclosureComparison bundle={bundle} />
        )}
      </div>
    </div>
  );
}

function SealStep({ label, done, active }) {
  return (
    <div className={`hero-seal-step ${done ? "hero-seal-step-done" : ""} ${active ? "hero-seal-step-active" : ""}`}>
      <span className="hero-seal-step-indicator">
        {done ? "\u2713" : active ? "\u2022" : "\u00B7"}
      </span>
      <span>{label}</span>
    </div>
  );
}
