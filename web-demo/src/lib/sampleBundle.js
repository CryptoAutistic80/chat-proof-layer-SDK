/**
 * Pre-baked sample bundle for offline demos.
 * All hashes and the Merkle root are pre-computed and internally consistent.
 * This bundle represents a realistic support-assistant interaction with governance.
 */
import { sha256Hex, canonicalize, computeMerkleRoot } from "./clientCrypto";

export const SAMPLE_PROMPT = {
  role: "user",
  content: "Our enterprise subscription renews next month. Can you summarize the key changes in the latest terms of service update?",
  system_prompt: "You are a support assistant for Acme Corp. Answer clearly and concisely. If unsure, say so.",
  model: "gpt-4o-mini",
  provider: "openai",
  temperature: 0.2,
  max_tokens: 256
};

export const SAMPLE_RESPONSE = {
  output: "The latest terms of service update (effective March 1, 2026) includes three key changes:\n\n1. Data retention: Customer data is now retained for 90 days after contract end (previously 30 days).\n2. SLA adjustment: Uptime commitment increased from 99.5% to 99.9% for enterprise tiers.\n3. AI usage disclosure: A new section requires disclosure when AI-generated content is used in customer-facing communications.\n\nI recommend reviewing Section 4.2 and the updated AI Addendum with your legal team before renewal.",
  model: "gpt-4o-mini",
  provider: "openai",
  response_source: "synthetic",
  finish_reason: "stop",
  usage: { prompt_tokens: 42, completion_tokens: 118 }
};

export const SAMPLE_ITEMS = [
  {
    type: "llm_interaction",
    data: {
      system_id: "acme-support-assistant",
      actor_role: "deployer",
      prompt: SAMPLE_PROMPT.content,
      system_prompt: SAMPLE_PROMPT.system_prompt,
      output: SAMPLE_RESPONSE.output,
      model: "gpt-4o-mini",
      provider: "openai",
      timestamp: "2026-03-21T10:15:00Z"
    },
    hash: null
  },
  {
    type: "data_governance",
    data: {
      system_id: "acme-support-assistant",
      dataset_name: "acme-kb-v3",
      dataset_version: "3.1.0",
      source_description: "Internal knowledge base articles, FAQ entries, and product documentation",
      bias_methodology: "Quarterly review of response accuracy across customer segments",
      safeguards: "PII filtering applied before retrieval; prompt injection detection enabled"
    },
    hash: null
  },
  {
    type: "instructions_for_use",
    data: {
      system_id: "acme-support-assistant",
      summary: "Support assistant for enterprise subscription queries",
      section: "Operator guidance",
      human_oversight_guidance: "Flag responses about contract terms for human review before sending to customer",
      intended_use: "Answering factual questions about Acme Corp products and subscription terms"
    },
    hash: null
  },
  {
    type: "qms_record",
    data: {
      system_id: "acme-support-assistant",
      status: "approved",
      approver: "j.chen@acme.example",
      scope: "Production deployment v2.4",
      policy_ref: "QMS-AI-2026-003"
    },
    hash: null
  }
];

export const SAMPLE_ARTEFACTS = [
  {
    name: "prompt.json",
    content_type: "application/json",
    content: SAMPLE_PROMPT,
    sha256: null
  },
  {
    name: "response.json",
    content_type: "application/json",
    content: SAMPLE_RESPONSE,
    sha256: null
  }
];

/**
 * Disclosure profiles showing what different audiences would see.
 */
export const DISCLOSURE_PROFILES = {
  auditor: {
    label: "Auditor",
    description: "Full access to all evidence, artefacts, and proof metadata.",
    visibleItems: [0, 1, 2, 3],
    visibleArtefacts: [0, 1],
    redactedFields: []
  },
  customer: {
    label: "Customer",
    description: "Sees the interaction record and instructions for use. Internal governance details are redacted.",
    visibleItems: [0, 2],
    visibleArtefacts: [1],
    redactedFields: ["system_prompt", "bias_methodology", "safeguards", "policy_ref", "approver"]
  },
  public: {
    label: "Public summary",
    description: "Minimal disclosure: system ID, evidence types present, and proof validity. No content disclosed.",
    visibleItems: [],
    visibleArtefacts: [],
    redactedFields: ["prompt", "output", "system_prompt", "dataset_name", "source_description"]
  }
};

/**
 * Build a complete, internally-consistent sample bundle.
 * Computes real SHA-256 hashes and a real Merkle root using the client crypto.
 */
export async function buildSampleBundle() {

  const items = SAMPLE_ITEMS.map((item) => ({
    ...item,
    hash: null
  }));
  for (const item of items) {
    item.hash = await sha256Hex(canonicalize(item.data));
  }

  const artefacts = SAMPLE_ARTEFACTS.map((a) => ({
    ...a,
    sha256: null
  }));
  for (const artefact of artefacts) {
    artefact.sha256 = await sha256Hex(canonicalize(artefact.content));
  }

  const leafHashes = [
    ...items.map((i) => i.hash),
    ...artefacts.map((a) => a.sha256)
  ];
  const root = await computeMerkleRoot(leafHashes);

  const signature = "ed25519:" + await sha256Hex("proof-layer-demo-signature-" + root);

  return {
    bundle_id: "pl_demo_" + root.slice(0, 16),
    bundle_version: "1.0",
    created_at: "2026-03-21T10:15:03Z",
    subject: {
      system_id: "acme-support-assistant",
      actor_role: "deployer"
    },
    items,
    artefacts,
    root,
    signature,
    signing_algorithm: "Ed25519",
    signing_key_id: "kid-demo-01",
    timestamp: {
      tsa: "http://timestamp.example.com",
      policy: "rfc3161",
      sealed_at: "2026-03-21T10:15:04Z"
    },
    receipt: null
  };
}
