export const DOC_SECTIONS = [
  {
    key: "overview",
    label: "Overview",
    pages: ["what-is-proof-layer", "how-it-works"]
  },
  {
    key: "demo",
    label: "Demo",
    pages: ["guided-demo", "playground"]
  },
  {
    key: "sdks",
    label: "SDKs",
    pages: ["typescript-sdk", "python-sdk"]
  },
  {
    key: "vault",
    label: "Vault",
    pages: ["vault-setup", "backup-and-restore"]
  },
  {
    key: "faq",
    label: "FAQ",
    pages: ["faq"]
  }
];

export const DOC_PAGES = {
  "what-is-proof-layer": {
    title: "What is Proof Layer?",
    section: "Overview",
    audience: ["business", "operator", "engineer"],
    description: "A plain-English overview of what the product does and why teams use it.",
    intro:
      "Proof Layer creates a tamper-evident proof record of an AI run so you can verify it later and share only what is necessary.",
    blocks: [
      {
        heading: "What it does",
        body: [
          "It captures prompts, responses, traces, and related materials for one AI run.",
          "It seals them into a signed proof record.",
          "It lets you verify that record later and export either a full or redacted package."
        ]
      },
      {
        heading: "Who it is for",
        body: [
          "Business owners who need evidence for investors or customers.",
          "Operators and compliance teams who need a reviewable audit trail.",
          "Engineers who need one consistent proof format across workflows."
        ]
      }
    ]
  },
  "how-it-works": {
    title: "How it works",
    section: "Overview",
    audience: ["business", "operator", "engineer"],
    description: "A simple walkthrough of capture, seal, verify, and share.",
    intro:
      "The product flow is designed to answer four questions: what happened, was it sealed, can it be verified, and what can be shared?",
    blocks: [
      {
        heading: "Capture",
        body: ["The site collects the prompt, output, and supporting materials for one AI run."]
      },
      {
        heading: "Seal",
        body: ["The vault turns that run into a signed proof record."]
      },
      {
        heading: "Verify",
        body: [
          "The site checks whether the proof record still matches the signer and, where configured, timestamp and transparency evidence."
        ]
      },
      {
        heading: "Share",
        body: ["The site can export either a full package or a redacted package using a sharing profile."]
      }
    ]
  },
  "guided-demo": {
    title: "Guided demo",
    section: "Demo",
    audience: ["business", "operator"],
    description: "How to use the business-first demo flow.",
    intro:
      "The guided demo is the fastest way to understand what Proof Layer produces and what a reviewer would see later.",
    blocks: [
      {
        heading: "What you choose",
        body: [
          "Pick a scenario, provider, model, and prompt.",
          "Choose synthetic mode for an offline-safe walkthrough or live mode for a real provider-backed run."
        ]
      },
      {
        heading: "What happens next",
        body: [
          "The site runs the scenario, creates a proof record, checks what can be proven, and shows what can be shared."
        ]
      }
    ]
  },
  "playground": {
    title: "Advanced playground",
    section: "Demo",
    audience: ["engineer", "operator"],
    description: "Full controls for teams who want to inspect and tune the workflow in detail.",
    intro:
      "The advanced playground exposes the full configuration surface for teams who want more control than the guided flow provides.",
    blocks: [
      {
        heading: "What it includes",
        body: [
          "Vault URL and auth controls.",
          "Capture mode, provider, prompt, and configuration details.",
          "Disclosure profile, bundle format, and related export settings."
        ]
      }
    ]
  },
  "typescript-sdk": {
    title: "TypeScript SDK",
    section: "SDKs",
    audience: ["engineer"],
    description: "Where the TypeScript SDK fits and what it offers.",
    intro:
      "The TypeScript SDK is the JavaScript and TypeScript entrypoint for local sealing, provider wrappers, and service-connected proof workflows.",
    blocks: [
      {
        heading: "Use it for",
        body: [
          "Local proof record creation.",
          "Vault-backed capture and export.",
          "Provider and observability integrations."
        ]
      }
    ]
  },
  "python-sdk": {
    title: "Python SDK",
    section: "SDKs",
    audience: ["engineer"],
    description: "Where the Python SDK fits and what it offers.",
    intro:
      "The Python SDK provides local and service-connected proof workflows for Python applications.",
    blocks: [
      {
        heading: "Use it for",
        body: [
          "Local proof record creation.",
          "Vault-backed capture and export.",
          "Decorator and provider integrations."
        ]
      }
    ]
  },
  "vault-setup": {
    title: "Vault setup",
    section: "Vault",
    audience: ["operator", "engineer"],
    description: "What the vault is responsible for and how to think about local setup.",
    intro:
      "The vault is the service that seals proof records, stores materials, and handles verification, disclosure, and exports.",
    blocks: [
      {
        heading: "What to configure",
        body: [
          "Signing key, service URL, optional auth, and optional assurance providers.",
          "Storage, retention, and backup behavior depending on your environment."
        ]
      }
    ]
  },
  "backup-and-restore": {
    title: "Backup and restore",
    section: "Vault",
    audience: ["operator"],
    description: "How to think about preserving and recovering vault state.",
    intro:
      "The vault supports local backup export, scheduled backups, restore/import workflows, and optional backup encryption.",
    blocks: [
      {
        heading: "Operational view",
        body: [
          "Use backups to preserve the metadata store, captured materials, and export outputs.",
          "Use restore/import to stage a vault state offline before reintroducing it into an environment."
        ]
      }
    ]
  },
  faq: {
    title: "FAQ",
    section: "FAQ",
    audience: ["business", "operator", "engineer"],
    description: "Short answers to common questions.",
    intro: "These are the questions most people ask when they first see the product.",
    blocks: [
      {
        heading: "Does this prove model truth?",
        body: ["No. It proves what was captured and sealed for one run, not whether the model output was correct."]
      },
      {
        heading: "Can I share only part of a run?",
        body: ["Yes. The product supports selective disclosure and controlled share packages."]
      },
      {
        heading: "Do I need live provider keys to try it?",
        body: ["No. The guided demo can run in synthetic mode and still use the real vault workflow."]
      }
    ]
  }
};

const DOC_ORDER = [
  "what-is-proof-layer",
  "how-it-works",
  "guided-demo",
  "playground",
  "typescript-sdk",
  "python-sdk",
  "vault-setup",
  "backup-and-restore",
  "faq"
];

export function getDocPage(slug) {
  return DOC_PAGES[slug] ?? DOC_PAGES["what-is-proof-layer"];
}

export function getDocNeighbors(slug) {
  const index = DOC_ORDER.indexOf(slug);
  return {
    previous: index > 0 ? DOC_ORDER[index - 1] : null,
    next: index >= 0 && index < DOC_ORDER.length - 1 ? DOC_ORDER[index + 1] : null
  };
}
