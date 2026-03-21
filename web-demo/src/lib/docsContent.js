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
      "Proof Layer is an SDK-first capture and verification system for tamper-evident AI compliance records, with an optional vault for retention and export workflows.",
    blocks: [
      {
        heading: "What it does",
        body: [
          "SDKs and the CLI capture prompts, responses, traces, and governance artefacts for one AI run or decision point.",
          "They seal that material into a signed proof record that can be verified locally.",
          "The optional vault adds retention, disclosure policy handling, and export packs for workflows such as provider governance, Annex XI or GPAI threshold tracking, post-market monitoring, incident response, and deployer-side FRIA reviews."
        ]
      },
      {
        heading: "Who it is for",
        body: [
          "Engineers who need one consistent proof format across local and service-backed workflows.",
          "Operators and compliance teams who need a reviewable evidence trail and export path.",
          "Teams building AI products who want capture, verification, and controlled disclosure without treating the demo UI as the product."
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
      "The product flow is designed to answer four questions: what happened, what system context applied, was it sealed, and what can be shared?",
    blocks: [
      {
        heading: "Capture",
        body: [
          "The SDK or CLI captures the prompt, output, supporting materials, and optional compliance profile for one run or governance event."
        ]
      },
      {
        heading: "Seal",
        body: ["The local SDK path or the optional vault turns that event into a signed proof record."]
      },
      {
        heading: "Verify",
        body: [
          "Teams can verify whether the proof record still matches the signer and, where configured, timestamp and transparency evidence."
        ]
      },
      {
        heading: "Share",
        body: [
          "The vault can export either a full package or a redacted package, including curated packs such as provider governance, Annex XI, post-market monitoring, incident response, or deployer-side fundamental rights evidence."
        ]
      }
    ]
  },
  "guided-demo": {
    title: "Guided demo",
    section: "Demo",
    audience: ["business", "operator"],
    description: "How to use the guided demo flow.",
    intro:
      "The guided demo is the fastest way to understand the workflow, but it is a walkthrough surface rather than the primary product interface.",
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
          "The site mirrors the underlying SDK and vault flow: it runs the scenario, creates a proof record, checks what can be proven, and shows what can be shared."
        ]
      }
    ]
  },
  "playground": {
    title: "SDK playground",
    section: "Demo",
    audience: ["engineer", "operator"],
    description: "Prefab TypeScript, Python, and CLI examples that run through the real demo workflow.",
    intro:
      "The SDK playground is the main engineer-facing demo surface: pick a prefab TypeScript, Python, or CLI example, change a few inputs, run the real vault-backed flow, then inspect the resulting evidence without leaving the page.",
    blocks: [
      {
        heading: "What it includes",
        body: [
          "Language lanes for TypeScript, Python, and the Rust-native CLI path.",
          "Read-only prefab scripts backed by constrained parameter forms rather than free-form code execution.",
          "Inline result, compliance-review, and drill-down links to the deeper walkthrough pages."
        ]
      },
      {
        heading: "Where advanced controls live",
        body: [
          "The raw workflow console still exists at `/playground/advanced` for teams who want the full disclosure and export control surface."
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
          "Compliance-profile-aware capture that can reuse actor role, intended use, and FRIA or GPAI context across items.",
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
          "Compliance-profile-aware capture that can reuse actor role, intended use, and FRIA or GPAI context across items.",
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
      "The vault is the optional service layer for teams that need shared retention, disclosure, and export workflows on top of the SDK and CLI path.",
    blocks: [
      {
        heading: "What to configure",
        body: [
          "Signing key, service URL, optional auth, and optional assurance providers.",
          "Storage, retention, and backup behavior depending on your environment.",
          "Pack/export workflows such as provider governance, runtime logs, Annex XI, post-market monitoring, incident response, and deployer-side fundamental rights evidence."
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
