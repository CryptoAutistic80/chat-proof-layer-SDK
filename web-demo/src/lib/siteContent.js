export const HOME_HERO = {
  eyebrow: "Proof Layer",
  title: "Prove what your AI system did, without relying on ordinary logs.",
  summary:
    "Proof Layer turns one AI run into a tamper-evident proof record you can verify later and selectively share with customers, regulators, partners, or investors.",
  primaryCta: { label: "Try guided demo", to: "/guided" },
  secondaryCta: { label: "Read how it works", to: "/docs/how-it-works" }
};

export const FEATURE_STEPS = [
  {
    title: "Capture",
    body: "Collect the prompt, response, and supporting materials that explain what happened during one AI run."
  },
  {
    title: "Seal",
    body: "Turn that run into a proof record signed by the vault so later changes become detectable."
  },
  {
    title: "Verify",
    body: "Check whether the proof record still matches the signer, timestamp, and transparency evidence."
  },
  {
    title: "Share",
    body: "Export either a full package or a controlled disclosure package depending on what the reviewer needs."
  }
];

export const WHY_POINTS = [
  "Ordinary logs are easy to change and difficult to share safely.",
  "AI teams need evidence that works for operators, compliance, and external reviewers at the same time.",
  "Proof Layer gives you a portable proof record, not just a screenshot or a JSON dump."
];

export const TRUST_STATEMENTS = [
  "Not generic logging",
  "Not screenshots",
  "Not ad hoc JSON",
  "Verifiable records"
];

export const USE_CASES = [
  {
    slug: "investor-diligence",
    title: "Investor diligence",
    problem: "You need to show that your AI product has real operational and governance controls, not just claims.",
    capture: "A real or synthetic AI interaction, its supporting materials, and a signed proof record.",
    prove: "You can later show that the record was sealed and has not been tampered with.",
    share: "You can export a minimal package without exposing all internal detail.",
    ctaLabel: "Run investor summary",
    ctaTo: "/guided"
  },
  {
    slug: "customer-dispute",
    title: "Customer dispute review",
    problem: "A customer questions what your AI system produced or how it behaved in a specific case.",
    capture: "The exact prompt, output, trace, and supporting materials for a run.",
    prove: "You can verify whether that record still matches the original signer and evidence.",
    share: "You can disclose only the relevant portion of the run.",
    ctaLabel: "Review what can be shared",
    ctaTo: "/what-you-can-share"
  },
  {
    slug: "incident-review",
    title: "Internal incident review",
    problem: "Your team needs evidence for an anomaly, policy issue, or unexpected model behavior.",
    capture: "The interaction plus a derived incident wrapper and related materials.",
    prove: "You can show the evidence trail used for review and downstream sharing.",
    share: "You can prepare a focused incident package instead of a full raw export.",
    ctaLabel: "Run incident review",
    ctaTo: "/guided"
  },
  {
    slug: "regulatory-evidence",
    title: "Regulatory evidence",
    problem: "You need structured documentation and evidence for regulator or conformity review.",
    capture: "Technical summary materials and supporting artefacts tied to one proof record.",
    prove: "You can show that the record and materials were sealed together.",
    share: "You can export documentation-oriented packages for review.",
    ctaLabel: "Explore Annex IV filing",
    ctaTo: "/guided"
  }
];

export const PRODUCT_SECTIONS = [
  {
    title: "What it is",
    body:
      "Proof Layer creates tamper-evident records of AI activity so a business can later verify and share evidence with confidence."
  },
  {
    title: "Why it matters",
    body:
      "When a customer, regulator, partner, or investor asks what your AI system did, ordinary logs are usually not enough."
  },
  {
    title: "What you get",
    body:
      "One proof record, integrity checks, selective sharing controls, and export packages built on the same evidence trail."
  }
];
