export const LEARN_HERO = {
  eyebrow: "Proof Layer",
  title: "Keep a clear record of what your AI system did and what controls were around it.",
  summary:
    "Proof Layer helps developers capture AI runs and related review records as sealed evidence they can later inspect, verify, and share during EU AI Act or internal review work.",
  primaryCta: { label: "Try the playground", to: "/playground" },
  secondaryCta: { label: "Explore a sample record", to: "/records" }
};

export const AI_ACT_EXPECTATIONS = [
  {
    title: "Know what your system did",
    body:
      "Teams need to be able to explain what the model saw, what it returned, and which system context applied at that moment."
  },
  {
    title: "Keep evidence of controls and reviews",
    body:
      "For higher-impact workflows, teams often need evidence of human review, operating rules, incident handling, or governance checks."
  },
  {
    title: "Show the right evidence to the right people",
    body:
      "The same evidence trail may later be needed by engineering, compliance, customers, auditors, or regulators, usually with different detail levels."
  }
];

export const WORKFLOW_STEPS = [
  {
    title: "Your app or model call",
    body: "A chatbot, support assistant, hiring workflow, or other AI step runs in your product."
  },
  {
    title: "SDK or CLI capture",
    body:
      "Proof Layer records the run details and any related governance material your workflow needs."
  },
  {
    title: "Sealed record",
    body:
      "That material is turned into a sealed record so later changes become detectable instead of silently changing the story."
  },
  {
    title: "Optional vault retention and export",
    body:
      "The vault can retain records, apply sharing rules, and build export packages when someone later asks for evidence."
  },
  {
    title: "Reviewer access later",
    body:
      "A reviewer can inspect what happened, verify the record, and receive only the package they actually need."
  }
];

export const RECORDED_ITEMS = [
  "Prompts and model outputs",
  "System, model, and actor-role context",
  "Human review or oversight actions",
  "Operating rules and governance records",
  "Incident and authority-reporting material when needed"
];

export const LIMITS = [
  "It does not prove that a model answer was true or fair by itself.",
  "It does not replace legal analysis or internal governance decisions.",
  "It does not automatically satisfy every EU AI Act requirement on its own."
];

export const COMMON_WORKFLOWS = [
  {
    slug: "chatbot-support",
    title: "Customer support chatbot",
    body:
      "Capture the prompt, output, and model context for a standard conversational workflow."
  },
  {
    slug: "support-rules",
    title: "Support assistant with operating rules",
    body:
      "Capture the AI run plus the operating instructions and quality sign-off around that workflow."
  },
  {
    slug: "hiring-review",
    title: "Hiring or review assistant",
    body:
      "Show the AI output together with a human-review path and a higher-impact assessment record."
  },
  {
    slug: "incident-response",
    title: "Incident escalation",
    body:
      "Capture the initial incident record, reporting deadlines, and regulator-facing follow-up material."
  }
];

export const LEGAL_BOUNDARY =
  "Proof Layer helps you create and organize evidence for compliance work. It does not by itself make a system legally compliant, and it is not legal advice.";
