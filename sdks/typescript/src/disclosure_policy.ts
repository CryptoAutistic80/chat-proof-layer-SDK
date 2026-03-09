import type {
  DisclosurePolicyBuilderOptions,
  DisclosurePolicyConfig,
  DisclosurePolicyTemplateName,
  DisclosurePolicyTemplateOptions,
  DisclosureRedactionGroup
} from "./types.js";

interface DisclosurePolicyTemplateBase {
  policy: {
    allowed_item_types: string[];
    excluded_item_types: string[];
    allowed_obligation_refs: string[];
    excluded_obligation_refs: string[];
    include_artefact_metadata: boolean;
    include_artefact_bytes: boolean;
    artefact_names: string[];
  };
  defaultGroups: DisclosureRedactionGroup[];
}

const ALL_ITEM_TYPES = [
  "llm_interaction",
  "tool_call",
  "retrieval",
  "human_oversight",
  "policy_decision",
  "risk_assessment",
  "data_governance",
  "technical_doc",
  "model_evaluation",
  "adversarial_test",
  "training_provenance",
  "conformity_assessment",
  "declaration",
  "registration",
  "literacy_attestation",
  "incident_report"
] as const;

export const disclosurePolicyTemplateNames: DisclosurePolicyTemplateName[] = [
  "regulator_minimum",
  "annex_iv_redacted",
  "incident_summary",
  "runtime_minimum",
  "privacy_review"
];

export const disclosureRedactionGroups: DisclosureRedactionGroup[] = [
  "commitments",
  "metadata",
  "parameters",
  "operational_metrics"
];

const GROUP_SELECTORS: Record<DisclosureRedactionGroup, Partial<Record<(typeof ALL_ITEM_TYPES)[number], string[]>>> =
  {
    commitments: {
      llm_interaction: [
        "input_commitment",
        "retrieval_commitment",
        "output_commitment",
        "tool_outputs_commitment",
        "trace_commitment"
      ],
      tool_call: ["input_commitment", "output_commitment"],
      retrieval: ["result_commitment", "query_commitment"],
      human_oversight: ["notes_commitment"],
      policy_decision: ["rationale_commitment"],
      technical_doc: ["commitment"],
      model_evaluation: ["report_commitment"],
      adversarial_test: ["report_commitment"],
      training_provenance: ["record_commitment"],
      conformity_assessment: ["report_commitment"],
      declaration: ["document_commitment"],
      registration: ["receipt_commitment"],
      literacy_attestation: ["attestation_commitment"],
      incident_report: ["report_commitment"]
    },
    metadata: {
      tool_call: ["/metadata"],
      retrieval: ["/metadata"],
      policy_decision: ["/metadata"],
      risk_assessment: ["/metadata"],
      data_governance: ["/metadata"],
      model_evaluation: ["/metadata"],
      adversarial_test: ["/metadata"],
      training_provenance: ["/metadata"],
      conformity_assessment: ["/metadata"],
      declaration: ["/metadata"],
      literacy_attestation: ["/metadata"],
      incident_report: ["/metadata"]
    },
    parameters: {
      llm_interaction: ["/parameters"]
    },
    operational_metrics: {
      llm_interaction: ["/token_usage", "/latency_ms", "/trace_semconv_version"]
    }
  };

const TEMPLATE_BASES: Record<DisclosurePolicyTemplateName, DisclosurePolicyTemplateBase> = {
  regulator_minimum: {
    policy: {
      allowed_item_types: [],
      excluded_item_types: [],
      allowed_obligation_refs: [],
      excluded_obligation_refs: [],
      include_artefact_metadata: false,
      include_artefact_bytes: false,
      artefact_names: []
    },
    defaultGroups: []
  },
  annex_iv_redacted: {
    policy: {
      allowed_item_types: ["technical_doc", "risk_assessment", "data_governance", "human_oversight"],
      excluded_item_types: [],
      allowed_obligation_refs: [],
      excluded_obligation_refs: [],
      include_artefact_metadata: true,
      include_artefact_bytes: true,
      artefact_names: []
    },
    defaultGroups: []
  },
  incident_summary: {
    policy: {
      allowed_item_types: ["incident_report", "risk_assessment", "policy_decision", "human_oversight"],
      excluded_item_types: ["llm_interaction", "retrieval", "tool_call"],
      allowed_obligation_refs: [],
      excluded_obligation_refs: [],
      include_artefact_metadata: false,
      include_artefact_bytes: false,
      artefact_names: []
    },
    defaultGroups: []
  },
  runtime_minimum: {
    policy: {
      allowed_item_types: [
        "llm_interaction",
        "tool_call",
        "retrieval",
        "policy_decision",
        "human_oversight"
      ],
      excluded_item_types: [],
      allowed_obligation_refs: [],
      excluded_obligation_refs: [],
      include_artefact_metadata: false,
      include_artefact_bytes: false,
      artefact_names: []
    },
    defaultGroups: ["commitments", "parameters", "operational_metrics"]
  },
  privacy_review: {
    policy: {
      allowed_item_types: [
        "llm_interaction",
        "risk_assessment",
        "incident_report",
        "policy_decision",
        "human_oversight"
      ],
      excluded_item_types: [],
      allowed_obligation_refs: [],
      excluded_obligation_refs: [],
      include_artefact_metadata: false,
      include_artefact_bytes: false,
      artefact_names: []
    },
    defaultGroups: ["commitments", "metadata", "parameters", "operational_metrics"]
  }
};

function uniqueStrings(values: string[] | undefined): string[] {
  return Array.from(new Set((values ?? []).filter((value) => value.trim().length > 0)));
}

function selectedItemTypes(policy: DisclosurePolicyConfig): string[] {
  return policy.allowed_item_types && policy.allowed_item_types.length > 0
    ? [...policy.allowed_item_types]
    : [...ALL_ITEM_TYPES];
}

function mergeRedactedSelectors(
  base: Record<string, string[]> | undefined,
  next: Record<string, string[]> | undefined
): Record<string, string[]> {
  const merged = new Map<string, Set<string>>();
  for (const [itemType, selectors] of Object.entries(base ?? {})) {
    merged.set(itemType, new Set(selectors));
  }
  for (const [itemType, selectors] of Object.entries(next ?? {})) {
    const bucket = merged.get(itemType) ?? new Set<string>();
    for (const selector of selectors) {
      if (selector.trim().length > 0) {
        bucket.add(selector);
      }
    }
    if (bucket.size > 0) {
      merged.set(itemType, bucket);
    }
  }
  return Object.fromEntries(
    Array.from(merged.entries()).map(([itemType, selectors]) => [itemType, Array.from(selectors)])
  );
}

function selectorsForGroups(
  itemTypes: string[],
  groups: DisclosureRedactionGroup[]
): Record<string, string[]> {
  const byItemType: Record<string, string[]> = {};
  for (const itemType of itemTypes) {
    for (const group of groups) {
      const selectors = GROUP_SELECTORS[group][itemType as (typeof ALL_ITEM_TYPES)[number]] ?? [];
      if (selectors.length === 0) {
        continue;
      }
      byItemType[itemType] = [...new Set([...(byItemType[itemType] ?? []), ...selectors])];
    }
  }
  return byItemType;
}

export function createDisclosurePolicy(
  options: DisclosurePolicyBuilderOptions
): DisclosurePolicyConfig {
  const policy: DisclosurePolicyConfig = {
    name: options.name,
    allowed_item_types: uniqueStrings(options.allowedItemTypes),
    excluded_item_types: uniqueStrings(options.excludedItemTypes),
    allowed_obligation_refs: uniqueStrings(options.allowedObligationRefs),
    excluded_obligation_refs: uniqueStrings(options.excludedObligationRefs),
    include_artefact_metadata: options.includeArtefactMetadata ?? false,
    include_artefact_bytes: options.includeArtefactBytes ?? false,
    artefact_names: uniqueStrings(options.artefactNames),
    redacted_fields_by_item_type: {}
  };

  const groupSelectors = selectorsForGroups(
    selectedItemTypes(policy),
    options.redactionGroups ?? []
  );
  policy.redacted_fields_by_item_type = mergeRedactedSelectors(
    groupSelectors,
    options.redactedFieldsByItemType
  );
  return policy;
}

export function createDisclosurePolicyTemplate(
  template: DisclosurePolicyTemplateName,
  options: DisclosurePolicyTemplateOptions = {}
): DisclosurePolicyConfig {
  const base = TEMPLATE_BASES[template];
  return createDisclosurePolicy({
    name: options.name ?? template,
    allowedItemTypes: base.policy.allowed_item_types,
    excludedItemTypes: base.policy.excluded_item_types,
    allowedObligationRefs: base.policy.allowed_obligation_refs,
    excludedObligationRefs: base.policy.excluded_obligation_refs,
    includeArtefactMetadata: base.policy.include_artefact_metadata,
    includeArtefactBytes: base.policy.include_artefact_bytes,
    artefactNames: base.policy.artefact_names,
    redactionGroups: [...base.defaultGroups, ...(options.redactionGroups ?? [])],
    redactedFieldsByItemType: options.redactedFieldsByItemType
  });
}
