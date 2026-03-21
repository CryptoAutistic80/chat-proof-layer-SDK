use crate::{
    completeness::{
        CompletenessProfile, CompletenessRuleResult, CompletenessStatus, report_for_rules,
    },
    schema::{EvidenceBundle, EvidenceItem},
};
use std::collections::BTreeSet;

struct RuleDefinition {
    rule_id: &'static str,
    item_type: &'static str,
    obligation_ref: &'static str,
    check: fn(&EvidenceItem) -> Option<Vec<String>>,
}

const RULES: &[RuleDefinition] = &[
    RuleDefinition {
        rule_id: "gpai_provider_technical_doc_context_minimum",
        item_type: "technical_doc",
        obligation_ref: "art53_annex_xi",
        check: check_technical_doc,
    },
    RuleDefinition {
        rule_id: "gpai_provider_model_evaluation_minimum",
        item_type: "model_evaluation",
        obligation_ref: "art53_annex_xi",
        check: check_model_evaluation,
    },
    RuleDefinition {
        rule_id: "gpai_provider_training_provenance_minimum",
        item_type: "training_provenance",
        obligation_ref: "art53_annex_xi",
        check: check_training_provenance,
    },
    RuleDefinition {
        rule_id: "gpai_provider_compute_threshold_minimum",
        item_type: "compute_metrics",
        obligation_ref: "art51_compute_threshold",
        check: check_compute_metrics,
    },
    RuleDefinition {
        rule_id: "gpai_provider_copyright_policy_minimum",
        item_type: "copyright_policy",
        obligation_ref: "art53_copyright",
        check: check_copyright_policy,
    },
    RuleDefinition {
        rule_id: "gpai_provider_training_summary_minimum",
        item_type: "training_summary",
        obligation_ref: "art53_training_summary",
        check: check_training_summary,
    },
];

pub(super) fn evaluate(bundle: &EvidenceBundle) -> crate::completeness::CompletenessReport {
    let rules = RULES
        .iter()
        .map(|rule| evaluate_rule(bundle, rule))
        .collect::<Vec<_>>();
    report_for_rules(bundle, CompletenessProfile::GpaiProviderV1, rules)
}

fn evaluate_rule(bundle: &EvidenceBundle, rule: &RuleDefinition) -> CompletenessRuleResult {
    let mut evaluated_item_indices = Vec::new();
    let mut complete_count = 0usize;
    let mut missing_fields = BTreeSet::new();

    for (index, item) in bundle.items.iter().enumerate() {
        let Some(item_missing_fields) = (rule.check)(item) else {
            continue;
        };
        evaluated_item_indices.push(index);
        if item_missing_fields.is_empty() {
            complete_count += 1;
        } else {
            missing_fields.extend(item_missing_fields);
        }
    }

    let present_count = evaluated_item_indices.len();
    let status = if present_count == 0 || complete_count == 0 {
        CompletenessStatus::Fail
    } else if complete_count < present_count {
        CompletenessStatus::Warn
    } else {
        CompletenessStatus::Pass
    };

    let summary = match status {
        CompletenessStatus::Pass => {
            format!(
                "{} is minimally structured for GPAI provider review.",
                rule.item_type.replace('_', " ")
            )
        }
        CompletenessStatus::Warn => format!(
            "{} has at least one complete item, but some evaluated items are missing structured fields.",
            rule.item_type.replace('_', " ")
        ),
        CompletenessStatus::Fail if present_count == 0 => format!(
            "{} is missing from the bundle.",
            rule.item_type.replace('_', " ")
        ),
        CompletenessStatus::Fail => format!(
            "{} is present but does not include a minimally complete item.",
            rule.item_type.replace('_', " ")
        ),
    };

    CompletenessRuleResult {
        rule_id: rule.rule_id.to_string(),
        item_type: rule.item_type.to_string(),
        obligation_ref: rule.obligation_ref.to_string(),
        status,
        present_count,
        complete_count,
        evaluated_item_indices,
        missing_fields: missing_fields.into_iter().collect(),
        summary,
    }
}

fn check_technical_doc(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::TechnicalDoc(evidence) = item else {
        return None;
    };
    let mut missing_fields = required_fields([
        ("document_ref", !evidence.document_ref.trim().is_empty()),
        (
            "capabilities_and_limitations",
            has_optional_text(evidence.capabilities_and_limitations.as_deref()),
        ),
        (
            "evaluation_metrics_summary",
            has_optional_text(evidence.evaluation_metrics_summary.as_deref()),
        ),
    ]);

    if !has_optional_text(evidence.model_description_summary.as_deref())
        && !has_optional_text(evidence.system_description_summary.as_deref())
    {
        missing_fields.push("model_description_summary|system_description_summary".to_string());
    }

    Some(missing_fields)
}

fn check_model_evaluation(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::ModelEvaluation(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("evaluation_id", !evidence.evaluation_id.trim().is_empty()),
        ("benchmark", !evidence.benchmark.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        ("summary", has_optional_text(evidence.summary.as_deref())),
        ("metrics_summary", !evidence.metrics_summary.is_empty()),
        (
            "evaluation_methodology",
            has_optional_text(evidence.evaluation_methodology.as_deref()),
        ),
    ]))
}

fn check_training_provenance(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::TrainingProvenance(evidence) = item else {
        return None;
    };
    let mut missing_fields = required_fields([
        ("dataset_ref", !evidence.dataset_ref.trim().is_empty()),
        ("stage", !evidence.stage.trim().is_empty()),
        (
            "training_dataset_summary",
            has_optional_text(evidence.training_dataset_summary.as_deref()),
        ),
        (
            "compute_metrics_ref",
            has_optional_text(evidence.compute_metrics_ref.as_deref()),
        ),
    ]);

    if !has_optional_text(evidence.lineage_ref.as_deref())
        && !has_optional_text(evidence.record_commitment.as_deref())
    {
        missing_fields.push("lineage_ref|record_commitment".to_string());
    }

    Some(missing_fields)
}

fn check_compute_metrics(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::ComputeMetrics(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("compute_id", !evidence.compute_id.trim().is_empty()),
        (
            "training_flops_estimate",
            !evidence.training_flops_estimate.trim().is_empty(),
        ),
        (
            "threshold_basis_ref",
            !evidence.threshold_basis_ref.trim().is_empty(),
        ),
        (
            "threshold_value",
            !evidence.threshold_value.trim().is_empty(),
        ),
        (
            "threshold_status",
            !evidence.threshold_status.trim().is_empty(),
        ),
        (
            "estimation_methodology",
            has_optional_text(evidence.estimation_methodology.as_deref()),
        ),
        (
            "measured_at",
            has_optional_text(evidence.measured_at.as_deref()),
        ),
        (
            "compute_resources_summary",
            !evidence.compute_resources_summary.is_empty(),
        ),
    ]))
}

fn check_copyright_policy(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::CopyrightPolicy(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("policy_ref", !evidence.policy_ref.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        (
            "jurisdiction",
            has_optional_text(evidence.jurisdiction.as_deref()),
        ),
        (
            "commitment",
            has_optional_text(evidence.commitment.as_deref()),
        ),
    ]))
}

fn check_training_summary(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::TrainingSummary(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("summary_ref", !evidence.summary_ref.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        ("audience", has_optional_text(evidence.audience.as_deref())),
        (
            "commitment",
            has_optional_text(evidence.commitment.as_deref()),
        ),
    ]))
}

fn required_fields<const N: usize>(pairs: [(&str, bool); N]) -> Vec<String> {
    pairs
        .into_iter()
        .filter_map(|(field, present)| (!present).then_some(field.to_string()))
        .collect()
}

fn has_optional_text(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}
