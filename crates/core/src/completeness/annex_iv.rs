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
        rule_id: "annex_iv_risk_assessment_minimum",
        item_type: "risk_assessment",
        obligation_ref: "art9",
        check: check_risk_assessment,
    },
    RuleDefinition {
        rule_id: "annex_iv_data_governance_minimum",
        item_type: "data_governance",
        obligation_ref: "art10",
        check: check_data_governance,
    },
    RuleDefinition {
        rule_id: "annex_iv_technical_doc_minimum",
        item_type: "technical_doc",
        obligation_ref: "art11_annex_iv",
        check: check_technical_doc,
    },
    RuleDefinition {
        rule_id: "annex_iv_instructions_for_use_minimum",
        item_type: "instructions_for_use",
        obligation_ref: "art13",
        check: check_instructions_for_use,
    },
    RuleDefinition {
        rule_id: "annex_iv_human_oversight_minimum",
        item_type: "human_oversight",
        obligation_ref: "art14",
        check: check_human_oversight,
    },
    RuleDefinition {
        rule_id: "annex_iv_qms_record_minimum",
        item_type: "qms_record",
        obligation_ref: "art17",
        check: check_qms_record,
    },
    RuleDefinition {
        rule_id: "annex_iv_standards_alignment_minimum",
        item_type: "standards_alignment",
        obligation_ref: "art40_43",
        check: check_standards_alignment,
    },
    RuleDefinition {
        rule_id: "annex_iv_post_market_monitoring_minimum",
        item_type: "post_market_monitoring",
        obligation_ref: "art72",
        check: check_post_market_monitoring,
    },
];

pub(super) fn evaluate(bundle: &EvidenceBundle) -> crate::completeness::CompletenessReport {
    let rules = RULES
        .iter()
        .map(|rule| evaluate_rule(bundle, rule))
        .collect::<Vec<_>>();
    report_for_rules(bundle, CompletenessProfile::AnnexIvGovernanceV1, rules)
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
                "{} is minimally structured for Annex IV review.",
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

fn check_risk_assessment(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::RiskAssessment(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("risk_id", !evidence.risk_id.trim().is_empty()),
        ("severity", !evidence.severity.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        (
            "risk_description",
            has_optional_text(evidence.risk_description.as_deref()),
        ),
        (
            "likelihood",
            has_optional_text(evidence.likelihood.as_deref()),
        ),
        ("affected_groups", !evidence.affected_groups.is_empty()),
        (
            "mitigation_measures",
            !evidence.mitigation_measures.is_empty(),
        ),
        (
            "residual_risk_level",
            has_optional_text(evidence.residual_risk_level.as_deref()),
        ),
        (
            "risk_owner",
            has_optional_text(evidence.risk_owner.as_deref()),
        ),
        (
            "test_results_summary",
            has_optional_text(evidence.test_results_summary.as_deref()),
        ),
    ]))
}

fn check_data_governance(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::DataGovernance(evidence) = item else {
        return None;
    };
    let mut missing_fields = required_fields([
        ("decision", !evidence.decision.trim().is_empty()),
        (
            "source_description",
            has_optional_text(evidence.source_description.as_deref()),
        ),
        ("collection_period", evidence.collection_period.is_some()),
        (
            "preprocessing_operations",
            !evidence.preprocessing_operations.is_empty(),
        ),
        (
            "bias_detection_methodology",
            has_optional_text(evidence.bias_detection_methodology.as_deref()),
        ),
        ("bias_metrics", !evidence.bias_metrics.is_empty()),
        (
            "mitigation_actions",
            !evidence.mitigation_actions.is_empty(),
        ),
        ("data_gaps", !evidence.data_gaps.is_empty()),
        (
            "personal_data_categories",
            !evidence.personal_data_categories.is_empty(),
        ),
        ("safeguards", !evidence.safeguards.is_empty()),
    ]);

    if !has_optional_text(evidence.dataset_ref.as_deref())
        && !has_optional_text(evidence.dataset_name.as_deref())
    {
        missing_fields.push("dataset_ref|dataset_name".to_string());
    }

    Some(missing_fields)
}

fn check_technical_doc(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::TechnicalDoc(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("document_ref", !evidence.document_ref.trim().is_empty()),
        ("annex_iv_sections", !evidence.annex_iv_sections.is_empty()),
        (
            "system_description_summary",
            has_optional_text(evidence.system_description_summary.as_deref()),
        ),
        (
            "model_description_summary",
            has_optional_text(evidence.model_description_summary.as_deref()),
        ),
        (
            "capabilities_and_limitations",
            has_optional_text(evidence.capabilities_and_limitations.as_deref()),
        ),
        (
            "design_choices_summary",
            has_optional_text(evidence.design_choices_summary.as_deref()),
        ),
        (
            "evaluation_metrics_summary",
            has_optional_text(evidence.evaluation_metrics_summary.as_deref()),
        ),
        (
            "human_oversight_design_summary",
            has_optional_text(evidence.human_oversight_design_summary.as_deref()),
        ),
        (
            "post_market_monitoring_plan_ref",
            has_optional_text(evidence.post_market_monitoring_plan_ref.as_deref()),
        ),
    ]))
}

fn check_instructions_for_use(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::InstructionsForUse(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("document_ref", !evidence.document_ref.trim().is_empty()),
        ("version", has_optional_text(evidence.version.as_deref())),
        (
            "provider_identity",
            has_optional_text(evidence.provider_identity.as_deref()),
        ),
        (
            "intended_purpose",
            has_optional_text(evidence.intended_purpose.as_deref()),
        ),
        (
            "system_capabilities",
            !evidence.system_capabilities.is_empty(),
        ),
        ("accuracy_metrics", !evidence.accuracy_metrics.is_empty()),
        ("foreseeable_risks", !evidence.foreseeable_risks.is_empty()),
        (
            "human_oversight_guidance",
            !evidence.human_oversight_guidance.is_empty(),
        ),
        (
            "log_management_guidance",
            !evidence.log_management_guidance.is_empty(),
        ),
    ]))
}

fn check_human_oversight(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::HumanOversight(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("action", !evidence.action.trim().is_empty()),
        ("reviewer", has_optional_text(evidence.reviewer.as_deref())),
        (
            "actor_role",
            has_optional_text(evidence.actor_role.as_deref()),
        ),
        ("anomaly_detected", evidence.anomaly_detected.is_some()),
        (
            "override_action",
            has_optional_text(evidence.override_action.as_deref()),
        ),
        (
            "automation_bias_detected",
            evidence.automation_bias_detected.is_some(),
        ),
        ("stop_triggered", evidence.stop_triggered.is_some()),
        (
            "stop_reason",
            has_optional_text(evidence.stop_reason.as_deref()),
        ),
    ]))
}

fn check_qms_record(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::QmsRecord(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("record_id", !evidence.record_id.trim().is_empty()),
        ("process", !evidence.process.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        (
            "policy_name",
            has_optional_text(evidence.policy_name.as_deref()),
        ),
        ("revision", has_optional_text(evidence.revision.as_deref())),
        ("scope", has_optional_text(evidence.scope.as_deref())),
        (
            "audit_results_summary",
            has_optional_text(evidence.audit_results_summary.as_deref()),
        ),
        (
            "continuous_improvement_actions",
            !evidence.continuous_improvement_actions.is_empty(),
        ),
    ]))
}

fn check_standards_alignment(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::StandardsAlignment(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("standard_ref", !evidence.standard_ref.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        ("scope", has_optional_text(evidence.scope.as_deref())),
    ]))
}

fn check_post_market_monitoring(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::PostMarketMonitoring(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("plan_id", !evidence.plan_id.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        ("summary", has_optional_text(evidence.summary.as_deref())),
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
