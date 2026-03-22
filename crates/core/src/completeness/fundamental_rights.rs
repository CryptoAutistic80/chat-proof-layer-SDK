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
        rule_id: "fundamental_rights_assessment_minimum",
        item_type: "fundamental_rights_assessment",
        obligation_ref: "art27",
        check: check_fundamental_rights_assessment,
    },
    RuleDefinition {
        rule_id: "fundamental_rights_human_oversight_minimum",
        item_type: "human_oversight",
        obligation_ref: "art14",
        check: check_human_oversight,
    },
];

pub(super) fn evaluate(bundle: &EvidenceBundle) -> crate::completeness::CompletenessReport {
    let rules = RULES
        .iter()
        .map(|rule| evaluate_rule(bundle, rule))
        .collect::<Vec<_>>();
    report_for_rules(bundle, CompletenessProfile::FundamentalRightsV1, rules)
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
                "{} is minimally structured for deployer-side fundamental-rights review.",
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

fn check_fundamental_rights_assessment(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::FundamentalRightsAssessment(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("assessment_id", !evidence.assessment_id.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        ("scope", has_optional_text(evidence.scope.as_deref())),
        (
            "report_commitment",
            has_optional_text(evidence.report_commitment.as_deref()),
        ),
        (
            "legal_basis",
            has_optional_text(evidence.legal_basis.as_deref()),
        ),
        ("affected_rights", !evidence.affected_rights.is_empty()),
        (
            "stakeholder_consultation_summary",
            has_optional_text(evidence.stakeholder_consultation_summary.as_deref()),
        ),
        (
            "mitigation_plan_summary",
            has_optional_text(evidence.mitigation_plan_summary.as_deref()),
        ),
        ("assessor", has_optional_text(evidence.assessor.as_deref())),
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
            "notes_commitment",
            has_optional_text(evidence.notes_commitment.as_deref()),
        ),
        (
            "override_action",
            has_optional_text(evidence.override_action.as_deref()),
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
