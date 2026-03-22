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
        rule_id: "conformity_assessment_minimum",
        item_type: "conformity_assessment",
        obligation_ref: "art43_annex_vi_vii",
        check: check_conformity_assessment,
    },
    RuleDefinition {
        rule_id: "conformity_declaration_minimum",
        item_type: "declaration",
        obligation_ref: "art47_annex_v",
        check: check_declaration,
    },
    RuleDefinition {
        rule_id: "conformity_registration_minimum",
        item_type: "registration",
        obligation_ref: "art49_71",
        check: check_registration,
    },
];

pub(super) fn evaluate(bundle: &EvidenceBundle) -> crate::completeness::CompletenessReport {
    let rules = RULES
        .iter()
        .map(|rule| evaluate_rule(bundle, rule))
        .collect::<Vec<_>>();
    report_for_rules(bundle, CompletenessProfile::ConformityV1, rules)
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
        CompletenessStatus::Pass => format!(
            "{} is minimally structured for conformity review.",
            rule.item_type.replace('_', " ")
        ),
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

fn check_conformity_assessment(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::ConformityAssessment(evidence) = item else {
        return None;
    };
    let mut missing_fields = required_fields([
        ("assessment_id", !evidence.assessment_id.trim().is_empty()),
        ("procedure", !evidence.procedure.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        (
            "report_commitment",
            has_optional_text(evidence.report_commitment.as_deref()),
        ),
    ]);

    if !has_optional_text(evidence.assessment_body.as_deref())
        && !has_optional_text(evidence.certificate_ref.as_deref())
    {
        missing_fields.push("assessment_body|certificate_ref".to_string());
    }

    Some(missing_fields)
}

fn check_declaration(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::Declaration(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("declaration_id", !evidence.declaration_id.trim().is_empty()),
        ("jurisdiction", !evidence.jurisdiction.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        (
            "document_commitment",
            has_optional_text(evidence.document_commitment.as_deref()),
        ),
        (
            "signatory",
            has_optional_text(evidence.signatory.as_deref()),
        ),
        (
            "document_version",
            has_optional_text(evidence.document_version.as_deref()),
        ),
    ]))
}

fn check_registration(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::Registration(evidence) = item else {
        return None;
    };
    Some(required_fields([
        (
            "registration_id",
            !evidence.registration_id.trim().is_empty(),
        ),
        ("authority", !evidence.authority.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        (
            "receipt_commitment",
            has_optional_text(evidence.receipt_commitment.as_deref()),
        ),
        (
            "registration_number",
            has_optional_text(evidence.registration_number.as_deref()),
        ),
        (
            "submitted_at",
            has_optional_text(evidence.submitted_at.as_deref()),
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
