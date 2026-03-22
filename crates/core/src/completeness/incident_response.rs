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
        rule_id: "incident_response_technical_doc_minimum",
        item_type: "technical_doc",
        obligation_ref: "art11_annex_iv",
        check: check_technical_doc,
    },
    RuleDefinition {
        rule_id: "incident_response_risk_assessment_minimum",
        item_type: "risk_assessment",
        obligation_ref: "art9",
        check: check_risk_assessment,
    },
    RuleDefinition {
        rule_id: "incident_response_human_oversight_minimum",
        item_type: "human_oversight",
        obligation_ref: "art14",
        check: check_human_oversight,
    },
    RuleDefinition {
        rule_id: "incident_response_policy_decision_minimum",
        item_type: "policy_decision",
        obligation_ref: "art20_73",
        check: check_policy_decision,
    },
    RuleDefinition {
        rule_id: "incident_response_incident_report_minimum",
        item_type: "incident_report",
        obligation_ref: "art55_73",
        check: check_incident_report,
    },
    RuleDefinition {
        rule_id: "incident_response_corrective_action_minimum",
        item_type: "corrective_action",
        obligation_ref: "art20_73",
        check: check_corrective_action,
    },
    RuleDefinition {
        rule_id: "incident_response_authority_notification_minimum",
        item_type: "authority_notification",
        obligation_ref: "art73_notification",
        check: check_authority_notification,
    },
    RuleDefinition {
        rule_id: "incident_response_authority_submission_minimum",
        item_type: "authority_submission",
        obligation_ref: "art73_submission",
        check: check_authority_submission,
    },
    RuleDefinition {
        rule_id: "incident_response_reporting_deadline_minimum",
        item_type: "reporting_deadline",
        obligation_ref: "art73_deadline",
        check: check_reporting_deadline,
    },
    RuleDefinition {
        rule_id: "incident_response_regulator_correspondence_minimum",
        item_type: "regulator_correspondence",
        obligation_ref: "art73_correspondence",
        check: check_regulator_correspondence,
    },
];

pub(super) fn evaluate(bundle: &EvidenceBundle) -> crate::completeness::CompletenessReport {
    let rules = RULES
        .iter()
        .map(|rule| evaluate_rule(bundle, rule))
        .collect::<Vec<_>>();
    report_for_rules(bundle, CompletenessProfile::IncidentResponseV1, rules)
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
            "{} is minimally structured for incident-response review.",
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

fn check_technical_doc(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::TechnicalDoc(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("document_ref", !evidence.document_ref.trim().is_empty()),
        (
            "commitment",
            has_optional_text(evidence.commitment.as_deref()),
        ),
        (
            "system_description_summary",
            has_optional_text(evidence.system_description_summary.as_deref()),
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
            "human_oversight_design_summary",
            has_optional_text(evidence.human_oversight_design_summary.as_deref()),
        ),
    ]))
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

fn check_policy_decision(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::PolicyDecision(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("policy_name", !evidence.policy_name.trim().is_empty()),
        ("decision", !evidence.decision.trim().is_empty()),
        (
            "rationale_commitment",
            has_optional_text(evidence.rationale_commitment.as_deref()),
        ),
    ]))
}

fn check_incident_report(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::IncidentReport(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("incident_id", !evidence.incident_id.trim().is_empty()),
        ("severity", !evidence.severity.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        (
            "occurred_at",
            has_optional_text(evidence.occurred_at.as_deref()),
        ),
        ("summary", has_optional_text(evidence.summary.as_deref())),
        (
            "report_commitment",
            has_optional_text(evidence.report_commitment.as_deref()),
        ),
        (
            "detection_method",
            has_optional_text(evidence.detection_method.as_deref()),
        ),
        (
            "root_cause_summary",
            has_optional_text(evidence.root_cause_summary.as_deref()),
        ),
        (
            "corrective_action_ref",
            has_optional_text(evidence.corrective_action_ref.as_deref()),
        ),
        (
            "authority_notification_required",
            evidence.authority_notification_required.is_some(),
        ),
        (
            "authority_notification_status",
            has_optional_text(evidence.authority_notification_status.as_deref()),
        ),
    ]))
}

fn check_corrective_action(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::CorrectiveAction(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("action_id", !evidence.action_id.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        ("summary", has_optional_text(evidence.summary.as_deref())),
        ("due_at", has_optional_text(evidence.due_at.as_deref())),
        (
            "record_commitment",
            has_optional_text(evidence.record_commitment.as_deref()),
        ),
    ]))
}

fn check_authority_notification(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::AuthorityNotification(evidence) = item else {
        return None;
    };
    Some(required_fields([
        (
            "notification_id",
            !evidence.notification_id.trim().is_empty(),
        ),
        ("authority", !evidence.authority.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        (
            "incident_id",
            has_optional_text(evidence.incident_id.as_deref()),
        ),
        ("due_at", has_optional_text(evidence.due_at.as_deref())),
        (
            "report_commitment",
            has_optional_text(evidence.report_commitment.as_deref()),
        ),
    ]))
}

fn check_authority_submission(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::AuthoritySubmission(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("submission_id", !evidence.submission_id.trim().is_empty()),
        ("authority", !evidence.authority.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        ("channel", has_optional_text(evidence.channel.as_deref())),
        (
            "submitted_at",
            has_optional_text(evidence.submitted_at.as_deref()),
        ),
        (
            "document_commitment",
            has_optional_text(evidence.document_commitment.as_deref()),
        ),
    ]))
}

fn check_reporting_deadline(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::ReportingDeadline(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("deadline_id", !evidence.deadline_id.trim().is_empty()),
        ("authority", !evidence.authority.trim().is_empty()),
        ("obligation_ref", !evidence.obligation_ref.trim().is_empty()),
        ("due_at", !evidence.due_at.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        (
            "incident_id",
            has_optional_text(evidence.incident_id.as_deref()),
        ),
    ]))
}

fn check_regulator_correspondence(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::RegulatorCorrespondence(evidence) = item else {
        return None;
    };
    Some(required_fields([
        (
            "correspondence_id",
            !evidence.correspondence_id.trim().is_empty(),
        ),
        ("authority", !evidence.authority.trim().is_empty()),
        ("direction", !evidence.direction.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        (
            "occurred_at",
            has_optional_text(evidence.occurred_at.as_deref()),
        ),
        (
            "message_commitment",
            has_optional_text(evidence.message_commitment.as_deref()),
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
