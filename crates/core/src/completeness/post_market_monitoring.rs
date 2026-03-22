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
        rule_id: "post_market_monitoring_plan_minimum",
        item_type: "post_market_monitoring",
        obligation_ref: "art72",
        check: check_post_market_monitoring,
    },
    RuleDefinition {
        rule_id: "post_market_monitoring_incident_report_minimum",
        item_type: "incident_report",
        obligation_ref: "art55_73",
        check: check_incident_report,
    },
    RuleDefinition {
        rule_id: "post_market_monitoring_corrective_action_minimum",
        item_type: "corrective_action",
        obligation_ref: "art20_73",
        check: check_corrective_action,
    },
    RuleDefinition {
        rule_id: "post_market_monitoring_authority_notification_minimum",
        item_type: "authority_notification",
        obligation_ref: "art73_notification",
        check: check_authority_notification,
    },
    RuleDefinition {
        rule_id: "post_market_monitoring_authority_submission_minimum",
        item_type: "authority_submission",
        obligation_ref: "art73_submission",
        check: check_authority_submission,
    },
    RuleDefinition {
        rule_id: "post_market_monitoring_reporting_deadline_minimum",
        item_type: "reporting_deadline",
        obligation_ref: "art73_deadline",
        check: check_reporting_deadline,
    },
];

pub(super) fn evaluate(bundle: &EvidenceBundle) -> crate::completeness::CompletenessReport {
    let rules = RULES
        .iter()
        .map(|rule| evaluate_rule(bundle, rule))
        .collect::<Vec<_>>();
    report_for_rules(bundle, CompletenessProfile::PostMarketMonitoringV1, rules)
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
            "{} is minimally structured for post-market monitoring review.",
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

fn check_post_market_monitoring(item: &EvidenceItem) -> Option<Vec<String>> {
    let EvidenceItem::PostMarketMonitoring(evidence) = item else {
        return None;
    };
    Some(required_fields([
        ("plan_id", !evidence.plan_id.trim().is_empty()),
        ("status", !evidence.status.trim().is_empty()),
        ("summary", has_optional_text(evidence.summary.as_deref())),
        (
            "report_commitment",
            has_optional_text(evidence.report_commitment.as_deref()),
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

fn required_fields<const N: usize>(pairs: [(&str, bool); N]) -> Vec<String> {
    pairs
        .into_iter()
        .filter_map(|(field, present)| (!present).then_some(field.to_string()))
        .collect()
}

fn has_optional_text(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}
