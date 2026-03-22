mod annex_iv;
mod fundamental_rights;
mod gpai_provider;
mod post_market_monitoring;

use crate::schema::EvidenceBundle;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompletenessProfile {
    AnnexIvGovernanceV1,
    FundamentalRightsV1,
    GpaiProviderV1,
    PostMarketMonitoringV1,
}

impl CompletenessProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AnnexIvGovernanceV1 => "annex_iv_governance_v1",
            Self::FundamentalRightsV1 => "fundamental_rights_v1",
            Self::GpaiProviderV1 => "gpai_provider_v1",
            Self::PostMarketMonitoringV1 => "post_market_monitoring_v1",
        }
    }
}

impl fmt::Display for CompletenessProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CompletenessProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "annex_iv_governance_v1" => Ok(Self::AnnexIvGovernanceV1),
            "fundamental_rights_v1" => Ok(Self::FundamentalRightsV1),
            "gpai_provider_v1" => Ok(Self::GpaiProviderV1),
            "post_market_monitoring_v1" => Ok(Self::PostMarketMonitoringV1),
            other => Err(format!("unsupported completeness profile {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CompletenessStatus {
    Pass,
    Warn,
    Fail,
}

impl CompletenessStatus {
    fn from_rule_counts(fail_count: usize, warn_count: usize) -> Self {
        if fail_count > 0 {
            Self::Fail
        } else if warn_count > 0 {
            Self::Warn
        } else {
            Self::Pass
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompletenessRuleResult {
    pub rule_id: String,
    pub item_type: String,
    pub obligation_ref: String,
    pub status: CompletenessStatus,
    pub present_count: usize,
    pub complete_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evaluated_item_indices: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_fields: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompletenessReport {
    pub profile: CompletenessProfile,
    pub status: CompletenessStatus,
    pub bundle_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_id: Option<String>,
    pub pass_count: usize,
    pub warn_count: usize,
    pub fail_count: usize,
    pub rules: Vec<CompletenessRuleResult>,
}

pub fn evaluate_completeness(
    bundle: &EvidenceBundle,
    profile: CompletenessProfile,
) -> CompletenessReport {
    match profile {
        CompletenessProfile::AnnexIvGovernanceV1 => annex_iv::evaluate(bundle),
        CompletenessProfile::FundamentalRightsV1 => fundamental_rights::evaluate(bundle),
        CompletenessProfile::GpaiProviderV1 => gpai_provider::evaluate(bundle),
        CompletenessProfile::PostMarketMonitoringV1 => post_market_monitoring::evaluate(bundle),
    }
}

fn report_for_rules(
    bundle: &EvidenceBundle,
    profile: CompletenessProfile,
    rules: Vec<CompletenessRuleResult>,
) -> CompletenessReport {
    let pass_count = rules
        .iter()
        .filter(|rule| rule.status == CompletenessStatus::Pass)
        .count();
    let warn_count = rules
        .iter()
        .filter(|rule| rule.status == CompletenessStatus::Warn)
        .count();
    let fail_count = rules
        .iter()
        .filter(|rule| rule.status == CompletenessStatus::Fail)
        .count();

    CompletenessReport {
        profile,
        status: CompletenessStatus::from_rule_counts(fail_count, warn_count),
        bundle_id: bundle.bundle_id.clone(),
        system_id: bundle.subject.system_id.clone(),
        pass_count,
        warn_count,
        fail_count,
        rules,
    }
}
