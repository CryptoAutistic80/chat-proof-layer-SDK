use proof_layer_core::schema::{
    BUNDLE_VERSION, ComputeMetricsEvidence, CopyrightPolicyEvidence, DataGovernanceEvidence,
    EvidenceBundle, EvidenceItem, FundamentalRightsAssessmentEvidence, HumanOversightEvidence,
    InstructionsForUseEvidence, ModelEvaluationEvidence, PostMarketMonitoringEvidence,
    QmsRecordEvidence, RiskAssessmentEvidence, StandardsAlignmentEvidence, TechnicalDocEvidence,
    TrainingProvenanceEvidence, TrainingSummaryEvidence,
};
use proof_layer_core::{
    Actor, ActorRole, CompletenessProfile, CompletenessStatus, EncryptionPolicy, EvidenceContext,
    Integrity, Policy, Subject, evaluate_completeness,
};
use serde::de::DeserializeOwned;
use std::{fs, path::PathBuf};

fn golden_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../fixtures/golden/{name}"))
}

fn read_json<T: DeserializeOwned>(dir: &str, name: &str) -> T {
    let path = golden_dir(dir).join(name);
    serde_json::from_slice(
        &fs::read(&path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display())),
    )
    .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn minimal_bundle(
    system_id: &str,
    model_id: &str,
    version: &str,
    items: Vec<EvidenceItem>,
) -> EvidenceBundle {
    EvidenceBundle {
        bundle_version: BUNDLE_VERSION.to_string(),
        bundle_id: "pl-completeness-test".to_string(),
        created_at: "2026-03-21T00:00:00Z".to_string(),
        actor: Actor {
            issuer: "proof-layer-test".to_string(),
            app_id: "core-tests".to_string(),
            env: "test".to_string(),
            signing_key_id: "kid-dev-01".to_string(),
            role: ActorRole::Provider,
            organization_id: None,
        },
        subject: Subject {
            request_id: Some("req-completeness".to_string()),
            thread_id: None,
            user_ref: None,
            system_id: Some(system_id.to_string()),
            model_id: Some(model_id.to_string()),
            deployment_id: None,
            version: Some(version.to_string()),
        },
        compliance_profile: None,
        context: EvidenceContext::default(),
        items,
        artefacts: Vec::new(),
        policy: Policy {
            redactions: Vec::new(),
            encryption: EncryptionPolicy { enabled: false },
            retention_class: None,
        },
        integrity: Integrity::default(),
        timestamp: None,
        receipt: None,
    }
}

fn annex_iv_bundle() -> EvidenceBundle {
    let risk: RiskAssessmentEvidence = read_json("annex_iv_governance", "risk_assessment.json");
    let data: DataGovernanceEvidence = read_json("annex_iv_governance", "data_governance.json");
    let technical: TechnicalDocEvidence = read_json("annex_iv_governance", "technical_doc.json");
    let instructions: InstructionsForUseEvidence =
        read_json("annex_iv_governance", "instructions_for_use.json");
    let oversight: HumanOversightEvidence =
        read_json("annex_iv_governance", "human_oversight.json");
    let qms: QmsRecordEvidence = read_json("annex_iv_governance", "qms_record.json");
    let standards: StandardsAlignmentEvidence =
        read_json("annex_iv_governance", "standards_alignment.json");
    let monitoring: PostMarketMonitoringEvidence =
        read_json("annex_iv_governance", "post_market_monitoring.json");

    minimal_bundle(
        "hiring-assistant",
        "hiring-model-v3",
        "2026.03",
        vec![
            EvidenceItem::TechnicalDoc(technical),
            EvidenceItem::RiskAssessment(risk),
            EvidenceItem::DataGovernance(data),
            EvidenceItem::InstructionsForUse(instructions),
            EvidenceItem::HumanOversight(oversight),
            EvidenceItem::QmsRecord(qms),
            EvidenceItem::StandardsAlignment(standards),
            EvidenceItem::PostMarketMonitoring(monitoring),
        ],
    )
}

fn gpai_provider_bundle() -> EvidenceBundle {
    let technical: TechnicalDocEvidence = read_json("gpai_provider", "technical_doc.json");
    let evaluation: ModelEvaluationEvidence = read_json("gpai_provider", "model_evaluation.json");
    let training: TrainingProvenanceEvidence =
        read_json("gpai_provider", "training_provenance.json");
    let compute: ComputeMetricsEvidence = read_json("gpai_provider", "compute_metrics.json");
    let copyright: CopyrightPolicyEvidence = read_json("gpai_provider", "copyright_policy.json");
    let summary: TrainingSummaryEvidence = read_json("gpai_provider", "training_summary.json");

    minimal_bundle(
        "foundation-model-alpha",
        "foundation-model-alpha-v5",
        "2026.03",
        vec![
            EvidenceItem::TechnicalDoc(technical),
            EvidenceItem::ModelEvaluation(evaluation),
            EvidenceItem::TrainingProvenance(training),
            EvidenceItem::ComputeMetrics(compute),
            EvidenceItem::CopyrightPolicy(copyright),
            EvidenceItem::TrainingSummary(summary),
        ],
    )
}

fn fundamental_rights_bundle() -> EvidenceBundle {
    let assessment: FundamentalRightsAssessmentEvidence =
        read_json("fundamental_rights", "fundamental_rights_assessment.json");
    let oversight: HumanOversightEvidence = read_json("fundamental_rights", "human_oversight.json");

    let mut bundle = minimal_bundle(
        "benefits-review",
        "eligibility-ranker-v2",
        "2026.03",
        vec![
            EvidenceItem::FundamentalRightsAssessment(assessment),
            EvidenceItem::HumanOversight(oversight),
        ],
    );
    bundle.actor.role = ActorRole::Deployer;
    bundle
}

#[test]
fn passing_annex_iv_governance_fixture_returns_pass() {
    let bundle = annex_iv_bundle();
    let report = evaluate_completeness(&bundle, CompletenessProfile::AnnexIvGovernanceV1);

    assert_eq!(report.status, CompletenessStatus::Pass);
    assert_eq!(report.pass_count, 8);
    assert_eq!(report.warn_count, 0);
    assert_eq!(report.fail_count, 0);
}

#[test]
fn missing_required_item_family_returns_fail() {
    let mut bundle = annex_iv_bundle();
    bundle
        .items
        .retain(|item| !matches!(item, EvidenceItem::DataGovernance(_)));

    let report = evaluate_completeness(&bundle, CompletenessProfile::AnnexIvGovernanceV1);

    assert_eq!(report.status, CompletenessStatus::Fail);
    let rule = report
        .rules
        .iter()
        .find(|rule| rule.item_type == "data_governance")
        .expect("data_governance rule should exist");
    assert_eq!(rule.status, CompletenessStatus::Fail);
    assert_eq!(rule.present_count, 0);
    assert_eq!(rule.complete_count, 0);
}

#[test]
fn present_but_incomplete_item_type_without_complete_item_returns_fail() {
    let mut bundle = annex_iv_bundle();
    let technical = bundle
        .items
        .iter_mut()
        .find_map(|item| match item {
            EvidenceItem::TechnicalDoc(evidence) => Some(evidence),
            _ => None,
        })
        .expect("technical_doc should exist");
    technical.annex_iv_sections.clear();

    let report = evaluate_completeness(&bundle, CompletenessProfile::AnnexIvGovernanceV1);

    assert_eq!(report.status, CompletenessStatus::Fail);
    let rule = report
        .rules
        .iter()
        .find(|rule| rule.item_type == "technical_doc")
        .expect("technical_doc rule should exist");
    assert_eq!(rule.status, CompletenessStatus::Fail);
    assert_eq!(rule.present_count, 1);
    assert_eq!(rule.complete_count, 0);
    assert_eq!(rule.missing_fields, vec!["annex_iv_sections"]);
}

#[test]
fn complete_and_incomplete_items_of_same_type_return_warn() {
    let mut bundle = annex_iv_bundle();
    let mut incomplete_risk: RiskAssessmentEvidence =
        read_json("annex_iv_governance", "risk_assessment.json");
    incomplete_risk.test_results_summary = None;
    bundle
        .items
        .push(EvidenceItem::RiskAssessment(incomplete_risk));

    let report = evaluate_completeness(&bundle, CompletenessProfile::AnnexIvGovernanceV1);

    assert_eq!(report.status, CompletenessStatus::Warn);
    let rule = report
        .rules
        .iter()
        .find(|rule| rule.item_type == "risk_assessment")
        .expect("risk_assessment rule should exist");
    assert_eq!(rule.status, CompletenessStatus::Warn);
    assert_eq!(rule.present_count, 2);
    assert_eq!(rule.complete_count, 1);
    assert_eq!(rule.missing_fields, vec!["test_results_summary"]);
}

#[test]
fn compound_dataset_reference_rule_reports_combined_field_name() {
    let mut bundle = annex_iv_bundle();
    let evidence = bundle
        .items
        .iter_mut()
        .find_map(|item| match item {
            EvidenceItem::DataGovernance(evidence) => Some(evidence),
            _ => None,
        })
        .expect("data_governance should exist");
    evidence.dataset_ref = None;
    evidence.dataset_name = None;

    let report = evaluate_completeness(&bundle, CompletenessProfile::AnnexIvGovernanceV1);

    assert_eq!(report.status, CompletenessStatus::Fail);
    let rule = report
        .rules
        .iter()
        .find(|rule| rule.item_type == "data_governance")
        .expect("data_governance rule should exist");
    assert!(
        rule.missing_fields
            .contains(&"dataset_ref|dataset_name".to_string())
    );
}

#[test]
fn passing_gpai_provider_fixture_returns_pass() {
    let bundle = gpai_provider_bundle();
    let report = evaluate_completeness(&bundle, CompletenessProfile::GpaiProviderV1);

    assert_eq!(report.status, CompletenessStatus::Pass);
    assert_eq!(report.pass_count, 6);
    assert_eq!(report.warn_count, 0);
    assert_eq!(report.fail_count, 0);
}

#[test]
fn gpai_provider_missing_required_field_returns_fail() {
    let mut bundle = gpai_provider_bundle();
    let evidence = bundle
        .items
        .iter_mut()
        .find_map(|item| match item {
            EvidenceItem::ComputeMetrics(evidence) => Some(evidence),
            _ => None,
        })
        .expect("compute_metrics should exist");
    evidence.compute_resources_summary.clear();

    let report = evaluate_completeness(&bundle, CompletenessProfile::GpaiProviderV1);

    assert_eq!(report.status, CompletenessStatus::Fail);
    let rule = report
        .rules
        .iter()
        .find(|rule| rule.item_type == "compute_metrics")
        .expect("compute_metrics rule should exist");
    assert_eq!(rule.status, CompletenessStatus::Fail);
    assert_eq!(rule.missing_fields, vec!["compute_resources_summary"]);
}

#[test]
fn passing_fundamental_rights_fixture_returns_pass() {
    let bundle = fundamental_rights_bundle();
    let report = evaluate_completeness(&bundle, CompletenessProfile::FundamentalRightsV1);

    assert_eq!(report.status, CompletenessStatus::Pass);
    assert_eq!(report.pass_count, 2);
    assert_eq!(report.warn_count, 0);
    assert_eq!(report.fail_count, 0);
}

#[test]
fn annex_iv_qms_record_missing_required_field_returns_fail() {
    let mut bundle = annex_iv_bundle();
    let evidence = bundle
        .items
        .iter_mut()
        .find_map(|item| match item {
            EvidenceItem::QmsRecord(evidence) => Some(evidence),
            _ => None,
        })
        .expect("qms_record should exist");
    evidence.continuous_improvement_actions.clear();

    let report = evaluate_completeness(&bundle, CompletenessProfile::AnnexIvGovernanceV1);

    assert_eq!(report.status, CompletenessStatus::Fail);
    let rule = report
        .rules
        .iter()
        .find(|rule| rule.item_type == "qms_record")
        .expect("qms_record rule should exist");
    assert_eq!(rule.status, CompletenessStatus::Fail);
    assert_eq!(rule.missing_fields, vec!["continuous_improvement_actions"]);
}

#[test]
fn fundamental_rights_missing_mitigation_summary_returns_fail() {
    let mut bundle = fundamental_rights_bundle();
    let evidence = bundle
        .items
        .iter_mut()
        .find_map(|item| match item {
            EvidenceItem::FundamentalRightsAssessment(evidence) => Some(evidence),
            _ => None,
        })
        .expect("fundamental_rights_assessment should exist");
    evidence.mitigation_plan_summary = None;

    let report = evaluate_completeness(&bundle, CompletenessProfile::FundamentalRightsV1);

    assert_eq!(report.status, CompletenessStatus::Fail);
    let rule = report
        .rules
        .iter()
        .find(|rule| rule.item_type == "fundamental_rights_assessment")
        .expect("fundamental_rights_assessment rule should exist");
    assert_eq!(rule.status, CompletenessStatus::Fail);
    assert_eq!(rule.missing_fields, vec!["mitigation_plan_summary"]);
}

#[test]
fn gpai_provider_complete_and_incomplete_items_of_same_type_return_warn() {
    let mut bundle = gpai_provider_bundle();
    let mut incomplete: ModelEvaluationEvidence =
        read_json("gpai_provider", "model_evaluation.json");
    incomplete.metrics_summary.clear();
    bundle.items.push(EvidenceItem::ModelEvaluation(incomplete));

    let report = evaluate_completeness(&bundle, CompletenessProfile::GpaiProviderV1);

    assert_eq!(report.status, CompletenessStatus::Warn);
    let rule = report
        .rules
        .iter()
        .find(|rule| rule.item_type == "model_evaluation")
        .expect("model_evaluation rule should exist");
    assert_eq!(rule.status, CompletenessStatus::Warn);
    assert_eq!(rule.present_count, 2);
    assert_eq!(rule.complete_count, 1);
    assert_eq!(rule.missing_fields, vec!["metrics_summary"]);
}

#[test]
fn gpai_provider_technical_doc_either_or_rule_reports_combined_field_name() {
    let mut bundle = gpai_provider_bundle();
    let evidence = bundle
        .items
        .iter_mut()
        .find_map(|item| match item {
            EvidenceItem::TechnicalDoc(evidence) => Some(evidence),
            _ => None,
        })
        .expect("technical_doc should exist");
    evidence.system_description_summary = None;
    evidence.model_description_summary = None;

    let report = evaluate_completeness(&bundle, CompletenessProfile::GpaiProviderV1);

    assert_eq!(report.status, CompletenessStatus::Fail);
    let rule = report
        .rules
        .iter()
        .find(|rule| rule.item_type == "technical_doc")
        .expect("technical_doc rule should exist");
    assert!(
        rule.missing_fields
            .contains(&"model_description_summary|system_description_summary".to_string())
    );
}

#[test]
fn gpai_provider_training_provenance_either_or_rule_reports_combined_field_name() {
    let mut bundle = gpai_provider_bundle();
    let evidence = bundle
        .items
        .iter_mut()
        .find_map(|item| match item {
            EvidenceItem::TrainingProvenance(evidence) => Some(evidence),
            _ => None,
        })
        .expect("training_provenance should exist");
    evidence.lineage_ref = None;
    evidence.record_commitment = None;

    let report = evaluate_completeness(&bundle, CompletenessProfile::GpaiProviderV1);

    assert_eq!(report.status, CompletenessStatus::Fail);
    let rule = report
        .rules
        .iter()
        .find(|rule| rule.item_type == "training_provenance")
        .expect("training_provenance rule should exist");
    assert!(
        rule.missing_fields
            .contains(&"lineage_ref|record_commitment".to_string())
    );
}

#[test]
fn completeness_profile_rejects_unknown_profile_strings() {
    let err = "not_a_profile"
        .parse::<CompletenessProfile>()
        .expect_err("unknown profile should fail");
    assert_eq!(err, "unsupported completeness profile not_a_profile");
}
