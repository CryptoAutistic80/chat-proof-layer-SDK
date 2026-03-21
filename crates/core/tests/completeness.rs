use proof_layer_core::{
    Actor, ActorRole, CompletenessProfile, CompletenessStatus, EvidenceContext,
    EncryptionPolicy, Integrity, Policy, Subject, evaluate_completeness,
};
use proof_layer_core::schema::{
    DataGovernanceEvidence, EvidenceBundle, EvidenceItem, HumanOversightEvidence,
    InstructionsForUseEvidence, RiskAssessmentEvidence, TechnicalDocEvidence, BUNDLE_VERSION,
};
use serde::de::DeserializeOwned;
use std::{fs, path::PathBuf};

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/golden/annex_iv_governance")
}

fn read_json<T: DeserializeOwned>(name: &str) -> T {
    let path = golden_dir().join(name);
    serde_json::from_slice(&fs::read(&path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", path.display())
    }))
    .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn minimal_bundle(items: Vec<EvidenceItem>) -> EvidenceBundle {
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
            system_id: Some("hiring-assistant".to_string()),
            model_id: Some("hiring-model-v3".to_string()),
            deployment_id: None,
            version: Some("2026.03".to_string()),
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
    let risk: RiskAssessmentEvidence = read_json("risk_assessment.json");
    let data: DataGovernanceEvidence = read_json("data_governance.json");
    let technical: TechnicalDocEvidence = read_json("technical_doc.json");
    let instructions: InstructionsForUseEvidence = read_json("instructions_for_use.json");
    let oversight: HumanOversightEvidence = read_json("human_oversight.json");

    minimal_bundle(vec![
        EvidenceItem::TechnicalDoc(technical),
        EvidenceItem::RiskAssessment(risk),
        EvidenceItem::DataGovernance(data),
        EvidenceItem::InstructionsForUse(instructions),
        EvidenceItem::HumanOversight(oversight),
    ])
}

#[test]
fn passing_annex_iv_governance_fixture_returns_pass() {
    let bundle = annex_iv_bundle();
    let report = evaluate_completeness(&bundle, CompletenessProfile::AnnexIvGovernanceV1);

    assert_eq!(report.status, CompletenessStatus::Pass);
    assert_eq!(report.pass_count, 5);
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
    let mut incomplete_risk: RiskAssessmentEvidence = read_json("risk_assessment.json");
    incomplete_risk.test_results_summary = None;
    bundle.items.push(EvidenceItem::RiskAssessment(incomplete_risk));

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
