use chrono::{TimeZone, Utc};
use ed25519_dalek::SigningKey;
use proof_layer_core::{
    ArtefactInput, BuildBundleError, CaptureInput, ProofBundle, SignError, build_bundle,
    decode_private_key_pem, decode_public_key_pem,
};
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn golden_dir() -> PathBuf {
    repo_root().join("fixtures/golden")
}

fn read_bytes(path: PathBuf) -> Vec<u8> {
    fs::read(&path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn read_string(path: PathBuf) -> String {
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn fixture_capture() -> CaptureInput {
    serde_json::from_slice(&read_bytes(golden_dir().join("capture.json")))
        .expect("capture fixture should parse")
}

fn fixture_artefacts() -> Vec<ArtefactInput> {
    vec![
        ArtefactInput {
            name: "prompt.json".to_string(),
            content_type: "application/json".to_string(),
            bytes: read_bytes(golden_dir().join("prompt.json")),
        },
        ArtefactInput {
            name: "response.json".to_string(),
            content_type: "application/json".to_string(),
            bytes: read_bytes(golden_dir().join("response.json")),
        },
    ]
}

fn built_fixture_bundle() -> ProofBundle {
    let signing_key = decode_private_key_pem(&read_string(golden_dir().join("signing_key.txt")))
        .expect("signing key should parse");
    build_bundle(
        fixture_capture(),
        &fixture_artefacts(),
        &signing_key,
        "kid-dev-01",
        "01JNFVDSM64DJN8SNMZP63YQC8",
        Utc.with_ymd_and_hms(2026, 3, 2, 0, 0, 0).unwrap(),
    )
    .expect("bundle build should succeed")
}

fn built_fixture_bundle_with_verifier() -> (ProofBundle, ed25519_dalek::VerifyingKey) {
    let bundle = built_fixture_bundle();
    let verifying_key = decode_public_key_pem(&read_string(golden_dir().join("verify_key.txt")))
        .expect("verify key should parse");
    (bundle, verifying_key)
}

#[test]
fn deterministic_hashing_invariants_hold_for_fixed_inputs() {
    let bundle_a = built_fixture_bundle();
    let bundle_b = built_fixture_bundle();

    let header_a = bundle_a
        .canonical_header_bytes()
        .expect("canonicalization should succeed");
    let header_b = bundle_b
        .canonical_header_bytes()
        .expect("canonicalization should succeed");

    assert_eq!(header_a, header_b);
    assert_eq!(
        bundle_a.integrity.header_digest,
        bundle_b.integrity.header_digest
    );
    assert_eq!(
        bundle_a.integrity.bundle_root,
        bundle_b.integrity.bundle_root
    );
    assert_eq!(
        bundle_a.integrity.signature.value,
        bundle_b.integrity.signature.value
    );
}

#[test]
fn tamper_detection_catches_message_order_and_metadata_mutations() {
    let (bundle, verifying_key) = built_fixture_bundle_with_verifier();
    let prompt_bytes = read_bytes(golden_dir().join("prompt.json"));
    let response_bytes = read_bytes(golden_dir().join("response.json"));
    let mut artefacts = BTreeMap::new();
    artefacts.insert("prompt.json".to_string(), prompt_bytes.clone());
    artefacts.insert("response.json".to_string(), response_bytes.clone());

    bundle
        .verify_with_artefacts(&artefacts, &verifying_key)
        .expect("baseline verification should pass");

    let mut tampered_message = bundle.clone();
    if let proof_layer_core::EvidenceItem::LlmInteraction(ref mut item) = tampered_message.items[0]
    {
        item.output_commitment =
            "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string();
    }
    assert!(
        tampered_message
            .verify_with_artefacts(&artefacts, &verifying_key)
            .is_err()
    );

    let mut tampered_order = bundle.clone();
    tampered_order.artefacts.reverse();
    assert!(
        tampered_order
            .verify_with_artefacts(&artefacts, &verifying_key)
            .is_err()
    );

    let mut tampered_metadata = bundle.clone();
    tampered_metadata.context.parameters = serde_json::json!({"temperature": 0.9});
    assert!(
        tampered_metadata
            .verify_with_artefacts(&artefacts, &verifying_key)
            .is_err()
    );
}

#[test]
fn signature_verification_passes_and_fails_with_key_mismatch() {
    let (bundle, verifying_key) = built_fixture_bundle_with_verifier();
    let mut artefacts = BTreeMap::new();
    artefacts.insert(
        "prompt.json".to_string(),
        read_bytes(golden_dir().join("prompt.json")),
    );
    artefacts.insert(
        "response.json".to_string(),
        read_bytes(golden_dir().join("response.json")),
    );

    bundle
        .verify_with_artefacts(&artefacts, &verifying_key)
        .expect("verification with matching key should pass");

    let wrong_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>()).verifying_key();
    assert!(
        bundle
            .verify_with_artefacts(&artefacts, &wrong_key)
            .is_err(),
        "verification with wrong key should fail"
    );
}

#[test]
fn signing_error_paths_surface_through_bundle_builder() {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let err = build_bundle(
        fixture_capture(),
        &fixture_artefacts(),
        &signing_key,
        "   ",
        "01JNFVDSM64DJN8SNMZP63YQC8",
        Utc.with_ymd_and_hms(2026, 3, 2, 0, 0, 0).unwrap(),
    )
    .expect_err("empty kid should fail");

    assert!(matches!(
        err,
        BuildBundleError::Signing(SignError::EmptyKid)
    ));
}

#[test]
fn generated_and_fixture_bundles_include_schema_required_fields() {
    let schema_text = read_string(repo_root().join("schemas/evidence_bundle.schema.json"));
    let schema_json: Value = serde_json::from_str(&schema_text).expect("schema should parse");
    let required = schema_json
        .get("required")
        .and_then(Value::as_array)
        .expect("schema should declare required fields")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();

    let generated_bundle = serde_json::to_value(built_fixture_bundle())
        .expect("generated bundle should serialize to value");
    let fixture_bundle: Value = serde_json::from_slice(&read_bytes(
        golden_dir().join("fixed_bundle/proof_bundle.json"),
    ))
    .expect("fixture bundle should parse");

    for field in &required {
        assert!(
            generated_bundle.get(*field).is_some(),
            "generated bundle should include required schema field {field}"
        );
        assert!(
            fixture_bundle.get(*field).is_some(),
            "fixture bundle should include required schema field {field}"
        );
    }
}
