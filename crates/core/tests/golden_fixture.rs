use chrono::{DateTime, Utc};
use proof_layer_core::{
    ArtefactInput, CaptureInput, ProofBundle, build_bundle, compute_commitment,
    decode_private_key_pem, decode_public_key_pem, sha256_prefixed, verify_bundle_root,
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Deserialize)]
struct ExpectedManifestEntry {
    digest: String,
    size: u64,
}

#[derive(Debug, Deserialize)]
struct ExpectedBundleValues {
    bundle_id: String,
    created_at: String,
    signing_kid: String,
    header_digest: String,
    bundle_root: String,
    signature_jws: String,
    artefact_digests: BTreeMap<String, String>,
    manifest_entries: BTreeMap<String, ExpectedManifestEntry>,
}

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/golden")
}

fn read_bytes(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn read_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

#[test]
fn golden_fixture_is_deterministic_and_verifiable() {
    let golden = golden_dir();
    let fixed_bundle = golden.join("fixed_bundle");

    let expected: ExpectedBundleValues =
        serde_json::from_slice(&read_bytes(&golden.join("expected_bundle_values.json")))
            .expect("expected values should parse");

    let bundle: ProofBundle =
        serde_json::from_slice(&read_bytes(&fixed_bundle.join("proof_bundle.json")))
            .expect("proof_bundle.json should parse");
    let canonical_fixture = read_bytes(&fixed_bundle.join("proof_bundle.canonical.json"));
    let signature_fixture = read_string(&fixed_bundle.join("proof_bundle.sig"));

    assert_eq!(bundle.bundle_id, expected.bundle_id);
    assert_eq!(bundle.created_at, expected.created_at);
    assert_eq!(bundle.integrity.signature.kid, expected.signing_kid);
    assert_eq!(bundle.integrity.header_digest, expected.header_digest);
    assert_eq!(bundle.integrity.bundle_root, expected.bundle_root);
    assert_eq!(bundle.integrity.signature.value, expected.signature_jws);
    assert_eq!(signature_fixture.trim(), expected.signature_jws);

    let canonical_once = bundle
        .canonical_header_bytes()
        .expect("canonicalization should work");
    let canonical_twice = bundle
        .canonical_header_bytes()
        .expect("canonicalization should work");
    assert_eq!(canonical_once, canonical_twice);
    assert_eq!(canonical_once, canonical_fixture);
    assert_eq!(sha256_prefixed(&canonical_once), expected.header_digest);

    let mut artefacts = BTreeMap::new();
    for meta in &bundle.artefacts {
        let bytes = read_bytes(&fixed_bundle.join("artefacts").join(&meta.name));
        assert_eq!(sha256_prefixed(&bytes), meta.digest);
        assert_eq!(
            sha256_prefixed(&bytes),
            expected.artefact_digests[&meta.name]
        );
        assert_eq!(bytes.len() as u64, meta.size);
        artefacts.insert(meta.name.clone(), bytes);
    }

    for (name, entry) in &expected.manifest_entries {
        let bytes = read_bytes(&fixed_bundle.join(name));
        assert_eq!(sha256_prefixed(&bytes), entry.digest);
        assert_eq!(bytes.len() as u64, entry.size);
    }

    let commitment_once =
        compute_commitment(&bundle.commitment_digests().expect("digests should build"))
            .expect("commitment should succeed");
    let commitment_twice =
        compute_commitment(&bundle.commitment_digests().expect("digests should build"))
            .expect("commitment should succeed");
    assert_eq!(commitment_once.root, commitment_twice.root);
    assert_eq!(commitment_once.root, expected.bundle_root);

    let verifying_key = decode_public_key_pem(&read_string(&golden.join("verify_key.txt")))
        .expect("verify key should parse");
    verify_bundle_root(
        &expected.signature_jws,
        &expected.bundle_root,
        &verifying_key,
    )
    .expect("signature should verify");

    let summary = bundle
        .verify_with_artefacts(&artefacts, &verifying_key)
        .expect("bundle should verify with fixture artefacts");
    assert_eq!(summary.artefact_count, bundle.artefacts.len());

    let capture: CaptureInput = serde_json::from_slice(&read_bytes(&golden.join("capture.json")))
        .expect("capture fixture should parse");
    let signing_key = decode_private_key_pem(&read_string(&golden.join("signing_key.txt")))
        .expect("signing key should parse");
    let created_at = DateTime::parse_from_rfc3339(&expected.created_at)
        .expect("expected created_at should be RFC3339")
        .with_timezone(&Utc);

    let artefact_inputs = bundle
        .artefacts
        .iter()
        .map(|meta| ArtefactInput {
            name: meta.name.clone(),
            content_type: meta.content_type.clone(),
            bytes: artefacts
                .get(&meta.name)
                .cloned()
                .expect("artefact bytes should exist"),
        })
        .collect::<Vec<_>>();

    let rebuilt = build_bundle(
        capture,
        &artefact_inputs,
        &signing_key,
        &expected.signing_kid,
        &expected.bundle_id,
        created_at,
    )
    .expect("rebuild should succeed");

    assert_eq!(rebuilt.integrity.header_digest, expected.header_digest);
    assert_eq!(rebuilt.integrity.bundle_root, expected.bundle_root);
    assert_eq!(rebuilt.integrity.signature.value, expected.signature_jws);
    assert_eq!(
        rebuilt
            .canonical_header_bytes()
            .expect("canonicalization should work"),
        canonical_fixture
    );
}
