use proof_layer_core::canonicalize_json_strict;
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Debug, Deserialize)]
struct CanonicalVector {
    name: String,
    raw_json: String,
    canonical_json: String,
}

#[derive(Debug, Deserialize)]
struct CanonicalVectors {
    vectors: Vec<CanonicalVector>,
}

fn vector_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/golden/rfc8785_vectors.json")
}

#[test]
fn canonicalization_matches_vector_fixture() {
    let fixture = fs::read(vector_fixture_path()).expect("vector fixture should exist");
    let vectors: CanonicalVectors =
        serde_json::from_slice(&fixture).expect("vector fixture should parse");

    for vector in vectors.vectors {
        let canonical = canonicalize_json_strict(vector.raw_json.as_bytes())
            .unwrap_or_else(|err| panic!("{} should canonicalize: {err}", vector.name));
        let canonical_text = String::from_utf8(canonical).expect("canonical bytes should be utf8");
        assert_eq!(canonical_text, vector.canonical_json, "{}", vector.name);
    }
}
