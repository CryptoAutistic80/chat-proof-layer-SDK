pub mod build;
pub mod bundle;
pub mod canonicalize;
pub mod hash;
pub mod merkle;
pub mod sign;
pub mod verify;

pub use build::{ArtefactInput, BuildBundleError, build_bundle};
pub use bundle::{
    Actor, ArtefactMeta, CaptureInput, EncryptionPolicy, Integrity, ModelInfo, Outputs, Policy,
    ProofBundle, SignatureInfo, Subject, Trace, VerificationSummary,
    validate_bundle_integrity_fields,
};
pub use canonicalize::{
    CanonError, canonicalize_json_strict, canonicalize_value, parse_json_strict,
};
pub use hash::{DigestError, parse_sha256_prefixed, sha256_prefixed, sha256_prefixed_file};
pub use merkle::{MerkleCommitment, MerkleError, compute_commitment};
pub use sign::{
    JwsHeader, KeyEncodingError, SignError, decode_private_key_pem, decode_public_key_pem,
    encode_private_key_pem, encode_public_key_pem, sign_bundle_root,
};
pub use verify::{VerifyBundleRootError, verify_bundle_root};
