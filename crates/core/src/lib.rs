pub mod build;
pub mod canon;
pub mod hash;
pub mod merkle;
pub mod schema;
pub mod sign;
pub mod timestamp;
pub mod transparency;
pub mod verify;

pub mod bundle {
    pub use crate::schema::migration::{capture_input_v01_to_event, migrate_v01_to_v10};
    pub use crate::schema::v01::{CaptureInput, Inputs, ModelInfo, Outputs, Trace};
    pub use crate::schema::{
        Actor, ActorRole, ArtefactMeta, ArtefactRef, BUNDLE_ROOT_ALGORITHM, BUNDLE_VERSION,
        BundleValidationError, BundleVerificationError, CANONICALIZATION_ALGORITHM, CaptureEvent,
        EncryptionPolicy, EvidenceBundle as ProofBundle, EvidenceContext, EvidenceItem,
        HASH_ALGORITHM, Integrity, LlmInteractionEvidence, Policy, SIGNATURE_ALGORITHM,
        SIGNATURE_FORMAT, SignatureInfo, Subject, TimestampToken, TransparencyReceipt,
        VerificationSummary, validate_bundle_integrity_fields,
    };
}

pub mod canonicalize {
    pub use crate::canon::*;
}

pub use build::{ArtefactInput, BuildBundleError, BundleBuildInput, build_bundle};
pub use bundle::{
    Actor, ActorRole, ArtefactMeta, ArtefactRef, CaptureEvent, CaptureInput, EncryptionPolicy,
    EvidenceContext, EvidenceItem, Inputs, Integrity, LlmInteractionEvidence, ModelInfo, Outputs,
    Policy, ProofBundle, SignatureInfo, Subject, TimestampToken, Trace, TransparencyReceipt,
    VerificationSummary, validate_bundle_integrity_fields,
};
pub use canon::{CanonError, canonicalize_json_strict, canonicalize_value, parse_json_strict};
pub use hash::{DigestError, parse_sha256_prefixed, sha256_prefixed, sha256_prefixed_file};
pub use merkle::{
    InclusionProof, MerkleCommitment, MerkleError, ProofStep, SiblingPosition,
    build_inclusion_proof, compute_commitment, verify_inclusion_proof,
};
pub use schema::migration::{capture_input_v01_to_event, migrate_v01_to_v10};
pub use schema::v01::{CaptureInput as LegacyCaptureInput, ProofBundle as LegacyProofBundle};
pub use sign::{
    JwsHeader, KeyEncodingError, SignError, decode_private_key_pem, decode_public_key_pem,
    encode_private_key_pem, encode_public_key_pem, sign_bundle_root,
};
pub use timestamp::{
    DIGICERT_TIMESTAMP_URL, FREETSA_TIMESTAMP_URL, RFC3161_TIMESTAMP_KIND,
    Rfc3161HttpTimestampProvider, TimestampError, TimestampProvider, TimestampTrustPolicy,
    TimestampVerification, timestamp_digest, validate_timestamp_trust_policy, verify_timestamp,
    verify_timestamp_with_policy,
};
pub use transparency::{
    REKOR_RFC3161_API_VERSION, REKOR_RFC3161_ENTRY_KIND, REKOR_TRANSPARENCY_KIND,
    ReceiptVerification, RekorTransparencyProvider, SIGSTORE_REKOR_URL, TransparencyEntry,
    TransparencyError, TransparencyProvider, TransparencyTrustPolicy, anchor_bundle,
    validate_transparency_trust_policy, verify_receipt, verify_receipt_with_policy,
};
pub use verify::{VerifyBundleRootError, verify_bundle_root};
