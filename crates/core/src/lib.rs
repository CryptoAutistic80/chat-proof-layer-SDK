pub mod backup;
pub mod build;
pub mod canon;
pub mod disclosure;
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
        Actor, ActorRole, ArtefactMeta, ArtefactRef, BUNDLE_ROOT_ALGORITHM,
        BUNDLE_ROOT_ALGORITHM_V2, BUNDLE_ROOT_ALGORITHM_V3, BUNDLE_ROOT_ALGORITHM_V4,
        BUNDLE_VERSION, BundleValidationError, BundleVerificationError, CANONICALIZATION_ALGORITHM,
        CaptureEvent, EncryptionPolicy, EvidenceBundle as ProofBundle, EvidenceContext,
        EvidenceItem, HASH_ALGORITHM, Integrity, LEGACY_BUNDLE_ROOT_ALGORITHM,
        LlmInteractionEvidence, Policy, SIGNATURE_ALGORITHM, SIGNATURE_FORMAT, SignatureInfo,
        Subject, TimestampToken, TransparencyReceipt, VerificationSummary,
        validate_bundle_integrity_fields,
    };
}

pub mod canonicalize {
    pub use crate::canon::*;
}

pub use backup::{
    BackupCryptoError, EncryptedVaultBackupEnvelope, VAULT_BACKUP_ENCRYPTION_ALGORITHM,
    VAULT_BACKUP_ENCRYPTION_KEY_LENGTH, VAULT_BACKUP_ENVELOPE_FORMAT,
    VaultBackupEncryptionMetadata, decode_backup_encryption_key, decrypt_backup_archive,
    encrypt_backup_archive, parse_backup_envelope,
};
pub use build::{ArtefactInput, BuildBundleError, BundleBuildInput, build_bundle};
pub use bundle::{
    Actor, ActorRole, ArtefactMeta, ArtefactRef, CaptureEvent, CaptureInput, EncryptionPolicy,
    EvidenceContext, EvidenceItem, Inputs, Integrity, LlmInteractionEvidence, ModelInfo, Outputs,
    Policy, ProofBundle, SignatureInfo, Subject, TimestampToken, Trace, TransparencyReceipt,
    VerificationSummary, validate_bundle_integrity_fields,
};
pub use canon::{CanonError, canonicalize_json_strict, canonicalize_value, parse_json_strict};
pub use disclosure::{
    DisclosedArtefact, DisclosedItem, DisclosureError, FieldRedactedItem, RedactedBundle,
    RedactedVerificationSummary, redact_bundle, redact_bundle_with_field_redactions,
    verify_redacted_bundle,
};
pub use hash::{DigestError, parse_sha256_prefixed, sha256_prefixed, sha256_prefixed_file};
pub use merkle::{
    InclusionProof, MerkleCommitment, MerkleError, ProofStep, SiblingPosition,
    build_inclusion_proof, compute_commitment, verify_inclusion_proof,
};
pub use schema::migration::{capture_input_v01_to_event, migrate_v01_to_v10};
pub use schema::v01::{CaptureInput as LegacyCaptureInput, ProofBundle as LegacyProofBundle};
pub use schema::{
    BUNDLE_ROOT_ALGORITHM_V2, BUNDLE_ROOT_ALGORITHM_V3, BUNDLE_ROOT_ALGORITHM_V4,
    LEGACY_BUNDLE_ROOT_ALGORITHM, artefact_commitment_digest, field_commitment_digest,
    item_commitment_digest, item_commitment_digest_for_algorithm,
    item_commitment_digest_from_fields, item_commitment_digest_from_paths,
    item_field_commitment_digests, item_path_commitment_digests,
};
pub use sign::{
    JwsHeader, KeyEncodingError, SignError, decode_private_key_pem, decode_public_key_pem,
    encode_private_key_pem, encode_public_key_pem, sign_bundle_root,
};
pub use timestamp::{
    DIGICERT_TIMESTAMP_URL, FREETSA_TIMESTAMP_URL, RFC3161_TIMESTAMP_KIND,
    Rfc3161HttpTimestampProvider, TimestampAssuranceProfile, TimestampError, TimestampProvider,
    TimestampTrustPolicy, TimestampVerification, timestamp_digest, validate_timestamp_trust_policy,
    verify_timestamp, verify_timestamp_with_policy,
};
pub use transparency::{
    REKOR_RFC3161_API_VERSION, REKOR_RFC3161_ENTRY_KIND, REKOR_TRANSPARENCY_KIND,
    ReceiptVerification, RekorTransparencyProvider, SCITT_STATEMENT_PROFILE,
    SCITT_TRANSPARENCY_KIND, SIGSTORE_REKOR_URL, ScittTransparencyProvider, TransparencyEntry,
    TransparencyError, TransparencyProvider, TransparencyTrustPolicy, anchor_bundle,
    validate_transparency_trust_policy, verify_receipt, verify_receipt_with_policy,
};
pub use verify::{VerifyBundleRootError, verify_bundle_root};
