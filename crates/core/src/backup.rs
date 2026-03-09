use base64ct::{Base64, Encoding};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Error as AeadError},
};
use rand::random;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const VAULT_BACKUP_ENVELOPE_FORMAT: &str = "pl-vault-backup-envelope-v1";
pub const VAULT_BACKUP_ENCRYPTION_ALGORITHM: &str = "xchacha20poly1305";
pub const VAULT_BACKUP_ENCRYPTION_KEY_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedVaultBackupEnvelope {
    pub format: String,
    pub encryption: VaultBackupEncryptionMetadata,
    pub ciphertext_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultBackupEncryptionMetadata {
    pub algorithm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub nonce_base64: String,
}

#[derive(Debug, Error)]
pub enum BackupCryptoError {
    #[error("backup encryption key must decode to exactly 32 bytes")]
    InvalidKeyLength,
    #[error("backup encryption key is not valid base64: {0}")]
    InvalidKeyEncoding(String),
    #[error("backup encryption envelope JSON is invalid: {0}")]
    InvalidEnvelopeJson(String),
    #[error("unsupported backup encryption algorithm {0}")]
    UnsupportedAlgorithm(String),
    #[error("backup encryption nonce is invalid")]
    InvalidNonce,
    #[error("backup decryption key is required for encrypted archives")]
    MissingDecryptionKey,
    #[error("backup archive decryption failed")]
    DecryptionFailed,
}

pub fn decode_backup_encryption_key(raw: &str) -> Result<[u8; 32], BackupCryptoError> {
    let decoded = Base64::decode_vec(raw.trim())
        .map_err(|err| BackupCryptoError::InvalidKeyEncoding(err.to_string()))?;
    decoded
        .try_into()
        .map_err(|_| BackupCryptoError::InvalidKeyLength)
}

pub fn encrypt_backup_archive(
    plaintext: &[u8],
    key: &[u8; 32],
    key_id: Option<&str>,
) -> Result<Vec<u8>, BackupCryptoError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| BackupCryptoError::InvalidKeyLength)?;
    let nonce_bytes = random::<[u8; 24]>();
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(map_aead_encrypt_error)?;
    let envelope = EncryptedVaultBackupEnvelope {
        format: VAULT_BACKUP_ENVELOPE_FORMAT.to_string(),
        encryption: VaultBackupEncryptionMetadata {
            algorithm: VAULT_BACKUP_ENCRYPTION_ALGORITHM.to_string(),
            key_id: key_id.map(str::to_string),
            nonce_base64: Base64::encode_string(&nonce_bytes),
        },
        ciphertext_base64: Base64::encode_string(&ciphertext),
    };
    serde_json::to_vec_pretty(&envelope)
        .map_err(|err| BackupCryptoError::InvalidEnvelopeJson(err.to_string()))
}

pub fn decrypt_backup_archive(
    bytes: &[u8],
    key: Option<&[u8; 32]>,
) -> Result<Option<Vec<u8>>, BackupCryptoError> {
    let Some(envelope) = parse_backup_envelope(bytes)? else {
        return Ok(None);
    };
    let key = key.ok_or(BackupCryptoError::MissingDecryptionKey)?;
    if envelope.encryption.algorithm != VAULT_BACKUP_ENCRYPTION_ALGORITHM {
        return Err(BackupCryptoError::UnsupportedAlgorithm(
            envelope.encryption.algorithm,
        ));
    }
    let nonce_bytes = Base64::decode_vec(&envelope.encryption.nonce_base64)
        .map_err(|_| BackupCryptoError::InvalidNonce)?;
    let nonce_array: [u8; 24] = nonce_bytes
        .try_into()
        .map_err(|_| BackupCryptoError::InvalidNonce)?;
    let ciphertext = Base64::decode_vec(&envelope.ciphertext_base64)
        .map_err(|err| BackupCryptoError::InvalidEnvelopeJson(err.to_string()))?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| BackupCryptoError::InvalidKeyLength)?;
    cipher
        .decrypt(XNonce::from_slice(&nonce_array), ciphertext.as_ref())
        .map(Some)
        .map_err(map_aead_decrypt_error)
}

pub fn parse_backup_envelope(
    bytes: &[u8],
) -> Result<Option<EncryptedVaultBackupEnvelope>, BackupCryptoError> {
    let envelope = match serde_json::from_slice::<EncryptedVaultBackupEnvelope>(bytes) {
        Ok(envelope) => envelope,
        Err(_) => return Ok(None),
    };
    if envelope.format != VAULT_BACKUP_ENVELOPE_FORMAT {
        return Ok(None);
    }
    Ok(Some(envelope))
}

fn map_aead_encrypt_error(_: AeadError) -> BackupCryptoError {
    BackupCryptoError::DecryptionFailed
}

fn map_aead_decrypt_error(_: AeadError) -> BackupCryptoError {
    BackupCryptoError::DecryptionFailed
}

#[cfg(test)]
mod tests {
    use super::{
        BackupCryptoError, VAULT_BACKUP_ENCRYPTION_ALGORITHM, decode_backup_encryption_key,
        decrypt_backup_archive, encrypt_backup_archive, parse_backup_envelope,
    };
    use base64ct::{Base64, Encoding};

    #[test]
    fn backup_archive_encryption_round_trips() {
        let key = [7_u8; 32];
        let plaintext = b"proof-layer-backup";

        let encrypted = encrypt_backup_archive(plaintext, &key, Some("backup-key-01")).unwrap();
        let decrypted = decrypt_backup_archive(&encrypted, Some(&key))
            .unwrap()
            .unwrap();

        assert_eq!(decrypted, plaintext);
        let envelope = parse_backup_envelope(&encrypted).unwrap().unwrap();
        assert_eq!(
            envelope.encryption.algorithm,
            VAULT_BACKUP_ENCRYPTION_ALGORITHM
        );
        assert_eq!(envelope.encryption.key_id.as_deref(), Some("backup-key-01"));
    }

    #[test]
    fn decrypt_backup_archive_returns_none_for_plain_archives() {
        let decrypted = decrypt_backup_archive(b"not-json", None).unwrap();
        assert!(decrypted.is_none());
    }

    #[test]
    fn decrypt_backup_archive_rejects_missing_key() {
        let key = [9_u8; 32];
        let encrypted = encrypt_backup_archive(b"backup", &key, None).unwrap();
        let err = decrypt_backup_archive(&encrypted, None).unwrap_err();
        assert!(matches!(err, BackupCryptoError::MissingDecryptionKey));
    }

    #[test]
    fn decrypt_backup_archive_rejects_wrong_key() {
        let encrypted = encrypt_backup_archive(b"backup", &[3_u8; 32], None).unwrap();
        let err = decrypt_backup_archive(&encrypted, Some(&[4_u8; 32])).unwrap_err();
        assert!(matches!(err, BackupCryptoError::DecryptionFailed));
    }

    #[test]
    fn decode_backup_encryption_key_requires_32_bytes() {
        let err = decode_backup_encryption_key(&Base64::encode_string(b"short")).unwrap_err();
        assert!(matches!(err, BackupCryptoError::InvalidKeyLength));
    }
}
