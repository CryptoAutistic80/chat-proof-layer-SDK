use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};
use thiserror::Error;

pub const SHA256_PREFIX: &str = "sha256:";

#[derive(Debug, Error)]
pub enum DigestError {
    #[error("digest must start with 'sha256:'")]
    InvalidPrefix,
    #[error("digest hex must be exactly 64 characters")]
    InvalidLength,
    #[error("digest hex is invalid: {0}")]
    InvalidHex(String),
}

pub fn sha256_prefixed(bytes: &[u8]) -> String {
    let digest = sha256_raw(bytes);
    format_sha256_prefixed_digest(&digest)
}

pub fn format_sha256_prefixed_digest(bytes: &[u8]) -> String {
    format!("{SHA256_PREFIX}{}", hex::encode(bytes))
}

pub fn sha256_prefixed_file(path: &Path) -> Result<String, io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8 * 1024];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(format!("{SHA256_PREFIX}{}", hex::encode(hasher.finalize())))
}

pub fn parse_sha256_prefixed(digest: &str) -> Result<[u8; 32], DigestError> {
    let value = digest
        .strip_prefix(SHA256_PREFIX)
        .ok_or(DigestError::InvalidPrefix)?;

    if value.len() != 64 {
        return Err(DigestError::InvalidLength);
    }

    let bytes = hex::decode(value).map_err(|err| DigestError::InvalidHex(err.to_string()))?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| DigestError::InvalidLength)?;
    Ok(array)
}

pub fn sha256_raw(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    digest.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixed_digest_round_trip() {
        let digest = sha256_prefixed(b"abc");
        let parsed = parse_sha256_prefixed(&digest).expect("digest should parse");
        assert_eq!(hex::encode(parsed), &digest[SHA256_PREFIX.len()..]);
    }

    #[test]
    fn invalid_prefix_rejected() {
        let err = parse_sha256_prefixed("sha1:1234").expect_err("invalid prefix should fail");
        assert!(matches!(err, DigestError::InvalidPrefix));
    }
}
