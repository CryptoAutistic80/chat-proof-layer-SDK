use crate::hash::{DigestError, parse_sha256_prefixed, sha256_prefixed, sha256_raw};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MERKLE_ALGORITHM: &str = "pl-merkle-sha256-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleCommitment {
    pub algorithm: String,
    pub root: String,
    pub leaves: Vec<String>,
}

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("cannot compute commitment for empty digest list")]
    Empty,
    #[error("invalid digest at index {index}: {source}")]
    InvalidDigest { index: usize, source: DigestError },
}

pub fn compute_commitment(digests: &[String]) -> Result<MerkleCommitment, MerkleError> {
    if digests.is_empty() {
        return Err(MerkleError::Empty);
    }

    let mut current_level = Vec::with_capacity(digests.len());
    for (index, digest) in digests.iter().enumerate() {
        let bytes = parse_sha256_prefixed(digest)
            .map_err(|source| MerkleError::InvalidDigest { index, source })?;

        let mut leaf_input = Vec::with_capacity(1 + bytes.len());
        leaf_input.push(0x00);
        leaf_input.extend_from_slice(&bytes);
        current_level.push(sha256_raw(&leaf_input).to_vec());
    }

    while current_level.len() > 1 {
        if current_level.len() % 2 == 1 {
            let last = current_level.last().cloned().expect("non-empty level");
            current_level.push(last);
        }

        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for pair in current_level.chunks_exact(2) {
            let mut parent_input = Vec::with_capacity(1 + pair[0].len() + pair[1].len());
            parent_input.push(0x01);
            parent_input.extend_from_slice(&pair[0]);
            parent_input.extend_from_slice(&pair[1]);
            next_level.push(sha256_raw(&parent_input).to_vec());
        }
        current_level = next_level;
    }

    let root = sha256_prefixed(&current_level[0]);
    Ok(MerkleCommitment {
        algorithm: MERKLE_ALGORITHM.to_owned(),
        root,
        leaves: digests.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_is_deterministic() {
        let leaves = vec![
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ];

        let one = compute_commitment(&leaves).expect("commitment should succeed");
        let two = compute_commitment(&leaves).expect("commitment should succeed");

        assert_eq!(one.root, two.root);
        assert_eq!(one.algorithm, MERKLE_ALGORITHM);
    }

    #[test]
    fn malformed_digest_fails() {
        let leaves = vec!["sha256:zz".to_string()];
        let err = compute_commitment(&leaves).expect_err("invalid digest should fail");
        assert!(matches!(err, MerkleError::InvalidDigest { .. }));
    }
}
