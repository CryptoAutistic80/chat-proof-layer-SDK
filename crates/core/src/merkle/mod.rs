use crate::hash::{
    DigestError, format_sha256_prefixed_digest, parse_sha256_prefixed, sha256_prefixed, sha256_raw,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MERKLE_ALGORITHM: &str = "pl-merkle-sha256-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleCommitment {
    pub algorithm: String,
    pub root: String,
    pub leaves: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SiblingPosition {
    Left,
    Right,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: String,
    pub position: SiblingPosition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionProof {
    pub algorithm: String,
    pub root: String,
    pub leaf: String,
    pub index: usize,
    pub path: Vec<ProofStep>,
}

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("cannot compute commitment for empty digest list")]
    Empty,
    #[error("invalid digest at index {index}: {source}")]
    InvalidDigest { index: usize, source: DigestError },
    #[error("proof index {index} is out of bounds for {len} leaves")]
    IndexOutOfBounds { index: usize, len: usize },
}

pub fn compute_commitment(digests: &[String]) -> Result<MerkleCommitment, MerkleError> {
    if digests.is_empty() {
        return Err(MerkleError::Empty);
    }

    let leaf_hashes = leaf_hashes(digests)?;
    let root = root_hash(leaf_hashes);

    Ok(MerkleCommitment {
        algorithm: MERKLE_ALGORITHM.to_owned(),
        root: sha256_prefixed(&root),
        leaves: digests.to_vec(),
    })
}

pub fn build_inclusion_proof(
    digests: &[String],
    index: usize,
) -> Result<InclusionProof, MerkleError> {
    if digests.is_empty() {
        return Err(MerkleError::Empty);
    }
    if index >= digests.len() {
        return Err(MerkleError::IndexOutOfBounds {
            index,
            len: digests.len(),
        });
    }

    let mut current_level = leaf_hashes(digests)?;
    let root = sha256_prefixed(&root_hash(current_level.clone()));
    let mut proof_index = index;
    let mut path = Vec::new();

    while current_level.len() > 1 {
        if current_level.len() % 2 == 1 {
            let last = current_level.last().cloned().expect("non-empty level");
            current_level.push(last);
        }

        let is_left = proof_index.is_multiple_of(2);
        let sibling_index = if is_left {
            proof_index + 1
        } else {
            proof_index - 1
        };
        let sibling = current_level[sibling_index];
        path.push(ProofStep {
            sibling: format_sha256_prefixed_digest(&sibling),
            position: if is_left {
                SiblingPosition::Right
            } else {
                SiblingPosition::Left
            },
        });

        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for pair in current_level.chunks_exact(2) {
            next_level.push(parent_hash(&pair[0], &pair[1]));
        }

        proof_index /= 2;
        current_level = next_level;
    }

    Ok(InclusionProof {
        algorithm: MERKLE_ALGORITHM.to_string(),
        root,
        leaf: digests[index].clone(),
        index,
        path,
    })
}

pub fn verify_inclusion_proof(proof: &InclusionProof) -> Result<bool, MerkleError> {
    if proof.algorithm != MERKLE_ALGORITHM {
        return Ok(false);
    }

    let mut current = leaf_hash(&proof.leaf, proof.index)?;
    for step in &proof.path {
        let sibling =
            parse_sha256_prefixed(&step.sibling).map_err(|source| MerkleError::InvalidDigest {
                index: proof.index,
                source,
            })?;
        current = match step.position {
            SiblingPosition::Left => parent_hash(&sibling, &current),
            SiblingPosition::Right => parent_hash(&current, &sibling),
        };
    }

    Ok(sha256_prefixed(&current) == proof.root)
}

fn leaf_hashes(digests: &[String]) -> Result<Vec<[u8; 32]>, MerkleError> {
    digests
        .iter()
        .enumerate()
        .map(|(index, digest)| leaf_hash(digest, index))
        .collect()
}

fn leaf_hash(digest: &str, index: usize) -> Result<[u8; 32], MerkleError> {
    let bytes = parse_sha256_prefixed(digest)
        .map_err(|source| MerkleError::InvalidDigest { index, source })?;
    let mut leaf_input = Vec::with_capacity(1 + bytes.len());
    leaf_input.push(0x00);
    leaf_input.extend_from_slice(&bytes);
    Ok(sha256_raw(&leaf_input))
}

fn root_hash(mut current_level: Vec<[u8; 32]>) -> [u8; 32] {
    while current_level.len() > 1 {
        if current_level.len() % 2 == 1 {
            let last = current_level.last().copied().expect("non-empty level");
            current_level.push(last);
        }

        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for pair in current_level.chunks_exact(2) {
            next_level.push(parent_hash(&pair[0], &pair[1]));
        }
        current_level = next_level;
    }

    current_level[0]
}

fn parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut parent_input = Vec::with_capacity(1 + left.len() + right.len());
    parent_input.push(0x01);
    parent_input.extend_from_slice(left);
    parent_input.extend_from_slice(right);
    sha256_raw(&parent_input)
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

    #[test]
    fn inclusion_proof_round_trip() {
        let leaves = vec![
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        ];

        let proof = build_inclusion_proof(&leaves, 1).expect("proof should build");
        assert!(verify_inclusion_proof(&proof).expect("proof should verify"));
        assert_eq!(
            proof.root,
            compute_commitment(&leaves)
                .expect("commitment should build")
                .root
        );
    }
}
