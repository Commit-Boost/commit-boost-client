use alloy::primitives::B256;

use crate::{constraints::ConstraintsMessageWithTxs, types::InclusionProofs};

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("Leaves and indices length mismatch")]
    LengthMismatch,
    #[error("Mismatch in provided leaves and leaves to prove")]
    LeavesMismatch,
    #[error("Proof verification failed")]
    VerificationFailed,
}

/// Returns the length of the leaves that need to be proven (i.e. all transactions).
fn total_leaves(constraints: &[ConstraintsMessageWithTxs]) -> usize {
    constraints.iter().map(|c| c.transactions.len()).sum()
}

pub fn verify_multiproofs(
    constraints: &[ConstraintsMessageWithTxs],
    proofs: &InclusionProofs,
    root: B256,
) -> Result<(), ProofError> {
    // TODO: consolidate proof check with error variants
    if proofs.transaction_hashes.len() != proofs.generalized_indeces.len() {
        return Err(ProofError::LengthMismatch);
    }

    let total_leaves = total_leaves(&constraints);

    // TODO: consolidate proof check with error variants
    // Check if the total leaves matches the proofs provided
    if total_leaves != proofs.total_leaves() {
        return Err(ProofError::LeavesMismatch);
    }

    ssz_rs::multiproofs::verify_merkle_multiproof(leaves, &proofs.merkle_hashes, indices, root)
        .map_err(|_| ProofError::VerificationFailed)?;

    Ok(())
}
