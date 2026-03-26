use alloy::{eips::eip7594::CELLS_PER_EXT_BLOB, primitives::B256};
use cb_common::pbs::{
    BlobsBundle, ForkName, ForkVersionDecode, KzgCommitments, PayloadAndBlobs,
    SubmitBlindedBlockResponse,
    error::{PbsError, ValidationError},
};
use serde::Deserialize;

/// Decode a JSON-encoded submit_block response
pub fn decode_json_payload(response_bytes: &[u8]) -> Result<SubmitBlindedBlockResponse, PbsError> {
    match serde_json::from_slice::<SubmitBlindedBlockResponse>(response_bytes) {
        Ok(parsed) => Ok(parsed),
        Err(err) => Err(PbsError::JsonDecode {
            err,
            raw: String::from_utf8_lossy(response_bytes).into_owned(),
        }),
    }
}

/// Get the fork name from a submit_block JSON response (used for light
/// processing)
pub fn get_light_info_from_json(response_bytes: &[u8]) -> Result<ForkName, PbsError> {
    #[derive(Deserialize)]
    struct LightVersionOnly {
        version: ForkName,
    }

    match serde_json::from_slice::<LightVersionOnly>(response_bytes) {
        Ok(parsed) => Ok(parsed.version),
        Err(err) => Err(PbsError::JsonDecode {
            err,
            raw: String::from_utf8_lossy(response_bytes).into_owned(),
        }),
    }
}

/// Decode an SSZ-encoded submit_block response
pub fn decode_ssz_payload(
    response_bytes: &[u8],
    fork: ForkName,
) -> Result<SubmitBlindedBlockResponse, PbsError> {
    let data = PayloadAndBlobs::from_ssz_bytes_by_fork(response_bytes, fork).map_err(|e| {
        PbsError::RelayResponse {
            error_msg: (format!("error decoding relay payload: {e:?}")).to_string(),
            code: 200,
        }
    })?;
    Ok(SubmitBlindedBlockResponse { version: fork, data, metadata: Default::default() })
}

pub fn validate_unblinded_block(
    expected_block_hash: B256,
    got_block_hash: B256,
    expected_commitments: &KzgCommitments,
    blobs_bundle: &BlobsBundle,
    fork_name: ForkName,
) -> Result<(), PbsError> {
    match fork_name {
        ForkName::Base |
        ForkName::Altair |
        ForkName::Bellatrix |
        ForkName::Capella |
        ForkName::Deneb |
        ForkName::Gloas => Err(PbsError::Validation(ValidationError::UnsupportedFork)),
        ForkName::Electra => validate_unblinded_block_electra(
            expected_block_hash,
            got_block_hash,
            expected_commitments,
            blobs_bundle,
        ),
        ForkName::Fulu => validate_unblinded_block_fulu(
            expected_block_hash,
            got_block_hash,
            expected_commitments,
            blobs_bundle,
        ),
    }
}

pub fn validate_unblinded_block_electra(
    expected_block_hash: B256,
    got_block_hash: B256,
    expected_commitments: &KzgCommitments,
    blobs_bundle: &BlobsBundle,
) -> Result<(), PbsError> {
    validate_unblinded_block_inner(
        expected_block_hash,
        got_block_hash,
        expected_commitments,
        blobs_bundle,
        expected_commitments.len(),
    )
}

pub fn validate_unblinded_block_fulu(
    expected_block_hash: B256,
    got_block_hash: B256,
    expected_commitments: &KzgCommitments,
    blobs_bundle: &BlobsBundle,
) -> Result<(), PbsError> {
    validate_unblinded_block_inner(
        expected_block_hash,
        got_block_hash,
        expected_commitments,
        blobs_bundle,
        expected_commitments.len() * CELLS_PER_EXT_BLOB,
    )
}

pub fn validate_unblinded_block_inner(
    expected_block_hash: B256,
    got_block_hash: B256,
    expected_commitments: &KzgCommitments,
    blobs_bundle: &BlobsBundle,
    expected_proof_count: usize,
) -> Result<(), PbsError> {
    if expected_block_hash != got_block_hash {
        return Err(PbsError::Validation(ValidationError::BlockHashMismatch {
            expected: expected_block_hash,
            got: got_block_hash,
        }));
    }

    if expected_commitments.len() != blobs_bundle.blobs.len() ||
        expected_commitments.len() != blobs_bundle.commitments.len() ||
        expected_proof_count != blobs_bundle.proofs.len()
    {
        return Err(PbsError::Validation(ValidationError::KzgCommitments {
            expected_blobs: expected_commitments.len(),
            got_blobs: blobs_bundle.blobs.len(),
            got_commitments: blobs_bundle.commitments.len(),
            got_proofs: blobs_bundle.proofs.len(),
        }));
    }

    for (i, comm) in expected_commitments.iter().enumerate() {
        // this is safe since we already know they are the same length
        if *comm != blobs_bundle.commitments[i] {
            return Err(PbsError::Validation(ValidationError::KzgMismatch {
                expected: format!("{comm}"),
                got: format!("{}", blobs_bundle.commitments[i]),
                index: i,
            }));
        }
    }

    Ok(())
}
