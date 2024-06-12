use std::{sync::Arc, time::Duration};

use cb_common::{
    config::BuilderConfig,
    pbs::{RelayEntry, HEADER_START_TIME_UNIX_MS},
    utils::utcnow_ms,
};
use futures::future::select_ok;

use crate::{
    error::{PbsError, ValidationError},
    state::{BuilderApiState, BuilderState},
    types::{SignedBlindedBeaconBlock, SubmitBlindedBlockResponse},
};

pub async fn submit_block<S: BuilderApiState>(
    signed_blinded_block: SignedBlindedBeaconBlock,
    pbs_state: BuilderState<S>,
) -> eyre::Result<SubmitBlindedBlockResponse> {
    let relays = pbs_state.relays();
    let mut handles = Vec::with_capacity(relays.len());

    for relay in relays.iter() {
        let handle = send_submit_block(
            relay.clone(),
            signed_blinded_block.clone(),
            pbs_state.config.clone(),
        );

        handles.push(Box::pin(handle));
    }

    let results = select_ok(handles).await;

    match results {
        Ok((res, _)) => Ok(res),
        Err(err) => Err(err.into()),
    }
}

// submits blinded signed block and expects the execution payload + blobs bundle back
async fn send_submit_block(
    relay: RelayEntry,
    signed_blinded_block: SignedBlindedBeaconBlock,
    config: Arc<BuilderConfig>,
) -> Result<SubmitBlindedBlockResponse, PbsError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_get_payload_ms))
        .build()?;
    let url = relay.submit_block_url();

    // TODO: add user agent, pass headers
    let res = client
        .post(url)
        // .header(HEADER_KEY_SLOT_UUID, slot_uuid.to_string())
        .header(HEADER_START_TIME_UNIX_MS, utcnow_ms())
        .json(&signed_blinded_block) // can probably serialize once and pass from above
        .send()
        .await?;

    let status = res.status();
    let response_bytes = res.bytes().await?;

    if !status.is_success() {
        return Err(PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: status.as_u16(),
        })
    };

    let block_response: SubmitBlindedBlockResponse = serde_json::from_slice(&response_bytes)?;

    if signed_blinded_block.block_hash() != block_response.block_hash() {
        return Err(PbsError::Validation(ValidationError::BlockHashMismatch {
            expected: signed_blinded_block.block_hash(),
            got: block_response.block_hash(),
        }))
    }

    if let Some(blobs) = &block_response.data.blobs_bundle {
        let expected_committments = &signed_blinded_block.message.body.blob_kzg_commitments;
        if expected_committments.len() != blobs.blobs.len() ||
            expected_committments.len() != blobs.commitments.len() ||
            expected_committments.len() != blobs.proofs.len()
        {
            return Err(PbsError::Validation(ValidationError::KzgCommitments {
                expected_blobs: expected_committments.len(),
                got_blobs: blobs.blobs.len(),
                got_commitments: blobs.commitments.len(),
                got_proofs: blobs.proofs.len(),
            }))
        }

        for (i, comm) in expected_committments.iter().enumerate() {
            // this is safe since we already know they are the same length
            if *comm != blobs.commitments[i] {
                return Err(PbsError::Validation(ValidationError::KzgMismatch {
                    expected: format!("{comm}"),
                    got: format!("{}", blobs.commitments[i]),
                    index: i,
                }))
            }
        }
    }

    Ok(block_response)
}
