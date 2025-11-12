use std::{
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::{eips::eip7594::CELLS_PER_EXT_BLOB, primitives::B256};
use axum::http::{HeaderMap, HeaderValue};
use cb_common::{
    pbs::{
        BlindedBeaconBlock, BlobsBundle, BuilderApiVersion, ForkName, ForkVersionDecode,
        HEADER_CONSENSUS_VERSION, HEADER_START_TIME_UNIX_MS, KzgCommitments, PayloadAndBlobs,
        RelayClient, SignedBlindedBeaconBlock, SubmitBlindedBlockResponse,
        error::{PbsError, ValidationError},
    },
    utils::{
        EncodingType, get_accept_types, get_content_type, get_user_agent_with_version,
        read_chunked_body_with_max, utcnow_ms,
    },
};
use futures::{FutureExt, future::select_ok};
use reqwest::{
    Response, StatusCode,
    header::{ACCEPT, CONTENT_TYPE, USER_AGENT},
};
use ssz::Encode;
use tracing::{debug, warn};
use url::Url;

use crate::{
    TIMEOUT_ERROR_CODE_STR,
    constants::{MAX_SIZE_SUBMIT_BLOCK_RESPONSE, SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG},
    metrics::{RELAY_LATENCY, RELAY_STATUS_CODE},
    state::{BuilderApiState, PbsState},
};

/// Implements https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock and
/// https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlockV2. Use `api_version` to
/// distinguish between the two.
pub async fn submit_block<S: BuilderApiState>(
    signed_blinded_block: Arc<SignedBlindedBeaconBlock>,
    req_headers: HeaderMap,
    state: PbsState<S>,
    api_version: BuilderApiVersion,
) -> eyre::Result<Option<SubmitBlindedBlockResponse>> {
    debug!(?req_headers, "received headers");

    let fork_name = req_headers
        .get(HEADER_CONSENSUS_VERSION)
        .and_then(|h| {
            let str = h.to_str().ok()?;
            ForkName::from_str(str).ok()
        })
        .unwrap_or_else(|| {
            let slot = signed_blinded_block.slot().as_u64();
            state.config.chain.fork_by_slot(slot)
        });

    // safe because ForkName is visible ASCII chars
    let consensus_version = HeaderValue::from_str(&fork_name.to_string()).unwrap();

    // prepare headers
    let mut send_headers = HeaderMap::new();
    send_headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(utcnow_ms()));
    send_headers.insert(USER_AGENT, get_user_agent_with_version(&req_headers)?);
    send_headers.insert(HEADER_CONSENSUS_VERSION, consensus_version);

    // Get the accept types from the request and forward them
    for value in req_headers.get_all(ACCEPT).iter() {
        send_headers.append(ACCEPT, value.clone());
    }

    // Copy the content type header
    send_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(get_content_type(&req_headers).content_type()).unwrap(),
    );

    let mut handles = Vec::with_capacity(state.all_relays().len());
    for relay in state.all_relays().iter().cloned() {
        handles.push(
            tokio::spawn(submit_block_with_timeout(
                signed_blinded_block.clone(),
                relay,
                send_headers.clone(),
                state.pbs_config().timeout_get_payload_ms,
                api_version,
                fork_name,
            ))
            .map(|join_result| match join_result {
                Ok(res) => res,
                Err(err) => Err(PbsError::TokioJoinError(err)),
            }),
        );
    }

    let results = select_ok(handles).await;
    match results {
        Ok((res, _)) => Ok(res),
        Err(err) => Err(err.into()),
    }
}

/// Submit blinded block to relay, retry connection errors until the
/// given timeout has passed
async fn submit_block_with_timeout(
    signed_blinded_block: Arc<SignedBlindedBeaconBlock>,
    relay: RelayClient,
    headers: HeaderMap,
    timeout_ms: u64,
    api_version: BuilderApiVersion,
    fork_name: ForkName,
) -> Result<Option<SubmitBlindedBlockResponse>, PbsError> {
    let mut url = relay.submit_block_url(api_version)?;
    let mut remaining_timeout_ms = timeout_ms;
    let mut retry = 0;
    let mut backoff = Duration::from_millis(250);

    loop {
        let start_request = Instant::now();
        match send_submit_block(
            url.clone(),
            &signed_blinded_block,
            &relay,
            headers.clone(),
            remaining_timeout_ms,
            retry,
            &api_version,
            fork_name,
        )
        .await
        {
            Ok(response) => return Ok(response),

            Err(err) if err.should_retry() => {
                tokio::time::sleep(backoff).await;
                backoff += Duration::from_millis(250);

                remaining_timeout_ms =
                    timeout_ms.saturating_sub(start_request.elapsed().as_millis() as u64);

                if remaining_timeout_ms == 0 {
                    return Err(err);
                }
            }

            Err(err) if err.is_not_found() && matches!(api_version, BuilderApiVersion::V2) => {
                warn!(
                    relay_id = relay.id.as_ref(),
                    "relay does not support v2 endpoint, retrying with v1"
                );
                url = relay.submit_block_url(BuilderApiVersion::V1)?;
            }

            Err(err) => return Err(err),
        };

        retry += 1;
    }
}

// submits blinded signed block and expects the execution payload + blobs bundle
// back
#[allow(clippy::too_many_arguments)]
async fn send_submit_block(
    url: Url,
    signed_blinded_block: &SignedBlindedBeaconBlock,
    relay: &RelayClient,
    headers: HeaderMap,
    timeout_ms: u64,
    retry: u32,
    api_version: &BuilderApiVersion,
    fork_name: ForkName,
) -> Result<Option<SubmitBlindedBlockResponse>, PbsError> {
    let mut original_headers = headers.clone();

    // Check which types this request is for
    let accept_types = get_accept_types(&headers).map_err(|e| {
        PbsError::GeneralRequest(format!("error reading accept types: {e}").to_string())
    })?;
    let accepts_ssz = accept_types.contains(&EncodingType::Ssz);
    let accepts_json = accept_types.contains(&EncodingType::Json);

    // Send the request
    let mut start_request = Instant::now();
    let (mut res, mut content_type) =
        send_submit_block_impl(url.clone(), signed_blinded_block, relay, headers, timeout_ms)
            .await?;
    let mut code = res.status();

    // If the request only supports SSZ, but the relay only supports JSON, resubmit
    // to the relay with JSON - we'll convert it ourselves
    if code == StatusCode::NOT_ACCEPTABLE && accepts_ssz && !accepts_json {
        // TODO: needs to handle the case where the content-type is wrong too
        debug!(
            relay_id = relay.id.as_ref(),
            "relay does not support SSZ, resubmitting request with JSON accept and content-type"
        );

        // Resubmit the request with JSON accept and content-type headers
        let elapsed = start_request.elapsed().as_millis() as u64;
        let json_header_value = HeaderValue::from_str(EncodingType::Json.content_type()).unwrap();
        original_headers.insert(ACCEPT, json_header_value.clone());
        original_headers.insert(CONTENT_TYPE, json_header_value);
        start_request = Instant::now();
        (res, content_type) = send_submit_block_impl(
            url,
            signed_blinded_block,
            relay,
            original_headers,
            timeout_ms - elapsed,
        )
        .await?;
        code = res.status();
    }

    // Get the consensus fork version if provided (to avoid cloning later)
    let content_type_header = res.headers().get(CONTENT_TYPE).cloned();

    let request_latency = start_request.elapsed();
    RELAY_LATENCY
        .with_label_values(&[SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG, &relay.id])
        .observe(request_latency.as_secs_f64());

    RELAY_STATUS_CODE
        .with_label_values(&[code.as_str(), SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG, &relay.id])
        .inc();

    let response_bytes = read_chunked_body_with_max(res, MAX_SIZE_SUBMIT_BLOCK_RESPONSE).await?;
    if !code.is_success() {
        let err = PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: code.as_u16(),
        };

        // we requested the payload from all relays, but some may have not received it
        warn!(relay_id = relay.id.as_ref(), retry, %err, "failed to get payload (this might be ok if other relays have it)");
        return Err(err);
    };

    if api_version != &BuilderApiVersion::V1 {
        // v2 response is going to be empty, so just break here
        debug!(
            relay_id = relay.id.as_ref(),
            retry,
            latency = ?request_latency,
            "successful request"
        );

        return Ok(None);
    }

    // Regenerate the block from the response
    let block_response = match content_type {
        Some(EncodingType::Ssz) => {
            let data = PayloadAndBlobs::from_ssz_bytes_by_fork(&response_bytes, fork_name)
                .map_err(|e| PbsError::RelayResponse {
                    error_msg: (format!("error decoding relay payload: {e:?}")).to_string(),
                    code: (code.as_u16()),
                })?;
            SubmitBlindedBlockResponse { version: fork_name, data, metadata: Default::default() }
        }
        Some(EncodingType::Json) => {
            match serde_json::from_slice::<SubmitBlindedBlockResponse>(&response_bytes) {
                Ok(parsed) => parsed,
                Err(err) => {
                    return Err(PbsError::JsonDecode {
                        err,
                        raw: String::from_utf8_lossy(&response_bytes).into_owned(),
                    });
                }
            }
        }
        None => {
            let error_msg = match content_type_header {
                None => "relay response missing content type header".to_string(),
                Some(ct) => format!("relay response has unsupported content type {ct:?}"),
            };
            return Err(PbsError::RelayResponse { error_msg, code: code.as_u16() });
        }
    };

    debug!(
        relay_id = relay.id.as_ref(),
        retry,
        latency = ?request_latency,
        version =% block_response.version,
        "received unblinded block"
    );

    let got_block_hash = block_response.data.execution_payload.block_hash().0;

    // request has different type so cant be deserialized in the wrong version,
    // response has a "version" field
    match &signed_blinded_block.message() {
        BlindedBeaconBlock::Electra(blinded_block) => {
            let expected_block_hash =
                blinded_block.body.execution_payload.execution_payload_header.block_hash.0;
            let expected_commitments = &blinded_block.body.blob_kzg_commitments;

            validate_unblinded_block(
                expected_block_hash,
                got_block_hash,
                expected_commitments,
                &block_response.data.blobs_bundle,
                fork_name,
            )
        }

        BlindedBeaconBlock::Fulu(blinded_block) => {
            let expected_block_hash =
                blinded_block.body.execution_payload.execution_payload_header.block_hash.0;
            let expected_commitments = &blinded_block.body.blob_kzg_commitments;

            validate_unblinded_block(
                expected_block_hash,
                got_block_hash,
                expected_commitments,
                &block_response.data.blobs_bundle,
                fork_name,
            )
        }

        _ => return Err(PbsError::Validation(ValidationError::UnsupportedFork)),
    }?;

    Ok(Some(block_response))
}

async fn send_submit_block_impl(
    url: Url,
    signed_blinded_block: &SignedBlindedBeaconBlock,
    relay: &RelayClient,
    headers: HeaderMap,
    timeout_ms: u64,
) -> Result<(Response, Option<EncodingType>), PbsError> {
    // Get the content type of the request
    let content_type = get_content_type(&headers);

    // Send the request
    let res = relay.client.post(url).timeout(Duration::from_millis(timeout_ms)).headers(headers);
    let body = match content_type {
        EncodingType::Json => serde_json::to_vec(&signed_blinded_block).unwrap(),
        EncodingType::Ssz => signed_blinded_block.as_ssz_bytes(),
    };
    let res = match res.body(body).header(CONTENT_TYPE, &content_type.to_string()).send().await {
        Ok(res) => res,
        Err(err) => {
            RELAY_STATUS_CODE
                .with_label_values(&[
                    TIMEOUT_ERROR_CODE_STR,
                    SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG,
                    &relay.id,
                ])
                .inc();
            return Err(err.into());
        }
    };

    // Get the content type; this is only really useful for OK responses, and
    // doesn't handle encoding types besides SSZ and JSON
    let mut content_type: Option<EncodingType> = None;
    if res.status() == StatusCode::OK &&
        let Some(header) = res.headers().get(CONTENT_TYPE)
    {
        let header_str = header.to_str().map_err(|e| PbsError::RelayResponse {
            error_msg: format!("cannot decode content-type header: {e}").to_string(),
            code: (res.status().as_u16()),
        })?;
        if header_str.eq_ignore_ascii_case(&EncodingType::Ssz.to_string()) {
            content_type = Some(EncodingType::Ssz)
        } else if header_str.eq_ignore_ascii_case(&EncodingType::Json.to_string()) {
            content_type = Some(EncodingType::Json)
        }
    }
    Ok((res, content_type))
}

fn validate_unblinded_block(
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

fn validate_unblinded_block_electra(
    expected_block_hash: B256,
    got_block_hash: B256,
    expected_commitments: &KzgCommitments,
    blobs_bundle: &BlobsBundle,
) -> Result<(), PbsError> {
    if expected_block_hash != got_block_hash {
        return Err(PbsError::Validation(ValidationError::BlockHashMismatch {
            expected: expected_block_hash,
            got: got_block_hash,
        }));
    }

    if expected_commitments.len() != blobs_bundle.blobs.len() ||
        expected_commitments.len() != blobs_bundle.commitments.len() ||
        expected_commitments.len() != blobs_bundle.proofs.len()
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

fn validate_unblinded_block_fulu(
    expected_block_hash: B256,
    got_block_hash: B256,
    expected_commitments: &KzgCommitments,
    blobs_bundle: &BlobsBundle,
) -> Result<(), PbsError> {
    if expected_block_hash != got_block_hash {
        return Err(PbsError::Validation(ValidationError::BlockHashMismatch {
            expected: expected_block_hash,
            got: got_block_hash,
        }));
    }

    if expected_commitments.len() != blobs_bundle.blobs.len() ||
        expected_commitments.len() != blobs_bundle.commitments.len() ||
        expected_commitments.len() * CELLS_PER_EXT_BLOB != blobs_bundle.proofs.len()
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
