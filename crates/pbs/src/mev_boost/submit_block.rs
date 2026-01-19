use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::{eips::eip7594::CELLS_PER_EXT_BLOB, primitives::B256};
use axum::http::{HeaderMap, HeaderValue};
use cb_common::{
    config::BlockValidationMode,
    pbs::{
        BlindedBeaconBlock, BlobsBundle, BuilderApiVersion, ForkName, ForkVersionDecode,
        HEADER_START_TIME_UNIX_MS, KzgCommitments, PayloadAndBlobs, RelayClient,
        SignedBlindedBeaconBlock, SubmitBlindedBlockResponse,
        error::{PbsError, ValidationError},
    },
    utils::{
        CONSENSUS_VERSION_HEADER, EncodingType, get_consensus_version_header,
        get_user_agent_with_version, read_chunked_body_with_max, utcnow_ms,
    },
};
use futures::{FutureExt, future::select_ok};
use reqwest::{
    StatusCode,
    header::{ACCEPT, CONTENT_TYPE, USER_AGENT},
};
use serde::Deserialize;
use ssz::Encode;
use tracing::{debug, warn};
use url::Url;

use crate::{
    CompoundSubmitBlockResponse, LightSubmitBlockResponse, TIMEOUT_ERROR_CODE_STR,
    constants::{MAX_SIZE_SUBMIT_BLOCK_RESPONSE, SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG},
    metrics::{RELAY_LATENCY, RELAY_STATUS_CODE},
    state::{BuilderApiState, PbsState},
};

/// Info about a proposal submission request.
/// Sent from submit_block to the submit_block_with_timeout function.
#[derive(Clone)]
struct ProposalInfo {
    /// The signed blinded block to submit
    signed_blinded_block: Arc<SignedBlindedBeaconBlock>,

    /// Common baseline of headers to send with each request
    headers: Arc<HeaderMap>,

    /// The version of the submit_block route being used
    api_version: BuilderApiVersion,

    /// How to validate the block returned by the relay
    validation_mode: BlockValidationMode,

    /// The accepted encoding types from the original request
    accepted_types: HashSet<EncodingType>,
}

/// Used interally to provide info and context about a submit_block request and
/// its response
struct SubmitBlockResponseInfo {
    /// The raw body of the response
    response_bytes: Vec<u8>,

    /// The content type the response is encoded with
    content_type: EncodingType,

    /// Which fork the response bid is for (if provided as a header, rather than
    /// part of the body)
    fork: Option<ForkName>,

    /// The status code of the response, for logging
    code: StatusCode,

    /// The round-trip latency of the request
    request_latency: Duration,
}

/// Implements https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock and
/// https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlockV2. Use `api_version` to
/// distinguish between the two.
pub async fn submit_block<S: BuilderApiState>(
    signed_blinded_block: Arc<SignedBlindedBeaconBlock>,
    req_headers: HeaderMap,
    state: PbsState<S>,
    api_version: BuilderApiVersion,
    accepted_types: HashSet<EncodingType>,
) -> eyre::Result<CompoundSubmitBlockResponse> {
    debug!(?req_headers, "received headers");

    // prepare headers
    let mut send_headers = HeaderMap::new();
    send_headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(utcnow_ms()));
    send_headers.insert(USER_AGENT, get_user_agent_with_version(&req_headers)?);

    // Create the Accept headers for requests
    let mode = state.pbs_config().block_validation_mode;
    let accept_types = match mode {
        BlockValidationMode::None => {
            // No validation mode, so only request what the user wants because the response
            // will be forwarded directly
            accepted_types.iter().map(|t| t.content_type()).collect::<Vec<&str>>().join(",")
        }
        _ => {
            // We're unpacking the body, so request both types since we can handle both
            [EncodingType::Ssz.content_type(), EncodingType::Json.content_type()].join(",")
        }
    };
    send_headers.insert(ACCEPT, HeaderValue::from_str(&accept_types).unwrap());

    // Send requests to all relays concurrently
    let proposal_info = Arc::new(ProposalInfo {
        signed_blinded_block,
        headers: Arc::new(send_headers),
        api_version,
        validation_mode: mode,
        accepted_types,
    });
    let mut handles = Vec::with_capacity(state.all_relays().len());
    for relay in state.all_relays().iter() {
        handles.push(
            tokio::spawn(submit_block_with_timeout(
                proposal_info.clone(),
                relay.clone(),
                state.pbs_config().timeout_get_payload_ms,
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
    proposal_info: Arc<ProposalInfo>,
    relay: RelayClient,
    timeout_ms: u64,
) -> Result<CompoundSubmitBlockResponse, PbsError> {
    let mut url = Arc::new(relay.submit_block_url(proposal_info.api_version)?);
    let mut remaining_timeout_ms = timeout_ms;
    let mut retry = 0;
    let mut backoff = Duration::from_millis(250);

    loop {
        let start_request = Instant::now();
        match send_submit_block(
            proposal_info.clone(),
            url.clone(),
            &relay,
            remaining_timeout_ms,
            retry,
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

            Err(err)
                if err.is_not_found() && proposal_info.api_version == BuilderApiVersion::V2 =>
            {
                warn!(
                    relay_id = relay.id.as_ref(),
                    "relay does not support v2 endpoint, retrying with v1"
                );
                url = Arc::new(relay.submit_block_url(BuilderApiVersion::V1)?);
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
    proposal_info: Arc<ProposalInfo>,
    url: Arc<Url>,
    relay: &RelayClient,
    timeout_ms: u64,
    retry: u32,
) -> Result<CompoundSubmitBlockResponse, PbsError> {
    match proposal_info.validation_mode {
        BlockValidationMode::None => {
            // No validation so do some light processing and forward the response directly
            let response =
                send_submit_block_light(proposal_info.clone(), url, relay, timeout_ms, retry)
                    .await?;
            match response {
                None => Ok(CompoundSubmitBlockResponse::EmptyBody),
                Some(res) => {
                    // Make sure the response is encoded in one of the accepted
                    // types since we're passing the raw response directly to the client
                    if !proposal_info.accepted_types.contains(&res.encoding_type) {
                        return Err(PbsError::RelayResponse {
                            error_msg: format!(
                                "relay returned unsupported encoding type for submit_block in no-validation mode: {:?}",
                                res.encoding_type
                            ),
                            code: 406, // Not Acceptable
                        });
                    }
                    Ok(CompoundSubmitBlockResponse::Light(res))
                }
            }
        }
        _ => {
            // Full processing: decode full response and validate
            let response =
                send_submit_block_full(proposal_info.clone(), url, relay, timeout_ms, retry)
                    .await?;
            let response = match response {
                None => {
                    // v2 request with no body
                    return Ok(CompoundSubmitBlockResponse::EmptyBody);
                }
                Some(res) => res,
            };
            // Extract the info needed for validation
            let got_block_hash = response.data.execution_payload.block_hash().0;

            // request has different type so cant be deserialized in the wrong version,
            // response has a "version" field
            match &proposal_info.signed_blinded_block.message() {
                BlindedBeaconBlock::Electra(blinded_block) => {
                    let expected_block_hash =
                        blinded_block.body.execution_payload.execution_payload_header.block_hash.0;
                    let expected_commitments = &blinded_block.body.blob_kzg_commitments;

                    validate_unblinded_block(
                        expected_block_hash,
                        got_block_hash,
                        expected_commitments,
                        &response.data.blobs_bundle,
                        response.version,
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
                        &response.data.blobs_bundle,
                        response.version,
                    )
                }

                _ => return Err(PbsError::Validation(ValidationError::UnsupportedFork)),
            }?;
            Ok(CompoundSubmitBlockResponse::Full(Box::new(response)))
        }
    }
}

/// Send and fully process a submit_block request, returning a complete decoded
/// response
async fn send_submit_block_full(
    proposal_info: Arc<ProposalInfo>,
    url: Arc<Url>,
    relay: &RelayClient,
    timeout_ms: u64,
    retry: u32,
) -> Result<Option<SubmitBlindedBlockResponse>, PbsError> {
    // Send the request
    let block_response = send_submit_block_impl(
        relay,
        url,
        timeout_ms,
        (*proposal_info.headers).clone(),
        &proposal_info.signed_blinded_block,
        retry,
        proposal_info.api_version,
    )
    .await?;

    // If this is not v1, there's no body to decode
    if proposal_info.api_version != BuilderApiVersion::V1 {
        return Ok(None);
    }

    // Decode the payload based on content type
    let decoded_response = match block_response.content_type {
        EncodingType::Json => decode_json_payload(&block_response.response_bytes)?,
        EncodingType::Ssz => {
            let fork = match block_response.fork {
                Some(fork) => fork,
                None => {
                    return Err(PbsError::RelayResponse {
                        error_msg: "missing fork version header in SSZ submit_block response"
                            .to_string(),
                        code: block_response.code.as_u16(),
                    });
                }
            };
            decode_ssz_payload(&block_response.response_bytes, fork)?
        }
    };

    // Log and return
    debug!(
        relay_id = relay.id.as_ref(),
        retry,
        latency = ?block_response.request_latency,
        version =% decoded_response.version,
        "received unblinded block"
    );

    Ok(Some(decoded_response))
}

/// Send and lightly process a submit_block request, minimizing the amount of
/// decoding and validation done
async fn send_submit_block_light(
    proposal_info: Arc<ProposalInfo>,
    url: Arc<Url>,
    relay: &RelayClient,
    timeout_ms: u64,
    retry: u32,
) -> Result<Option<LightSubmitBlockResponse>, PbsError> {
    // Send the request
    let block_response = send_submit_block_impl(
        relay,
        url,
        timeout_ms,
        (*proposal_info.headers).clone(),
        &proposal_info.signed_blinded_block,
        retry,
        proposal_info.api_version,
    )
    .await?;

    // If this is not v1, there's no body to decode
    if proposal_info.api_version != BuilderApiVersion::V1 {
        return Ok(None);
    }

    // Decode the payload based on content type
    let fork = match block_response.content_type {
        EncodingType::Json => get_light_info_from_json(&block_response.response_bytes)?,
        EncodingType::Ssz => match block_response.fork {
            Some(fork) => fork,
            None => {
                return Err(PbsError::RelayResponse {
                    error_msg: "missing fork version header in SSZ submit_block response"
                        .to_string(),
                    code: block_response.code.as_u16(),
                });
            }
        },
    };

    // Log and return
    debug!(
        relay_id = relay.id.as_ref(),
        retry,
        latency = ?block_response.request_latency,
        version =% fork,
        "received unblinded block (light processing)"
    );

    Ok(Some(LightSubmitBlockResponse {
        version: fork,
        encoding_type: block_response.content_type,
        raw_bytes: block_response.response_bytes,
    }))
}

/// Sends the actual HTTP request to the relay's submit_block endpoint,
/// returning the response (if applicable), the round-trip time, and the
/// encoding type used for the body (if any). Used by send_submit_block.
async fn send_submit_block_impl(
    relay: &RelayClient,
    url: Arc<Url>,
    timeout_ms: u64,
    headers: HeaderMap,
    signed_blinded_block: &SignedBlindedBeaconBlock,
    retry: u32,
    api_version: BuilderApiVersion,
) -> Result<SubmitBlockResponseInfo, PbsError> {
    let start_request = Instant::now();

    // Try SSZ first
    let mut res = match relay
        .client
        .post(url.as_ref().clone())
        .timeout(Duration::from_millis(timeout_ms))
        .headers(headers.clone())
        .body(signed_blinded_block.as_ssz_bytes())
        .header(CONTENT_TYPE, EncodingType::Ssz.to_string())
        .header(CONSENSUS_VERSION_HEADER, signed_blinded_block.fork_name_unchecked().to_string())
        .send()
        .await
    {
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

    // If we got a client error, retry with JSON - the spec says that this should be
    // a 406 or 415, but we're a little more permissive here
    if res.status().is_client_error() {
        warn!(
            relay_id = relay.id.as_ref(),
            "relay does not support SSZ, resubmitting block with JSON content-type"
        );
        res = match relay
            .client
            .post(url.as_ref().clone())
            .timeout(Duration::from_millis(timeout_ms))
            .headers(headers)
            .body(serde_json::to_vec(&signed_blinded_block).unwrap())
            .header(CONTENT_TYPE, EncodingType::Json.to_string())
            .send()
            .await
        {
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
    }

    // Log the response code and latency
    let code = res.status();
    let request_latency = start_request.elapsed();
    RELAY_LATENCY
        .with_label_values(&[SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG, &relay.id])
        .observe(request_latency.as_secs_f64());
    RELAY_STATUS_CODE
        .with_label_values(&[code.as_str(), SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG, &relay.id])
        .inc();

    // If this was API v2 and succeeded then we can just return here
    if api_version != BuilderApiVersion::V1 {
        debug!(
            relay_id = relay.id.as_ref(),
            retry,
            latency = ?request_latency,
            "received 202 Accepted for v2 submit_block"
        );

        match code {
            StatusCode::ACCEPTED => {
                return Ok(SubmitBlockResponseInfo {
                    response_bytes: Vec::new(),
                    content_type: EncodingType::Json, // dummy value
                    fork: None,
                    code,
                    request_latency,
                });
            }
            StatusCode::OK => {
                warn!(
                    relay_id = relay.id.as_ref(),
                    "relay sent OK response for v2 submit_block, expected 202 Accepted"
                );
                return Ok(SubmitBlockResponseInfo {
                    response_bytes: Vec::new(),
                    content_type: EncodingType::Json, // dummy value
                    fork: None,
                    code,
                    request_latency,
                });
            }
            _ => {
                return Err(PbsError::RelayResponse {
                    error_msg: format!(
                        "relay sent unexpected code for builder route v2 {}: {code}",
                        relay.id.as_ref()
                    ),
                    code: code.as_u16(),
                });
            }
        }
    }

    // If the code is not OK, return early
    if code != StatusCode::OK {
        let response_bytes =
            read_chunked_body_with_max(res, MAX_SIZE_SUBMIT_BLOCK_RESPONSE).await?;
        let err = PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: code.as_u16(),
        };

        // we requested the payload from all relays, but some may have not received it
        warn!(relay_id = relay.id.as_ref(), %err, "failed to get payload (this might be ok if other relays have it)");
        return Err(err);
    }

    // We're on v1 so decode the payload normally - get the content type
    let content_type = match res.headers().get(CONTENT_TYPE) {
        None => {
            // Assume a missing content type means JSON; shouldn't happen in practice with
            // any respectable HTTP server but just in case
            EncodingType::Json
        }
        Some(header_value) => match header_value.to_str().map_err(|e| PbsError::RelayResponse {
            error_msg: format!("cannot decode content-type header: {e}").to_string(),
            code: (code.as_u16()),
        })? {
            header_str if header_str.eq_ignore_ascii_case(&EncodingType::Ssz.to_string()) => {
                EncodingType::Ssz
            }
            header_str if header_str.eq_ignore_ascii_case(&EncodingType::Json.to_string()) => {
                EncodingType::Json
            }
            header_str => {
                return Err(PbsError::RelayResponse {
                    error_msg: format!("unsupported content type: {header_str}"),
                    code: code.as_u16(),
                })
            }
        },
    };

    // Decode the body
    let fork = get_consensus_version_header(res.headers());
    let response_bytes = read_chunked_body_with_max(res, MAX_SIZE_SUBMIT_BLOCK_RESPONSE).await?;
    Ok(SubmitBlockResponseInfo { response_bytes, content_type, fork, code, request_latency })
}

/// Decode a JSON-encoded submit_block response
fn decode_json_payload(response_bytes: &[u8]) -> Result<SubmitBlindedBlockResponse, PbsError> {
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
fn get_light_info_from_json(response_bytes: &[u8]) -> Result<ForkName, PbsError> {
    #[derive(Deserialize)]
    struct LightSubmitBlockResponse {
        version: ForkName,
    }

    match serde_json::from_slice::<LightSubmitBlockResponse>(response_bytes) {
        Ok(parsed) => Ok(parsed.version),
        Err(err) => Err(PbsError::JsonDecode {
            err,
            raw: String::from_utf8_lossy(response_bytes).into_owned(),
        }),
    }
}

/// Decode an SSZ-encoded submit_block response
fn decode_ssz_payload(
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
