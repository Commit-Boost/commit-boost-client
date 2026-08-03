use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use alloy::{
    eips::eip7594::CELLS_PER_EXT_BLOB,
    primitives::{B256, U256},
    rpc::types::beacon::relay::ValidatorRegistration,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use cb_common::{
    constants::{GENESIS_VALIDATORS_ROOT, GLOAS_FORK_VERSION},
    pbs::{
        BUILDER_V1_API_PATH, BUILDER_V2_API_PATH, BlobsBundle, BuilderBid, BuilderBidFulu,
        BuilderPreferencesRequest, ExecutionPayloadBid, ExecutionPayloadElectra,
        ExecutionPayloadHeaderFulu, ExecutionRequests, ForkName, ForkVersionDecode,
        GET_EXECUTION_PAYLOAD_BID_PATH, GET_HEADER_PATH, GET_STATUS_PATH,
        GetExecutionPayloadBidResponse, GetHeaderParams, GetHeaderResponse, GetPayloadInfo,
        HEADER_TIMEOUT_MS, PayloadAndBlobs, REGISTER_VALIDATOR_PATH, SUBMIT_BLOCK_PATH,
        SUBMIT_BUILDER_PREFERENCES_PATH, SUBMIT_SIGNED_BEACON_BLOCK_PATH, SignedBeaconBlock,
        SignedBuilderBid, SignedExecutionPayloadBid, SignedRequestAuth, SubmitBlindedBlockResponse,
    },
    signature::{sign_builder_root, sign_execution_payload_bid_root},
    signer::random_secret,
    types::{BlsPublicKey, BlsSecretKey, Chain},
    utils::{TestRandomSeed, timestamp_of_slot_start_sec, utcnow_ms},
    wire::{
        CONSENSUS_VERSION_HEADER, EncodingType, deserialize_body, get_accept_types,
        get_consensus_version_header, get_content_type,
    },
};
use cb_pbs::MAX_SIZE_SUBMIT_BLOCK_RESPONSE;
use lh_types::{KzgProof, Slot};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use ssz::{Decode, Encode};
use tokio::net::TcpListener;
use tracing::{debug, error};
use tree_hash::TreeHash;

pub async fn start_mock_relay_service(state: Arc<MockRelayState>, port: u16) -> eyre::Result<()> {
    let socket = SocketAddr::new("0.0.0.0".parse()?, port);
    let listener = TcpListener::bind(socket).await?;
    start_mock_relay_service_with_listener(state, listener).await
}

/// Like [`start_mock_relay_service`], but accepts a pre-bound [`TcpListener`].
pub async fn start_mock_relay_service_with_listener(
    state: Arc<MockRelayState>,
    listener: TcpListener,
) -> eyre::Result<()> {
    let app = mock_relay_app_router(state);
    axum::serve(listener, app).await?;
    Ok(())
}

/// One inbound `getExecutionPayloadBid` request, recorded on arrival. Both
/// fields are captured under a single lock so the two derived sequences cannot
/// interleave differently when polls overlap.
struct BidRequestRecord {
    /// `X-Timeout-Ms` the caller granted this request
    timeout_ms: u64,
    arrival_ms: u64,
}

pub struct MockRelayState {
    pub chain: Chain,
    pub signer: BlsSecretKey,
    pub supported_content_types: Arc<HashSet<EncodingType>>,
    large_body: bool,
    supports_submit_block_v2: bool,
    use_not_found_for_submit_block: bool,
    /// If set, `handle_submit_block_v1`/`v2` short-circuits with this status
    /// when the inbound request carries `Content-Type:
    /// application/octet-stream`. The counter is still incremented before
    /// the short-circuit so tests can observe the attempt. Used to drive C3
    /// (retry-as-JSON) tests.
    submit_block_ssz_status_override: Option<StatusCode>,
    /// If set, this literal string is sent as the outgoing `Content-Type`
    /// header on `handle_get_header` and `handle_submit_block_v1` responses
    /// instead of the canonical `application/json` / `application/octet-stream`
    /// value. The body is still serialized according to the encoding that was
    /// negotiated via `Accept`. Used to exercise PBS tolerance of
    /// MIME-parameter suffixes like `application/octet-stream; charset=binary`.
    response_content_type_override: Option<String>,
    /// If set, `handle_submit_block_v1` labels its JSON response with this fork
    /// in the `version` field instead of the request's fork. Used to drive the
    /// fork-mismatch rejection test
    submit_block_version_override: Option<ForkName>,
    received_get_header: Arc<AtomicU64>,
    received_get_status: Arc<AtomicU64>,
    received_register_validator: Arc<AtomicU64>,
    received_submit_block: Arc<AtomicU64>,
    received_execution_payload_bid: Arc<AtomicU64>,
    received_builder_preferences: Arc<AtomicU64>,
    received_signed_beacon_block: Arc<AtomicU64>,
    /// `slot` of the last signed beacon block forwarded, decoded from the SSZ
    /// body PBS sent, so a test can assert the block survived the hop
    received_block_slot: RwLock<Option<u64>>,
    /// `block_hash` the last forwarded block committed to in its bid
    received_block_committed_hash: RwLock<Option<B256>>,
    /// The last `BuilderPreferencesRequest` submitted, so a test can assert
    /// both the preferences and the auth were forwarded unchanged
    received_preferences: RwLock<Option<BuilderPreferencesRequest>>,
    /// The `{proposer_pubkey}` path segment of the last preferences submission
    received_preferences_pubkey: RwLock<Option<BlsPublicKey>>,
    /// Bid requests answered after `bid_delay_ms` elapsed. A poll the caller
    /// timed out on is cancelled during the delay and never lands here, so this
    /// counts the polls that actually got a response.
    served_execution_payload_bid: Arc<AtomicU64>,
    /// Every inbound bid request, in arrival order
    received_bid_requests: RwLock<Vec<BidRequestRecord>>,
    /// Each successive bid request serves this many more gwei than the last,
    /// so a test can tell which poll's bid won
    improving_bid_step_gwei: Option<u64>,
    /// Hold every bid request this long before answering, simulating a builder
    /// that sits on a request instead of answering promptly
    bid_delay_ms: Option<u64>,
    /// `data` bytes of the last `SignedRequestAuth` forwarded on a bid
    /// request
    received_auth: RwLock<Option<SignedRequestAuth>>,
    response_override: RwLock<Option<StatusCode>>,
    bid_value: RwLock<U256>,
    /// The raw `Accept` header PBS sent on the most recent get_header request,
    /// so a test can assert what encoding PBS asked the relay for.
    received_get_header_accept: RwLock<Option<String>>,
    /// Served as `bid.value` / `bid.execution_payment` by
    /// `handle_get_execution_payload_bid`
    trustless_bid_gwei: u64, // default 10
    trusted_bid_gwei: u64,
    epbs_no_bid: bool,
    epbs_invalid_signature: bool,
    epbs_wrong_parent_hash: bool,
    epbs_wrong_parent_root: bool,
    /// When true, `handle_get_execution_payload_bid` omits the
    /// `Eth-Consensus-Version` header on an SSZ 200. Drives the PBS error path
    /// for an SSZ bid response that lacks the fork header.
    epbs_omit_consensus_version: bool,
}

impl MockRelayState {
    pub fn received_get_header(&self) -> u64 {
        self.received_get_header.load(Ordering::Relaxed)
    }
    pub fn received_get_header_accept(&self) -> Option<String> {
        self.received_get_header_accept.read().unwrap().clone()
    }
    pub fn received_get_status(&self) -> u64 {
        self.received_get_status.load(Ordering::Relaxed)
    }
    pub fn received_register_validator(&self) -> u64 {
        self.received_register_validator.load(Ordering::Relaxed)
    }
    pub fn received_submit_block(&self) -> u64 {
        self.received_submit_block.load(Ordering::Relaxed)
    }
    pub fn received_execution_payload_bid(&self) -> u64 {
        self.received_execution_payload_bid.load(Ordering::Relaxed)
    }
    pub fn served_execution_payload_bid(&self) -> u64 {
        self.served_execution_payload_bid.load(Ordering::Relaxed)
    }
    pub fn received_builder_preferences(&self) -> u64 {
        self.received_builder_preferences.load(Ordering::Relaxed)
    }
    pub fn received_signed_beacon_block(&self) -> u64 {
        self.received_signed_beacon_block.load(Ordering::Relaxed)
    }
    /// `slot` of the last signed beacon block PBS forwarded
    pub fn received_block_slot(&self) -> Option<u64> {
        *self.received_block_slot.read().unwrap()
    }
    /// `block_hash` the last forwarded block committed to
    pub fn received_block_committed_hash(&self) -> Option<B256> {
        *self.received_block_committed_hash.read().unwrap()
    }

    /// `max_execution_payment` of the last submitted preferences
    pub fn received_max_execution_payment(&self) -> Option<u64> {
        self.received_preferences
            .read()
            .unwrap()
            .as_ref()
            .map(|r| r.preferences.max_execution_payment)
    }

    /// The `SignedRequestAuth` carried by the last submitted preferences
    pub fn received_preferences_auth(&self) -> Option<SignedRequestAuth> {
        self.received_preferences.read().unwrap().as_ref().map(|r| r.auth.clone())
    }

    /// The proposer the last preferences submission was filed under
    pub fn received_preferences_pubkey(&self) -> Option<BlsPublicKey> {
        self.received_preferences_pubkey.read().unwrap().clone()
    }

    /// `X-Timeout-Ms` of every inbound bid request, in arrival order: the shape
    /// of the poll ladder as the builder saw it.
    pub fn received_bid_timeouts(&self) -> Vec<u64> {
        self.received_bid_requests.read().unwrap().iter().map(|r| r.timeout_ms).collect()
    }

    /// Arrival time of every inbound bid request, in arrival order, for
    /// asserting the poll cadence.
    pub fn received_bid_arrivals_ms(&self) -> Vec<u64> {
        self.received_bid_requests.read().unwrap().iter().map(|r| r.arrival_ms).collect()
    }
    pub fn received_auth_data(&self) -> Option<Vec<u8>> {
        self.received_auth.read().unwrap().as_ref().map(|a| a.message.data.to_vec())
    }

    /// The full `SignedRequestAuth` the relay saw, so a test can assert the
    /// signature was forwarded byte-for-byte.
    pub fn received_auth(&self) -> Option<SignedRequestAuth> {
        self.received_auth.read().unwrap().clone()
    }
    pub fn large_body(&self) -> bool {
        self.large_body
    }
    pub fn supports_submit_block_v2(&self) -> bool {
        self.supports_submit_block_v2
    }
    pub fn use_not_found_for_submit_block(&self) -> bool {
        self.use_not_found_for_submit_block
    }
    pub fn submit_block_ssz_status_override(&self) -> Option<StatusCode> {
        self.submit_block_ssz_status_override
    }
    pub fn response_content_type_override(&self) -> Option<&str> {
        self.response_content_type_override.as_deref()
    }
    pub fn submit_block_version_override(&self) -> Option<ForkName> {
        self.submit_block_version_override
    }
    pub fn set_response_override(&self, status: StatusCode) {
        *self.response_override.write().unwrap() = Some(status);
    }
}

impl MockRelayState {
    pub fn new(chain: Chain, signer: BlsSecretKey) -> Self {
        Self {
            chain,
            signer,
            large_body: false,
            supports_submit_block_v2: true,
            use_not_found_for_submit_block: false,
            submit_block_ssz_status_override: None,
            response_content_type_override: None,
            submit_block_version_override: None,
            received_get_header: Default::default(),
            received_get_status: Default::default(),
            received_register_validator: Default::default(),
            received_submit_block: Default::default(),
            received_execution_payload_bid: Default::default(),
            received_builder_preferences: Default::default(),
            received_signed_beacon_block: Default::default(),
            received_block_slot: RwLock::new(None),
            received_block_committed_hash: RwLock::new(None),
            received_preferences: RwLock::new(None),
            received_preferences_pubkey: RwLock::new(None),
            served_execution_payload_bid: Default::default(),
            received_bid_requests: RwLock::new(Vec::new()),
            improving_bid_step_gwei: None,
            bid_delay_ms: None,
            received_auth: RwLock::new(None),
            response_override: RwLock::new(None),
            bid_value: RwLock::new(U256::from(10)),
            received_get_header_accept: RwLock::new(None),
            trustless_bid_gwei: 10,
            trusted_bid_gwei: 0,
            epbs_no_bid: false,
            epbs_invalid_signature: false,
            epbs_wrong_parent_hash: false,
            epbs_wrong_parent_root: false,
            epbs_omit_consensus_version: false,
            supported_content_types: Arc::new(
                [EncodingType::Json, EncodingType::Ssz].iter().cloned().collect(),
            ),
        }
    }

    /// Override the bid value returned by this relay. Defaults to
    /// `U256::from(10)`.
    pub fn with_bid_value(self, value: U256) -> Self {
        *self.bid_value.write().unwrap() = value;
        self
    }

    pub fn with_large_body(self) -> Self {
        Self { large_body: true, ..self }
    }

    pub fn with_no_submit_block_v2(self) -> Self {
        Self { supports_submit_block_v2: false, ..self }
    }

    pub fn with_not_found_for_submit_block(self) -> Self {
        Self { use_not_found_for_submit_block: true, ..self }
    }

    /// Make `handle_submit_block_v1`/`v2` respond with `status` whenever the
    /// request comes in as SSZ (`Content-Type: application/octet-stream`).
    /// JSON requests still go through the normal happy path, which lets a
    /// single test cover the SSZ→JSON retry behavior.
    pub fn with_submit_block_ssz_status(self, status: StatusCode) -> Self {
        Self { submit_block_ssz_status_override: Some(status), ..self }
    }

    /// Make the relay advertise `raw_content_type` as the `Content-Type`
    /// header on `get_header` and `submit_block_v1` responses. The body is
    /// still encoded via the negotiated [`EncodingType`] — only the header
    /// string changes. Use this to drive PBS tolerance of MIME-parameter
    /// suffixes (e.g. `application/octet-stream; charset=binary`).
    pub fn with_response_content_type(self, raw_content_type: impl Into<String>) -> Self {
        Self { response_content_type_override: Some(raw_content_type.into()), ..self }
    }

    /// Make `handle_submit_block_v1` label its JSON response with `fork` in the
    /// `version` field, regardless of the request's fork. Used to exercise the
    /// PBS fork-mismatch rejection.
    pub fn with_submit_block_version(self, fork: ForkName) -> Self {
        Self { submit_block_version_override: Some(fork), ..self }
    }

    pub fn with_trustless_bid_gwei(self, value: u64) -> Self {
        Self { trustless_bid_gwei: value, ..self }
    }

    pub fn with_trusted_bid_gwei(self, execution_payment: u64) -> Self {
        Self { trusted_bid_gwei: execution_payment, ..self }
    }

    pub fn with_no_epbs_bid(self) -> Self {
        Self { epbs_no_bid: true, ..self }
    }

    /// Signs the served bid with a throwaway key
    pub fn with_epbs_invalid_signature(self) -> Self {
        Self { epbs_invalid_signature: true, ..self }
    }

    pub fn with_epbs_wrong_parent_hash(self) -> Self {
        Self { epbs_wrong_parent_hash: true, ..self }
    }

    pub fn with_epbs_wrong_parent_root(self) -> Self {
        Self { epbs_wrong_parent_root: true, ..self }
    }

    /// Restrict this relay to SSZ responses on the bid endpoint, so the bid
    /// 200 is served as SSZ regardless of the caller's fallback preference.
    pub fn with_ssz_only_response(self) -> Self {
        Self {
            supported_content_types: Arc::new([EncodingType::Ssz].into_iter().collect()),
            ..self
        }
    }

    /// Restrict this relay to JSON responses on the bid endpoint.
    pub fn with_json_only_response(self) -> Self {
        Self {
            supported_content_types: Arc::new([EncodingType::Json].into_iter().collect()),
            ..self
        }
    }

    /// Serve a strictly better bid on each successive bid request: the nth
    /// request (0-indexed) is worth `trustless_bid_gwei + n * step_gwei`. Lets
    /// a test prove WHICH poll of a ladder produced the winning bid.
    pub fn with_improving_bids(self, step_gwei: u64) -> Self {
        Self { improving_bid_step_gwei: Some(step_gwei), ..self }
    }

    /// Hold every bid request `delay_ms` before answering. Polls whose
    /// `X-Timeout-Ms` is shorter than this are dropped by the caller, which is
    /// what makes the early rungs of the ladder observable.
    pub fn with_bid_delay_ms(self, delay_ms: u64) -> Self {
        Self { bid_delay_ms: Some(delay_ms), ..self }
    }

    /// Serve an SSZ bid 200 WITHOUT the `Eth-Consensus-Version` header, to
    /// exercise the PBS missing-fork error path on the outbound SSZ decode.
    pub fn with_epbs_omit_consensus_version(self) -> Self {
        Self { epbs_omit_consensus_version: true, ..self }
    }
}

pub fn mock_relay_app_router(state: Arc<MockRelayState>) -> Router {
    let v1_builder_routes = Router::new()
        .route(GET_HEADER_PATH, get(handle_get_header))
        .route(GET_STATUS_PATH, get(handle_get_status))
        .route(REGISTER_VALIDATOR_PATH, post(handle_register_validator))
        .route(SUBMIT_BLOCK_PATH, post(handle_submit_block_v1))
        // ePBS endpoints are v1 of new resources per builder-specs
        .route(GET_EXECUTION_PAYLOAD_BID_PATH, post(handle_get_execution_payload_bid))
        .route(SUBMIT_BUILDER_PREFERENCES_PATH, post(handle_submit_builder_preferences))
        .route(SUBMIT_SIGNED_BEACON_BLOCK_PATH, post(handle_submit_signed_beacon_block));

    let v2_builder_routes = if state.supports_submit_block_v2 {
        Router::new().route(SUBMIT_BLOCK_PATH, post(handle_submit_block_v2))
    } else {
        Router::new()
    };

    let builder_router_v1 = Router::new().nest(BUILDER_V1_API_PATH, v1_builder_routes);
    let builder_router_v2 = Router::new().nest(BUILDER_V2_API_PATH, v2_builder_routes);
    Router::new().merge(builder_router_v1).merge(builder_router_v2).with_state(state)
}

async fn handle_get_execution_payload_bid(
    State(state): State<Arc<MockRelayState>>,
    Path((slot, parent_hash, parent_root, _pubkey)): Path<(u64, B256, B256, BlsPublicKey)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let request_index = state.received_execution_payload_bid.fetch_add(1, Ordering::Relaxed);
    state.received_bid_requests.write().unwrap().push(BidRequestRecord {
        timeout_ms: headers
            .get(HEADER_TIMEOUT_MS)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
            .unwrap_or_default(),
        arrival_ms: utcnow_ms(),
    });
    // Decode the optional request auth the way a real builder does: Content-Type
    // selects JSON vs SSZ. The wire type is fork-versioned per builder-specs,
    // so the SSZ form additionally requires Eth-Consensus-Version — PBS always
    // forwards SSZ, making this the assertion that the header arrives.
    if !body.is_empty() {
        let auth = match get_content_type(&headers) {
            EncodingType::Ssz => {
                if get_consensus_version_header(&headers).is_none() {
                    return (
                        StatusCode::BAD_REQUEST,
                        "missing Eth-Consensus-Version header".to_string(),
                    )
                        .into_response();
                }
                SignedRequestAuth::from_ssz_bytes(&body).ok()
            }
            EncodingType::Json => serde_json::from_slice::<SignedRequestAuth>(&body).ok(),
        };
        if let Some(auth) = auth {
            *state.received_auth.write().unwrap() = Some(auth);
        }
    }

    // Honor a forced status like the other handlers, so a test can make a relay
    // fail on the bid endpoint (its bid is then dropped by PBS). The request was
    // already counted above.
    if let Some(status) = *state.response_override.read().unwrap() {
        return status.into_response();
    }

    // Sleep, never block: concurrent polls must overlap, not serialize
    if let Some(delay_ms) = state.bid_delay_ms {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
    state.served_execution_payload_bid.fetch_add(1, Ordering::Relaxed);

    if state.epbs_no_bid {
        return StatusCode::NO_CONTENT.into_response();
    }

    let served_parent_hash =
        if state.epbs_wrong_parent_hash { B256::repeat_byte(0xab) } else { parent_hash };
    let served_parent_root =
        if state.epbs_wrong_parent_root { B256::repeat_byte(0xcd) } else { parent_root };

    let mut block_hash = B256::ZERO;
    block_hash.0[0] = 1;

    let message = ExecutionPayloadBid {
        parent_block_hash: served_parent_hash.into(),
        parent_block_root: served_parent_root,
        block_hash: block_hash.into(),
        gas_limit: 30_000_000,
        builder_index: 42,
        slot: Slot::new(slot),
        value: state.trustless_bid_gwei.saturating_add(
            state.improving_bid_step_gwei.unwrap_or(0).saturating_mul(request_index),
        ),
        execution_payment: state.trusted_bid_gwei,
        ..Default::default()
    };

    let object_root = message.tree_hash_root();
    let signature = if state.epbs_invalid_signature {
        let wrong_key = random_secret();
        sign_execution_payload_bid_root(
            &wrong_key,
            &object_root,
            GLOAS_FORK_VERSION,
            GENESIS_VALIDATORS_ROOT.into(),
        )
    } else {
        sign_execution_payload_bid_root(
            &state.signer,
            &object_root,
            GLOAS_FORK_VERSION,
            GENESIS_VALIDATORS_ROOT.into(),
        )
    };

    let data = SignedExecutionPayloadBid { message, signature };

    // Negotiate the RESPONSE encoding from the forwarded Accept, mirroring
    // handle_get_header: honor supported_content_types + the caller's Accept.
    let accept_types = match get_accept_types(&headers) {
        Ok(a) => a,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("error parsing accept header: {e}"))
                .into_response();
        }
    };
    let content_type = if state.supported_content_types.contains(&EncodingType::Ssz) &&
        accept_types.contains(EncodingType::Ssz)
    {
        EncodingType::Ssz
    } else if state.supported_content_types.contains(&EncodingType::Json) &&
        accept_types.contains(EncodingType::Json)
    {
        EncodingType::Json
    } else {
        return (StatusCode::NOT_ACCEPTABLE, "No acceptable content type found".to_string())
            .into_response();
    };

    let response_body = match content_type {
        // SSZ carries the inner bid; the fork travels in Eth-Consensus-Version.
        EncodingType::Ssz => data.as_ssz_bytes(),
        // JSON carries the fork-versioned wrapper (fork is in the body).
        EncodingType::Json => {
            let versioned = GetExecutionPayloadBidResponse {
                version: ForkName::Gloas,
                data,
                metadata: Default::default(),
            };
            serde_json::to_vec(&versioned).unwrap()
        }
    };

    let mut response = (StatusCode::OK, response_body).into_response();
    // A real builder tags the 200 with the fork so a client can decode the
    // (non-self-describing) SSZ bytes. The omit knob drives the PBS
    // "SSZ response missing Eth-Consensus-Version" error path.
    if !state.epbs_omit_consensus_version {
        response.headers_mut().insert(
            CONSENSUS_VERSION_HEADER,
            HeaderValue::from_str(&ForkName::Gloas.to_string()).unwrap(),
        );
    }
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_str(&content_type.to_string()).unwrap());
    response
}

async fn handle_get_header(
    State(state): State<Arc<MockRelayState>>,
    Path(GetHeaderParams { parent_hash, slot, .. }): Path<GetHeaderParams>,
    headers: HeaderMap,
) -> Response {
    state.received_get_header.fetch_add(1, Ordering::Relaxed);
    *state.received_get_header_accept.write().unwrap() =
        headers.get(ACCEPT).and_then(|v| v.to_str().ok()).map(String::from);
    let accept_types = get_accept_types(&headers)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("error parsing accept header: {e}")));
    if let Err(e) = accept_types {
        return e.into_response();
    }
    let accept_types = accept_types.unwrap();
    let consensus_version_header = get_consensus_version_header(&headers).unwrap_or(ForkName::Fulu);

    let content_type = if state.supported_content_types.contains(&EncodingType::Ssz) &&
        accept_types.contains(EncodingType::Ssz)
    {
        EncodingType::Ssz
    } else if state.supported_content_types.contains(&EncodingType::Json) &&
        accept_types.contains(EncodingType::Json)
    {
        EncodingType::Json
    } else {
        return (StatusCode::NOT_ACCEPTABLE, "No acceptable content type found".to_string())
            .into_response();
    };

    let bid_value = *state.bid_value.read().unwrap();

    let data = match consensus_version_header {
        ForkName::Fulu => {
            let mut header = ExecutionPayloadHeaderFulu {
                parent_hash: parent_hash.into(),
                block_hash: Default::default(),
                timestamp: timestamp_of_slot_start_sec(slot, state.chain),
                ..ExecutionPayloadHeaderFulu::test_random()
            };
            header.block_hash.0[0] = 1;

            let message = BuilderBid::Fulu(BuilderBidFulu {
                header,
                blob_kzg_commitments: Default::default(),
                execution_requests: ExecutionRequests::default(),
                value: bid_value,
                pubkey: state.signer.public_key().into(),
            });
            let object_root = message.tree_hash_root();
            let signature = sign_builder_root(state.chain, &state.signer, &object_root);
            let response = SignedBuilderBid { message, signature };
            if content_type == EncodingType::Ssz {
                response.as_ssz_bytes()
            } else {
                let versioned_response = GetHeaderResponse {
                    version: ForkName::Fulu,
                    data: response,
                    metadata: Default::default(),
                };
                serde_json::to_vec(&versioned_response).unwrap()
            }
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Unsupported fork {consensus_version_header}"),
            )
                .into_response();
        }
    };

    let mut response = (StatusCode::OK, data).into_response();
    let consensus_version_header =
        HeaderValue::from_str(&consensus_version_header.to_string()).unwrap();
    let content_type_str = state
        .response_content_type_override()
        .map(|s| s.to_string())
        .unwrap_or_else(|| content_type.to_string());
    let content_type_header = HeaderValue::from_str(&content_type_str).unwrap();
    response.headers_mut().insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
    response.headers_mut().insert(CONTENT_TYPE, content_type_header);
    response
}

async fn handle_get_status(State(state): State<Arc<MockRelayState>>) -> impl IntoResponse {
    state.received_get_status.fetch_add(1, Ordering::Relaxed);
    // Production `get_status` dispatches relays concurrently via `select_ok`,
    // which cancels losing futures as soon as any relay returns OK. On a
    // loaded runner this can abort a sibling relay's reqwest send before
    // its handler is entered, so the test-side counter only reaches 1. A
    // tiny response delay (counter already bumped above) guarantees every
    // concurrent request lands in a handler before any response is written,
    // eliminating the flake without altering production behavior.
    tokio::time::sleep(Duration::from_millis(20)).await;
    StatusCode::OK
}

/// Decodes the submission the way a real builder does (Content-Type selects
/// JSON vs SSZ), records it, and 202s unless the test overrode the response.
async fn handle_submit_builder_preferences(
    Path(proposer_pubkey): Path<BlsPublicKey>,
    headers: HeaderMap,
    State(state): State<Arc<MockRelayState>>,
    body: axum::body::Bytes,
) -> Response {
    state.received_builder_preferences.fetch_add(1, Ordering::Relaxed);
    // A real builder keys preferences by proposer, so the path segment PBS sent
    // is part of what a test must be able to assert
    *state.received_preferences_pubkey.write().unwrap() = Some(proposer_pubkey);

    let decoded = match get_content_type(&headers) {
        EncodingType::Json => serde_json::from_slice::<BuilderPreferencesRequest>(&body).ok(),
        // The wire type is fork-versioned per builder-specs, so a real builder
        // requires Eth-Consensus-Version on the SSZ form — PBS always forwards
        // SSZ, making this the assertion that the header arrives.
        EncodingType::Ssz => get_consensus_version_header(&headers)
            .and_then(|_| BuilderPreferencesRequest::from_ssz_bytes(&body).ok()),
    };
    let Some(request) = decoded else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    *state.received_preferences.write().unwrap() = Some(request);

    if let Some(status) = state.response_override.read().unwrap().as_ref() {
        return (*status).into_response();
    }

    StatusCode::ACCEPTED.into_response()
}

/// Decodes the forwarded block (PBS always sends SSZ with
/// `Eth-Consensus-Version`), records its slot and committed bid hash, and 202s
/// unless the test overrode the response.
async fn handle_submit_signed_beacon_block(
    headers: HeaderMap,
    State(state): State<Arc<MockRelayState>>,
    body: axum::body::Bytes,
) -> Response {
    state.received_signed_beacon_block.fetch_add(1, Ordering::Relaxed);

    if let Some(fork) = get_consensus_version_header(&headers) &&
        let Ok(block) = SignedBeaconBlock::from_ssz_bytes_by_fork(&body, fork)
    {
        *state.received_block_slot.write().unwrap() = Some(block.slot().as_u64());
        *state.received_block_committed_hash.write().unwrap() = match &block {
            lh_types::SignedBeaconBlock::Gloas(b) => {
                Some(b.message.body.signed_execution_payload_bid.message.block_hash.0)
            }
            _ => None,
        };
    }

    if let Some(status) = state.response_override.read().unwrap().as_ref() {
        return (*status).into_response();
    }

    StatusCode::ACCEPTED.into_response()
}

async fn handle_register_validator(
    State(state): State<Arc<MockRelayState>>,
    Json(validators): Json<Vec<ValidatorRegistration>>,
) -> impl IntoResponse {
    state.received_register_validator.fetch_add(1, Ordering::Relaxed);
    debug!("Received {} registrations", validators.len());

    if let Some(status) = state.response_override.read().unwrap().as_ref() {
        return (*status).into_response();
    }

    StatusCode::OK.into_response()
}

async fn handle_submit_block_v1(
    headers: HeaderMap,
    State(state): State<Arc<MockRelayState>>,
    body_bytes: axum::body::Bytes,
) -> Response {
    if state.use_not_found_for_submit_block() {
        return StatusCode::NOT_FOUND.into_response();
    }
    state.received_submit_block.fetch_add(1, Ordering::Relaxed);
    // Short-circuit SSZ requests with an overridden status so tests can
    // drive the PBS SSZ→JSON retry logic. JSON requests still take the
    // normal path so a single mock run can exercise both attempts.
    if let Some(status) = state.submit_block_ssz_status_override() &&
        get_content_type(&headers) == EncodingType::Ssz
    {
        return (status, "forced ssz override").into_response();
    }
    let accept_types = get_accept_types(&headers)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("error parsing accept header: {e}")));
    if let Err(e) = accept_types {
        return e.into_response();
    }
    let accept_types = accept_types.unwrap();
    let consensus_version_header = get_consensus_version_header(&headers);
    let response_content_type = if state.supported_content_types.contains(&EncodingType::Ssz) &&
        accept_types.contains(EncodingType::Ssz)
    {
        EncodingType::Ssz
    } else if state.supported_content_types.contains(&EncodingType::Json) &&
        accept_types.contains(EncodingType::Json)
    {
        EncodingType::Json
    } else {
        return (StatusCode::NOT_ACCEPTABLE, "No acceptable content type found".to_string())
            .into_response();
    };

    // Error out if the request content type is not supported
    let content_type = get_content_type(&headers);
    if !state.supported_content_types.contains(&content_type) {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "Unsupported content type".to_string())
            .into_response();
    };

    let data = if state.large_body() {
        vec![1u8; 1 + MAX_SIZE_SUBMIT_BLOCK_RESPONSE]
    } else {
        let mut execution_payload = ExecutionPayloadElectra::test_random();
        let submit_block = deserialize_body(&headers, body_bytes).map_err(|err| {
            error!(%err, "failed to deserialize signed blinded block");
            (StatusCode::BAD_REQUEST, format!("failed to deserialize body: {err}"))
        });
        if let Err(e) = submit_block {
            return e.into_response();
        }
        let submit_block = submit_block.unwrap();
        execution_payload.block_hash = submit_block.block_hash().into();

        let mut blobs_bundle = BlobsBundle::default();

        blobs_bundle.blobs.push(Default::default()).unwrap();
        blobs_bundle.commitments =
            submit_block.as_electra().unwrap().message.body.blob_kzg_commitments.clone();
        // Emit a proof layout matching the fork we label the response with, so a
        // mismatch-labelled response still passes that fork's blob validation and
        // the only thing left to reject it is the fork check itself. Electra uses
        // one proof per blob; Fulu uses CELLS_PER_EXT_BLOB per blob.
        let proofs_per_blob = match state.submit_block_version_override() {
            Some(ForkName::Fulu) => CELLS_PER_EXT_BLOB,
            _ => 1,
        };
        for _ in 0..(blobs_bundle.blobs.len() * proofs_per_blob) {
            blobs_bundle.proofs.push(KzgProof([0; 48])).unwrap();
        }

        let response =
            PayloadAndBlobs { execution_payload: execution_payload.into(), blobs_bundle };

        if response_content_type == EncodingType::Ssz {
            response.as_ssz_bytes()
        } else {
            // Return JSON for everything else; this is fine for the mock
            let response = SubmitBlindedBlockResponse {
                version: state.submit_block_version_override().unwrap_or(ForkName::Electra),
                metadata: Default::default(),
                data: response,
            };
            serde_json::to_vec(&response).unwrap()
        }
    };

    let mut response = (StatusCode::OK, data).into_response();
    if response_content_type == EncodingType::Ssz {
        let consensus_version_header = match consensus_version_header {
            Some(header) => header,
            None => {
                return (StatusCode::BAD_REQUEST, "Missing consensus version header".to_string())
                    .into_response()
            }
        };
        let consensus_version_header =
            HeaderValue::from_str(&consensus_version_header.to_string()).unwrap();
        response.headers_mut().insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
    }
    let content_type_str = state
        .response_content_type_override()
        .map(|s| s.to_string())
        .unwrap_or_else(|| response_content_type.to_string());
    let content_type_header = HeaderValue::from_str(&content_type_str).unwrap();
    response.headers_mut().insert(CONTENT_TYPE, content_type_header);
    response
}

async fn handle_submit_block_v2(
    headers: HeaderMap,
    State(state): State<Arc<MockRelayState>>,
) -> Response {
    if state.use_not_found_for_submit_block() {
        return StatusCode::NOT_FOUND.into_response();
    }
    state.received_submit_block.fetch_add(1, Ordering::Relaxed);
    // See comment in `handle_submit_block_v1`. Override SSZ with the
    // injected status so C3 tests can assert retry / no-retry behavior.
    if let Some(status) = state.submit_block_ssz_status_override() &&
        get_content_type(&headers) == EncodingType::Ssz
    {
        return (status, "forced ssz override").into_response();
    }
    let content_type = get_content_type(&headers);
    if !state.supported_content_types.contains(&content_type) {
        return (StatusCode::NOT_ACCEPTABLE, "No acceptable content type found".to_string())
            .into_response();
    };
    (StatusCode::ACCEPTED, "").into_response()
}
