use std::{path::PathBuf, sync::Arc, time::Duration};

use alloy::primitives::B256;
use cb_common::{
    pbs::{
        GetExecutionPayloadBidInfo, GetExecutionPayloadBidResponse, RequestAuthV1,
        SignedRequestAuthV1,
    },
    signature::sign_builder_root,
    signer::random_secret,
    types::{BlsSignature, Chain},
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service_with_listener},
    mock_validator::MockValidator,
    utils::{
        generate_mock_relay, get_free_listener, get_pbs_config, setup_test_env, to_pbs_config,
    },
};
use eyre::Result;
use lh_types::Slot;
use reqwest::StatusCode;
use tracing::info;
use tree_hash::TreeHash;

const TEST_SLOT: u64 = 100;

/// Which builder the request auth targets, if any
enum AuthTarget {
    None,
    /// Index into the relay list
    Relay(usize),
    UnknownBuilder,
}

/// Test requesting a bid with a single default relay
#[tokio::test]
async fn test_get_execution_payload_bid() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![MockRelayState::new(Chain::Hoodi, random_secret())],
        AuthTarget::None,
        StatusCode::OK,
        &[1],
        Some(10),
    )
    .await
}

/// Test that the relay returning 204 (no bid) results in a 204 from PBS
#[tokio::test]
async fn test_get_execution_payload_bid_no_bid() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![MockRelayState::new(Chain::Hoodi, random_secret()).with_no_epbs_bid()],
        AuthTarget::None,
        StatusCode::NO_CONTENT,
        &[1],
        None,
    )
    .await
}

/// Test that a bid signed with the wrong key is dropped
#[tokio::test]
async fn test_get_execution_payload_bid_invalid_signature() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![MockRelayState::new(Chain::Hoodi, random_secret()).with_epbs_invalid_signature()],
        AuthTarget::None,
        StatusCode::NO_CONTENT,
        &[1],
        None,
    )
    .await
}

/// Test that a bid with a mismatched parent hash is dropped
#[tokio::test]
async fn test_get_execution_payload_bid_wrong_parent_hash() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![MockRelayState::new(Chain::Hoodi, random_secret()).with_epbs_wrong_parent_hash()],
        AuthTarget::None,
        StatusCode::NO_CONTENT,
        &[1],
        None,
    )
    .await
}

/// Test that a bid with a mismatched parent root is dropped
#[tokio::test]
async fn test_get_execution_payload_bid_wrong_parent_root() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![MockRelayState::new(Chain::Hoodi, random_secret()).with_epbs_wrong_parent_root()],
        AuthTarget::None,
        StatusCode::NO_CONTENT,
        &[1],
        None,
    )
    .await
}

/// TODO Documents CURRENT behavior: `max_trusted_bid_gwei` is hardcoded to 0 in
/// the route, so any bid with a nonzero execution_payment is rejected as
/// TrustedBidTooHigh. Per spec this threshold should come from the proposer's
/// BuilderPreferences (and 0-when-absent is spec-correct); update this test
/// when the preferences endpoint lands.
#[tokio::test]
async fn test_get_execution_payload_bid_nonzero_execution_payment_rejected() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![MockRelayState::new(Chain::Hoodi, random_secret()).with_trusted_bid_gwei(1)],
        AuthTarget::None,
        StatusCode::NO_CONTENT,
        &[1],
        None,
    )
    .await
}

/// Test that PBS returns the highest bid across relays (selection is by
/// trustless `value`)
#[tokio::test]
async fn test_get_execution_payload_bid_highest_wins() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![
            MockRelayState::new(Chain::Hoodi, random_secret()).with_trustless_bid_gwei(10),
            MockRelayState::new(Chain::Hoodi, random_secret()).with_trustless_bid_gwei(42),
        ],
        AuthTarget::None,
        StatusCode::OK,
        &[1, 1],
        Some(42),
    )
    .await
}

/// Test that auth for a specific builder forwards the request ONLY to the
/// relay whose configured URL matches. Targets the lower bid to prove the
/// response came from the filter target, not max-bid selection.
#[tokio::test]
async fn test_get_execution_payload_bid_auth_filters_to_target() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![
            MockRelayState::new(Chain::Hoodi, random_secret()).with_trustless_bid_gwei(10),
            MockRelayState::new(Chain::Hoodi, random_secret()).with_trustless_bid_gwei(42),
        ],
        AuthTarget::Relay(0),
        StatusCode::OK,
        &[1, 0],
        Some(10),
    )
    .await
}

/// Test that auth for an unconfigured builder drops the request: no relay is
/// contacted and PBS returns 204
#[tokio::test]
async fn test_get_execution_payload_bid_auth_unknown_builder() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![
            MockRelayState::new(Chain::Hoodi, random_secret()),
            MockRelayState::new(Chain::Hoodi, random_secret()),
        ],
        AuthTarget::UnknownBuilder,
        StatusCode::NO_CONTENT,
        &[0, 0],
        None,
    )
    .await
}

#[tokio::test]
async fn test_get_execution_payload_bid_spec_url() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let signer = random_secret();

    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    let mock_relay = generate_mock_relay(relay_port, mock_state.signer.public_key())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    drop(pbs_listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    let pubkey = "0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae";
    let url = format!(
        "{}eth/v1/builder/execution_payload_bid/{}/{}/{}/{}",
        mock_validator.comm_boost.config.entry.url,
        TEST_SLOT,
        B256::ZERO,
        B256::ZERO,
        pubkey,
    );
    let res = mock_validator.comm_boost.client.post(url).send().await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(mock_state.received_execution_payload_bid(), 1);
    Ok(())
}

async fn test_get_execution_payload_bid_impl(
    relay_states: Vec<MockRelayState>,
    auth_target: AuthTarget,
    expected_code: StatusCode,
    expected_relay_counts: &[u64],
    expected_value: Option<u64>,
) -> Result<()> {
    // Setup test environment
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();

    // Run one mock relay per state so per-relay knobs and counters work
    let mut relays = Vec::new();
    let mut states = Vec::new();
    let mut relay_urls = Vec::new();
    for state in relay_states {
        let relay_listener = get_free_listener().await;
        let relay_port = relay_listener.local_addr()?.port();
        let state = Arc::new(state);
        let relay = generate_mock_relay(relay_port, state.signer.public_key())?;
        relay_urls.push(relay.config.entry.url.to_string());
        tokio::spawn(start_mock_relay_service_with_listener(state.clone(), relay_listener));
        relays.push(relay);
        states.push(state);
    }

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    let state = PbsState::new(config, PathBuf::new());
    drop(pbs_listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    // Send the bid request
    let auth = match auth_target {
        AuthTarget::None => None,
        AuthTarget::Relay(i) => Some(auth_for(&relay_urls[i], TEST_SLOT)),
        AuthTarget::UnknownBuilder => {
            Some(auth_for("http://unknown-builder.example:9999/", TEST_SLOT))
        }
    };
    info!("Sending get execution payload bid");
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, auth.as_ref())
        .await?;
    assert_eq!(res.status(), expected_code);
    for (state, expected) in states.iter().zip(expected_relay_counts) {
        assert_eq!(state.received_execution_payload_bid(), *expected);
    }
    if expected_code != StatusCode::OK {
        return Ok(());
    }

    // Get the data
    let res = serde_json::from_slice::<GetExecutionPayloadBidResponse>(&res.bytes().await?)?;
    assert_eq!(res.slot(), TEST_SLOT);
    assert_eq!(res.parent_hash(), B256::ZERO);
    assert_eq!(res.parent_root(), B256::ZERO);
    assert_ne!(res.block_hash(), B256::ZERO);
    assert_eq!(res.execution_payment(), 0);
    if let Some(expected_value) = expected_value {
        assert_eq!(res.value(), expected_value);
    }
    // The winning bid must be signed by one of the configured relays
    let object_root = res.data.message.tree_hash_root();
    assert!(
        states
            .iter()
            .any(|s| sign_builder_root(chain, &s.signer, &object_root) == res.data.signature),
        "bid signature does not match any configured relay"
    );
    Ok(())
}

/// Poll /status until PBS and its relays are up. relay_check makes a 200 mean
/// the whole chain is ready; the fixed 100ms sleep used elsewhere flakes under
/// parallel suite load.
async fn wait_for_ready(mock_validator: &MockValidator) -> Result<()> {
    for _ in 0..100 {
        if let Ok(res) = mock_validator.do_get_status().await &&
            res.status() == StatusCode::OK
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    eyre::bail!("PBS/relays did not become ready within 2s")
}

/// Build a SignedRequestAuthV1 targeting `builder_url`. PBS only reads the URL
/// out of the auth to filter relays; the signature is not verified, so an
/// empty signature is sufficient here.
fn auth_for(builder_url: &str, slot: u64) -> SignedRequestAuthV1 {
    let data = ssz_types::VariableList::new(builder_url.as_bytes().to_vec())
        .expect("builder url fits in MAX_DATA_SIZE");
    SignedRequestAuthV1 {
        message: RequestAuthV1 { data, slot: Slot::new(slot) },
        signature: BlsSignature::empty(),
    }
}
