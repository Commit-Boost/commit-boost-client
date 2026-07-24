use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use alloy::primitives::{Address, B256, U256};
use cb_common::{
    config::RuntimeMuxConfig,
    constants::{GENESIS_VALIDATORS_ROOT, GLOAS_FORK_VERSION},
    pbs::{
        GetExecutionPayloadBidInfo, GetExecutionPayloadBidResponse, RequestAuthV1,
        SignedExecutionPayloadBid, SignedRequestAuthV1,
    },
    signature::sign_execution_payload_bid_root,
    signer::random_secret,
    types::{BlsSignature, Chain},
    wire::EncodingType,
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service_with_listener},
    mock_validator::MockValidator,
    utils::{
        generate_mock_relay, generate_mock_relay_with_auth_data, get_free_listener, get_pbs_config,
        setup_test_env, to_pbs_config,
    },
};
use eyre::Result;
use lh_types::Slot;
use reqwest::{StatusCode, header::CONTENT_TYPE};
use ssz::{Decode, Encode};
use tracing::info;
use tree_hash::TreeHash;

const TEST_SLOT: u64 = 100;

/// Test requesting a bid with a single default relay
#[tokio::test]
async fn test_get_execution_payload_bid() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![MockRelayState::new(Chain::Hoodi, random_secret())],
        StatusCode::OK,
        &[1],
        Some(10),
        0,
    )
    .await
}

/// Test that the relay returning 204 (no bid) results in a 204 from PBS
#[tokio::test]
async fn test_get_execution_payload_bid_no_bid() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![MockRelayState::new(Chain::Hoodi, random_secret()).with_no_epbs_bid()],
        StatusCode::NO_CONTENT,
        &[1],
        None,
        0,
    )
    .await
}

/// Test that a bid signed with the wrong key is dropped
#[tokio::test]
async fn test_get_execution_payload_bid_invalid_signature() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![MockRelayState::new(Chain::Hoodi, random_secret()).with_epbs_invalid_signature()],
        StatusCode::NO_CONTENT,
        &[1],
        None,
        0,
    )
    .await
}

/// Test that a bid with a mismatched parent hash is dropped
#[tokio::test]
async fn test_get_execution_payload_bid_wrong_parent_hash() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![MockRelayState::new(Chain::Hoodi, random_secret()).with_epbs_wrong_parent_hash()],
        StatusCode::NO_CONTENT,
        &[1],
        None,
        0,
    )
    .await
}

/// Test that a bid with a mismatched parent root is dropped
#[tokio::test]
async fn test_get_execution_payload_bid_wrong_parent_root() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![MockRelayState::new(Chain::Hoodi, random_secret()).with_epbs_wrong_parent_root()],
        StatusCode::NO_CONTENT,
        &[1],
        None,
        0,
    )
    .await
}

/// With the default `max_execution_payment_gwei` of 0, any bid with a nonzero
/// execution_payment is rejected as TrustedBidTooHigh
#[tokio::test]
async fn test_get_execution_payload_bid_nonzero_execution_payment_rejected() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![MockRelayState::new(Chain::Hoodi, random_secret()).with_trusted_bid_gwei(1)],
        StatusCode::NO_CONTENT,
        &[1],
        None,
        0,
    )
    .await
}

#[tokio::test]
async fn test_get_execution_payload_bid_highest_wins() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![
            MockRelayState::new(Chain::Hoodi, random_secret()).with_trustless_bid_gwei(10),
            MockRelayState::new(Chain::Hoodi, random_secret()).with_trustless_bid_gwei(42),
        ],
        StatusCode::OK,
        &[1, 1],
        Some(42),
        0,
    )
    .await
}

/// Test that a bid with an execution payment within the configured
/// `max_execution_payment_gwei` is accepted
#[tokio::test]
async fn test_get_execution_payload_bid_execution_payment_within_cap() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![MockRelayState::new(Chain::Hoodi, random_secret()).with_trusted_bid_gwei(5)],
        StatusCode::OK,
        &[1],
        None,
        10,
    )
    .await
}

/// Test that selection is by TOTAL payment: trustless 5 + payment 10 beats
/// trustless 10 + payment 0. Asserting value == 5 proves the total won.
#[tokio::test]
async fn test_get_execution_payload_bid_highest_total_payment_wins() -> Result<()> {
    test_get_execution_payload_bid_impl(
        vec![
            MockRelayState::new(Chain::Hoodi, random_secret()).with_trustless_bid_gwei(10),
            MockRelayState::new(Chain::Hoodi, random_secret())
                .with_trustless_bid_gwei(5)
                .with_trusted_bid_gwei(10),
        ],
        StatusCode::OK,
        &[1, 1],
        Some(5),
        10,
    )
    .await
}

/// Test that min_bid_eth also floors ePBS bids: a bid whose total payment (in
/// gwei) is below the configured minimum returns 204. Covers the wei -> gwei
/// conversion, which the unit tests don't.
#[tokio::test]
async fn test_get_execution_payload_bid_below_min_bid_rejected() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    // Default mock bid: trustless 10 gwei, no execution payment
    let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
    let mock_relay = generate_mock_relay(relay_port, mock_state.signer.public_key())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let mut pbs_config = get_pbs_config(pbs_port);
    pbs_config.min_bid_wei = U256::from(20_000_000_000u64); // 20 gwei
    let config = to_pbs_config(chain, pbs_config, vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, None, vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(mock_state.received_execution_payload_bid(), 1);
    Ok(())
}

/// Test that a bid whose fee_recipient differs from the configured expected
/// value is dropped. The mock serves Address::ZERO as fee_recipient.
#[tokio::test]
async fn test_get_execution_payload_bid_wrong_fee_recipient_rejected() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
    let mock_relay = generate_mock_relay(relay_port, mock_state.signer.public_key())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let mut pbs_config = get_pbs_config(pbs_port);
    pbs_config.fee_recipient = Some(Address::from([1; 20]));
    let config = to_pbs_config(chain, pbs_config, vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, None, vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(mock_state.received_execution_payload_bid(), 1);
    Ok(())
}

/// Test that a MUX-level fee_recipient reaches bid validation: the mux's
/// validator gets its bid (mock serves Address::ZERO) rejected, while the
/// default config (no expected fee_recipient) still accepts it.
#[tokio::test]
async fn test_get_execution_payload_bid_mux_fee_recipient() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
    let mock_relay = generate_mock_relay(relay_port, mock_state.signer.public_key())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    // Default config has no expected fee_recipient; only the mux does
    let mut config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay.clone()]);
    let mut mux_pbs_config = get_pbs_config(pbs_port);
    mux_pbs_config.fee_recipient = Some(Address::from([1; 20]));
    let mux = RuntimeMuxConfig {
        id: String::from("fee-mux"),
        config: Arc::new(mux_pbs_config),
        relays: vec![mock_relay],
    };
    let mux_pubkey = random_secret().public_key();
    config.mux_lookup = Some(HashMap::from([(mux_pubkey.clone(), mux)]));

    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    // The mux validator's bid fails the fee_recipient check
    let res = mock_validator
        .do_get_execution_payload_bid(
            TEST_SLOT,
            B256::ZERO,
            B256::ZERO,
            Some(mux_pubkey),
            None,
            vec![EncodingType::Json],
        )
        .await?;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // A non-mux validator uses the default config and gets the bid
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, None, vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(mock_state.received_execution_payload_bid(), 2);
    Ok(())
}

/// The caller's auth data designates the downstream: only the relay whose
/// `expected_auth_data` matches is contacted, and its bid is returned.
#[tokio::test]
async fn test_get_execution_payload_bid_demux_routes_by_auth_data() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();

    let data_a = vec![0xaa, 0x01];
    let data_b = vec![0xbb, 0x02];
    let mut relays = Vec::new();
    let mut states = Vec::new();
    for data in [&data_a, &data_b] {
        let relay_listener = get_free_listener().await;
        let relay_port = relay_listener.local_addr()?.port();
        let state = Arc::new(MockRelayState::new(chain, random_secret()));
        relays.push(generate_mock_relay_with_auth_data(
            relay_port,
            state.signer.public_key(),
            data,
        )?);
        tokio::spawn(start_mock_relay_service_with_listener(state.clone(), relay_listener));
        states.push(state);
    }

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    let auth = opaque_auth(&data_a, TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(states[0].received_execution_payload_bid(), 1);
    assert_eq!(states[1].received_execution_payload_bid(), 0);
    Ok(())
}

/// Auth data carrying a builder URL (raw UTF-8 bytes, the spec default) routes
/// to the relay whose configured URL matches, ignoring the entry's userinfo.
#[tokio::test]
async fn test_get_execution_payload_bid_demux_by_url_bytes() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();

    let mut relays = Vec::new();
    let mut states = Vec::new();
    let mut urls = Vec::new();
    for _ in 0..2 {
        let relay_listener = get_free_listener().await;
        let relay_port = relay_listener.local_addr()?.port();
        let state = Arc::new(MockRelayState::new(chain, random_secret()));
        let relay = generate_mock_relay(relay_port, state.signer.public_key())?;
        urls.push(format!("http://0.0.0.0:{relay_port}/"));
        tokio::spawn(start_mock_relay_service_with_listener(state.clone(), relay_listener));
        relays.push(relay);
        states.push(state);
    }

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    // data = UTF-8 bytes of relay-0's URL
    let auth = opaque_auth(urls[0].as_bytes(), TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(states[0].received_execution_payload_bid(), 1);
    assert_eq!(states[1].received_execution_payload_bid(), 0);

    // URL bytes with a NUL-suffixed extra payload route the same way
    let mut with_extra = urls[1].as_bytes().to_vec();
    with_extra.push(0);
    with_extra.extend_from_slice(&[0xde, 0xad]);
    let auth = opaque_auth(&with_extra, TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(states[0].received_execution_payload_bid(), 1);
    assert_eq!(states[1].received_execution_payload_bid(), 1);

    // a URL matching no configured relay is a 400, nothing contacted
    let auth = opaque_auth(b"https://unknown-builder.example:9999/", TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(states[0].received_execution_payload_bid(), 1);
    assert_eq!(states[1].received_execution_payload_bid(), 1);
    Ok(())
}

/// Auth data matching no configured relay is rejected with 400 and the spec
/// data-mismatch message; no relay is contacted.
#[tokio::test]
async fn test_get_execution_payload_bid_demux_no_match_400() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
    let mock_relay =
        generate_mock_relay_with_auth_data(relay_port, mock_state.signer.public_key(), &[0xaa])?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    let auth = opaque_auth(&[0xbb], TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(mock_state.received_execution_payload_bid(), 0);
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 400);
    assert_eq!(
        body["message"],
        "Invalid SignedRequestAuthV1: auth.message.data does not match the value agreed with this builder"
    );
    Ok(())
}

/// A relay without `expected_auth_data` accepts any auth data by default, but
/// matches nothing when `strict_auth_data` is enabled.
#[tokio::test]
async fn test_get_execution_payload_bid_strict_auth_data() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;

    for (strict, expected_status, expected_count) in
        [(false, StatusCode::OK, 1), (true, StatusCode::BAD_REQUEST, 0)]
    {
        let pbs_listener = get_free_listener().await;
        let pbs_port = pbs_listener.local_addr()?.port();
        let relay_listener = get_free_listener().await;
        let relay_port = relay_listener.local_addr()?.port();

        let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
        let mock_relay = generate_mock_relay(relay_port, mock_state.signer.public_key())?;
        tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

        let mut pbs_config = get_pbs_config(pbs_port);
        pbs_config.strict_auth_data = strict;
        let config = to_pbs_config(chain, pbs_config, vec![mock_relay]);
        let state = PbsState::new(config, PathBuf::new());
        tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

        let mock_validator = MockValidator::new(pbs_port)?;
        wait_for_ready(&mock_validator).await?;

        let auth = opaque_auth(&[0xcc], TEST_SLOT);
        let res = mock_validator
            .do_get_execution_payload_bid(
                TEST_SLOT,
                B256::ZERO,
                B256::ZERO,
                None,
                Some(&auth),
                vec![EncodingType::Json],
            )
            .await?;
        assert_eq!(res.status(), expected_status, "strict={strict}");
        assert_eq!(mock_state.received_execution_payload_bid(), expected_count, "strict={strict}");
    }
    Ok(())
}

/// An opaque (non-URL) auth body is forwarded to the relays verbatim.
#[tokio::test]
async fn test_get_execution_payload_bid_forwards_opaque_auth() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
    let mock_relay = generate_mock_relay(relay_port, mock_state.signer.public_key())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    let data = vec![0xde, 0xad, 0xbe, 0xef];
    let auth = opaque_auth(&data, TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(mock_state.received_execution_payload_bid(), 1);
    assert_eq!(mock_state.received_auth_data(), Some(data));
    Ok(())
}

/// Build a `SignedRequestAuthV1` carrying opaque `data`. CB forwards it
/// unmodified; the signature is not verified, so an empty one suffices.
fn opaque_auth(data: &[u8], slot: u64) -> SignedRequestAuthV1 {
    SignedRequestAuthV1 {
        message: RequestAuthV1 {
            data: ssz_types::VariableList::new(data.to_vec()).expect("data fits in MAX_DATA_SIZE"),
            slot: Slot::new(slot),
        },
        signature: BlsSignature::empty(),
    }
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
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

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

/// The bid response is served as SSZ when the caller sends
/// Accept: application/octet-stream, with Eth-Consensus-Version on the 200.
#[tokio::test]
async fn test_get_execution_payload_bid_ssz_response() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
    let mock_relay = generate_mock_relay(relay_port, mock_state.signer.public_key())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, None, vec![
            EncodingType::Ssz,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::OK);

    let content_type =
        res.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default();
    assert_eq!(content_type, EncodingType::Ssz.to_string(), "response must be SSZ");

    let version =
        res.headers().get("eth-consensus-version").and_then(|v| v.to_str().ok()).map(str::to_owned);
    assert_eq!(version.as_deref(), Some("gloas"), "200 must set Eth-Consensus-Version");

    let bid = SignedExecutionPayloadBid::from_ssz_bytes(&res.bytes().await?)
        .expect("body must SSZ-decode to a SignedExecutionPayloadBid");
    assert_ne!(bid.message.block_hash.0, B256::ZERO);
    assert_eq!(bid.message.slot.as_u64(), TEST_SLOT);
    Ok(())
}

/// With NO Accept header the response defaults to SSZ (this endpoint is
/// SSZ-by-default): the 200 carries Content-Type: application/octet-stream and
/// the body SSZ-decodes to a SignedExecutionPayloadBid. Proves the
/// no-preference tiebreak is SSZ, not the legacy JSON default.
#[tokio::test]
async fn test_get_execution_payload_bid_no_accept_defaults_to_ssz() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
    let mock_relay = generate_mock_relay(relay_port, mock_state.signer.public_key())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    // An empty accept vec makes MockValidator send NO Accept header at all.
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, None, vec![])
        .await?;
    assert_eq!(res.status(), StatusCode::OK);

    let content_type =
        res.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default();
    assert_eq!(content_type, EncodingType::Ssz.to_string(), "no Accept header must default to SSZ");

    let bid = SignedExecutionPayloadBid::from_ssz_bytes(&res.bytes().await?)
        .expect("body must SSZ-decode to a SignedExecutionPayloadBid");
    assert_ne!(bid.message.block_hash.0, B256::ZERO);
    assert_eq!(bid.message.slot.as_u64(), TEST_SLOT);
    Ok(())
}

/// An explicit `Accept: application/json` is still obeyed even though the
/// endpoint defaults to SSZ when no preference is expressed. The 200 is JSON
/// and decodes to a GetExecutionPayloadBidResponse. The relay is JSON-only so
/// this also covers the JSON relay-leg decode path end to end.
#[tokio::test]
async fn test_get_execution_payload_bid_explicit_json_obeyed() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mock_state =
        Arc::new(MockRelayState::new(chain, random_secret()).with_json_only_response());
    let mock_relay = generate_mock_relay(relay_port, mock_state.signer.public_key())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, None, vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::OK);

    let content_type =
        res.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default();
    assert_eq!(
        content_type,
        EncodingType::Json.to_string(),
        "explicit Accept: application/json must be obeyed over the SSZ default"
    );

    let decoded = serde_json::from_slice::<GetExecutionPayloadBidResponse>(&res.bytes().await?)?;
    assert_eq!(decoded.slot(), TEST_SLOT);
    assert_ne!(decoded.block_hash(), B256::ZERO);
    Ok(())
}

/// End-to-end outbound SSZ decode: the relay serves the bid as SSZ (with the
/// Eth-Consensus-Version header), PBS decodes it on the relay leg and returns
/// 200 with the correct bid. A decode failure would drop the only relay and
/// yield 204, so a 200 with matching fields proves the SSZ relay-response
/// decode path actually ran.
#[tokio::test]
async fn test_get_execution_payload_bid_relay_ssz_response_roundtrip() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    // Relay serves ONLY SSZ, so PBS must decode the SSZ bid on the relay leg.
    let mock_state = Arc::new(
        MockRelayState::new(chain, random_secret())
            .with_ssz_only_response()
            .with_trustless_bid_gwei(42),
    );
    let mock_relay = generate_mock_relay(relay_port, mock_state.signer.public_key())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    // BN asks for JSON; PBS decodes SSZ from the relay and re-encodes to JSON.
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, None, vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(mock_state.received_execution_payload_bid(), 1);

    let decoded = serde_json::from_slice::<GetExecutionPayloadBidResponse>(&res.bytes().await?)?;
    assert_eq!(decoded.slot(), TEST_SLOT);
    assert_eq!(decoded.value(), 42, "bid value must survive the SSZ relay-leg round-trip");
    assert_ne!(decoded.block_hash(), B256::ZERO);
    Ok(())
}

/// The relay serves an SSZ bid 200 WITHOUT the Eth-Consensus-Version header.
/// PBS cannot decode the (non-self-describing) SSZ without the fork, so it
/// surfaces a clean PbsError and drops the bid rather than returning a bogus
/// 200 or panicking. With a single relay this drop yields a 204 to the BN.
#[tokio::test]
async fn test_get_execution_payload_bid_relay_ssz_missing_version_header() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mock_state = Arc::new(
        MockRelayState::new(chain, random_secret())
            .with_ssz_only_response()
            .with_epbs_omit_consensus_version(),
    );
    let mock_relay = generate_mock_relay(relay_port, mock_state.signer.public_key())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, None, vec![])
        .await?;
    // The relay was contacted, but its undecodable SSZ bid was dropped.
    assert_eq!(mock_state.received_execution_payload_bid(), 1);
    // Never a bogus 200; the response exists (no panic). Single dropped relay ->
    // 204.
    assert_ne!(res.status(), StatusCode::OK, "an undecodable SSZ bid must not yield 200");
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    Ok(())
}

/// An unsupported Accept type is rejected with 406 before any relay is queried
/// (a typed error, not a 500).
#[tokio::test]
async fn test_get_execution_payload_bid_unsupported_accept_406() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
    let mock_relay = generate_mock_relay(relay_port, mock_state.signer.public_key())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

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
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header("accept", "application/xml")
        .send()
        .await?;
    assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE);
    assert_eq!(mock_state.received_execution_payload_bid(), 0, "406 short-circuits before relays");
    Ok(())
}

/// An SSZ-encoded auth body (application/octet-stream) is decoded and forwarded
/// to the relay, same as JSON.
#[tokio::test]
async fn test_get_execution_payload_bid_ssz_auth_forwarded() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
    let mock_relay = generate_mock_relay(relay_port, mock_state.signer.public_key())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    let data = vec![0xde, 0xad, 0xbe, 0xef];
    let ssz_body = opaque_auth(&data, TEST_SLOT).as_ssz_bytes();
    let url = format!(
        "{}eth/v1/builder/execution_payload_bid/{}/{}/{}/{}",
        mock_validator.comm_boost.config.entry.url,
        TEST_SLOT,
        B256::ZERO,
        B256::ZERO,
        "0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae",
    );
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(ssz_body)
        .send()
        .await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(mock_state.received_auth_data(), Some(data), "relay must receive the decoded auth");
    Ok(())
}

/// A present-but-malformed auth body is rejected with 400 and an ErrorMessage
/// JSON body, before any relay is queried.
#[tokio::test]
async fn test_get_execution_payload_bid_malformed_auth_400() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
    let mock_relay = generate_mock_relay(relay_port, mock_state.signer.public_key())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    let url = format!(
        "{}eth/v1/builder/execution_payload_bid/{}/{}/{}/{}",
        mock_validator.comm_boost.config.entry.url,
        TEST_SLOT,
        B256::ZERO,
        B256::ZERO,
        "0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae",
    );
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, "application/json")
        .body(vec![0xff, 0x00, 0x99])
        .send()
        .await?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        mock_state.received_execution_payload_bid(),
        0,
        "malformed auth rejected before relays"
    );
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 400);
    assert!(
        body["message"].as_str().unwrap_or_default().contains("decoding"),
        "error body must be an ErrorMessage describing the decode failure"
    );
    Ok(())
}

async fn test_get_execution_payload_bid_impl(
    relay_states: Vec<MockRelayState>,
    expected_code: StatusCode,
    expected_relay_counts: &[u64],
    expected_value: Option<u64>,
    max_execution_payment_gwei: u64,
) -> Result<()> {
    // Setup test environment
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();

    // Run one mock relay per state so per-relay knobs and counters work
    let mut relays = Vec::new();
    let mut states = Vec::new();
    for state in relay_states {
        let relay_listener = get_free_listener().await;
        let relay_port = relay_listener.local_addr()?.port();
        let state = Arc::new(state);
        let relay = generate_mock_relay(relay_port, state.signer.public_key())?;
        tokio::spawn(start_mock_relay_service_with_listener(state.clone(), relay_listener));
        relays.push(relay);
        states.push(state);
    }

    // Run the PBS service
    let mut pbs_config = get_pbs_config(pbs_port);
    pbs_config.max_execution_payment_gwei = max_execution_payment_gwei;
    let config = to_pbs_config(chain, pbs_config, relays);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    info!("Sending get execution payload bid");
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, None, vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), expected_code);
    for (state, expected) in states.iter().zip(expected_relay_counts) {
        assert_eq!(state.received_execution_payload_bid(), *expected);
    }
    if expected_code != StatusCode::OK {
        return Ok(());
    }

    // Eth-Consensus-Version required on 200
    let version_header =
        res.headers().get("eth-consensus-version").and_then(|v| v.to_str().ok()).map(str::to_owned);
    assert_eq!(
        version_header.as_deref(),
        Some("gloas"),
        "200 response must set Eth-Consensus-Version: gloas"
    );

    // Get the data
    let res = serde_json::from_slice::<GetExecutionPayloadBidResponse>(&res.bytes().await?)?;
    assert_eq!(res.version.to_string(), "gloas");
    assert_eq!(res.slot(), TEST_SLOT);
    assert_eq!(res.parent_hash(), B256::ZERO);
    assert_eq!(res.parent_root(), B256::ZERO);
    assert_ne!(res.block_hash(), B256::ZERO);
    assert!(res.execution_payment() <= max_execution_payment_gwei);
    if let Some(expected_value) = expected_value {
        assert_eq!(res.value(), expected_value);
    }
    // The winning bid must be signed by one of the configured relays
    let object_root = res.data.message.tree_hash_root();
    assert!(
        states.iter().any(|s| sign_execution_payload_bid_root(
            &s.signer,
            &object_root,
            GLOAS_FORK_VERSION,
            GENESIS_VALIDATORS_ROOT.into(),
        ) == res.data.signature),
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
