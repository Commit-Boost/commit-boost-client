use std::{collections::HashMap, path::PathBuf, sync::Arc};

use alloy::primitives::{Address, B256, U256};
use cb_common::{
    config::RuntimeMuxConfig,
    constants::{GENESIS_VALIDATORS_ROOT, GLOAS_FORK_VERSION},
    pbs::{
        DEFAULT_BID_POLL_TIMEOUT_MS, GetExecutionPayloadBidInfo, GetExecutionPayloadBidResponse,
        HEADER_START_TIME_UNIX_MS, HEADER_TIMEOUT_MS, SignedExecutionPayloadBid,
    },
    signature::sign_execution_payload_bid_root,
    signer::random_secret,
    types::Chain,
    utils::utcnow_ms,
    wire::EncodingType,
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service_with_listener},
    mock_validator::MockValidator,
    utils::{
        generate_mock_relay, generate_mock_relay_url_only, generate_mock_relay_with_auth_data,
        generate_mock_relay_with_max_payment, generate_mock_relay_with_timing_games,
        get_free_listener, get_pbs_config, opaque_auth, setup_relay, setup_relays, setup_test_env,
        signed_auth, to_pbs_config, wait_for_ready,
    },
};
use eyre::Result;
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

    let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
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

    let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
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
    let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(
            TEST_SLOT,
            B256::ZERO,
            B256::ZERO,
            Some(mux_pubkey),
            Some(&auth),
            vec![EncodingType::Json],
        )
        .await?;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // A non-mux validator uses the default config and gets the bid
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
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
        // No expected_auth_data: these relays are addressed by URL-carrying data
        let relay = generate_mock_relay_url_only(relay_port, state.signer.public_key())?;
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
        "Invalid SignedRequestAuth: auth.message.data does not match the value agreed with this builder"
    );
    Ok(())
}

/// Opaque auth data matching no configured relay is a 400 with the builder's
/// data-mismatch message, and no relay receives anything: with auth data
/// required and unique per entry, CB has no builder to proxy to and answers as
/// a builder would.
#[tokio::test]
async fn test_get_execution_payload_bid_unmatched_opaque_auth_400() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
    let mock_relay = generate_mock_relay_url_only(relay_port, mock_state.signer.public_key())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    let auth = opaque_auth(&[0xcc], TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(mock_state.received_execution_payload_bid(), 0, "no relay receives anything");
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 400);
    assert_eq!(
        body["message"],
        "Invalid SignedRequestAuth: auth.message.data does not match the value agreed with this builder"
    );
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

    let data = vec![0xde, 0xad, 0xbe, 0xef];
    let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
    let mock_relay =
        generate_mock_relay_with_auth_data(relay_port, mock_state.signer.public_key(), &data)?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

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

/// The spec makes the auth body mandatory: a request without one is a 400 with
/// an ErrorMessage body, before any relay is queried.
#[tokio::test]
async fn test_get_execution_payload_bid_missing_auth_400() -> Result<()> {
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;

    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, None, vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(mock_state.received_execution_payload_bid(), 0, "no auth means no relay call");
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 400);
    assert!(
        body["message"].as_str().unwrap_or_default().contains("missing request body"),
        "error body must name the missing body, got: {}",
        body["message"]
    );
    Ok(())
}

/// `auth.message.slot` must match the proposal slot in the request path.
#[tokio::test]
async fn test_get_execution_payload_bid_auth_slot_mismatch_400() -> Result<()> {
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;

    let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT + 1);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        mock_state.received_execution_payload_bid(),
        0,
        "slot mismatch precedes relay calls"
    );
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 400);
    assert_eq!(
        body["message"],
        "Invalid SignedRequestAuth: auth.message.slot does not match the proposal slot in the request path"
    );
    Ok(())
}

/// With `verify_request_auth` on, a bad auth signature is a 401 and a good one
/// passes through to the relay.
#[tokio::test]
async fn test_get_execution_payload_bid_verify_request_auth_enabled() -> Result<()> {
    let secret_key = random_secret();
    let proposer_pubkey = secret_key.public_key();
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |cfg| cfg.verify_request_auth = true, generate_mock_relay)
            .await?;

    // An empty signature never verifies under DOMAIN_REQUEST_AUTH
    let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(
            TEST_SLOT,
            B256::ZERO,
            B256::ZERO,
            Some(proposer_pubkey.clone()),
            Some(&auth),
            vec![EncodingType::Json],
        )
        .await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(mock_state.received_execution_payload_bid(), 0, "bad auth precedes relay calls");
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 401);
    assert_eq!(body["message"], "Invalid SignedRequestAuth: signature verification failed");

    let auth = signed_auth(&secret_key, &[0xde, 0xad], TEST_SLOT, Chain::Hoodi);
    let res = mock_validator
        .do_get_execution_payload_bid(
            TEST_SLOT,
            B256::ZERO,
            B256::ZERO,
            Some(proposer_pubkey),
            Some(&auth),
            vec![EncodingType::Json],
        )
        .await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(mock_state.received_execution_payload_bid(), 1);
    Ok(())
}

/// Both timing headers are required: the send time and the timeout are what
/// bound every downstream call, so a request missing either is a 400 and no
/// relay is contacted.
#[tokio::test]
async fn test_get_execution_payload_bid_missing_timing_headers_400() -> Result<()> {
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;
    let url = mock_validator.comm_boost.get_execution_payload_bid_url(
        TEST_SLOT,
        &B256::ZERO,
        &B256::ZERO,
        &random_secret().public_key(),
    )?;
    let body = opaque_auth(&[0xde, 0xad], TEST_SLOT).as_ssz_bytes();

    // no headers at all / only the send time / only the timeout / zero timeout
    let cases: Vec<Vec<(&str, String)>> = vec![
        vec![],
        vec![(HEADER_START_TIME_UNIX_MS, utcnow_ms().to_string())],
        vec![(HEADER_TIMEOUT_MS, "1000".to_string())],
        vec![
            (HEADER_START_TIME_UNIX_MS, utcnow_ms().to_string()),
            (HEADER_TIMEOUT_MS, "0".to_string()),
        ],
    ];
    for headers in cases {
        // Version header present throughout: only the timing headers vary
        let mut req = mock_validator
            .comm_boost
            .client
            .post(url.clone())
            .header("Eth-Consensus-Version", "gloas")
            .body(body.clone());
        for (name, value) in &headers {
            req = req.header(*name, value);
        }
        let res = req.send().await?;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "headers: {headers:?}");
        let json: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
        assert_eq!(json["code"], 400);
        assert_eq!(
            json["message"],
            "Invalid request: Date-Milliseconds and X-Timeout-Ms headers are required"
        );
    }
    assert_eq!(mock_state.received_execution_payload_bid(), 0, "no relay call for a 400");
    Ok(())
}

/// A deadline that has already passed means there is no time to serve the
/// request: CB returns 204 rather than calling a relay it cannot beat.
#[tokio::test]
async fn test_get_execution_payload_bid_expired_deadline_204() -> Result<()> {
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;
    let url = mock_validator.comm_boost.get_execution_payload_bid_url(
        TEST_SLOT,
        &B256::ZERO,
        &B256::ZERO,
        &random_secret().public_key(),
    )?;
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(HEADER_START_TIME_UNIX_MS, utcnow_ms() - 5_000)
        .header(HEADER_TIMEOUT_MS, 1_000u64)
        .header("Eth-Consensus-Version", "gloas")
        .body(opaque_auth(&[0xde, 0xad], TEST_SLOT).as_ssz_bytes())
        .send()
        .await?;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(mock_state.received_execution_payload_bid(), 0, "no relay call past the deadline");
    Ok(())
}

/// By default CB does not verify the auth signature: a bad one is forwarded to
/// the builder, which verifies it itself.
#[tokio::test]
async fn test_get_execution_payload_bid_bad_auth_signature_forwarded_by_default() -> Result<()> {
    let proposer_pubkey = random_secret().public_key();
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;

    let data = vec![0xde, 0xad];
    let auth = opaque_auth(&data, TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(
            TEST_SLOT,
            B256::ZERO,
            B256::ZERO,
            Some(proposer_pubkey),
            Some(&auth),
            vec![EncodingType::Json],
        )
        .await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(mock_state.received_execution_payload_bid(), 1);
    // The spec requires message AND signature to reach the builder unchanged
    let seen = mock_state.received_auth().expect("relay saw an auth");
    assert_eq!(seen.message.data.to_vec(), data);
    assert_eq!(seen.message.slot, auth.message.slot);
    assert_eq!(seen.signature, auth.signature, "signature must be forwarded byte-for-byte");
    Ok(())
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
    // The auth body, timing headers and version header are required, so even
    // the bare-URL shape test must carry them
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(HEADER_START_TIME_UNIX_MS, utcnow_ms())
        .header(HEADER_TIMEOUT_MS, 60_000u64)
        .header("Eth-Consensus-Version", "gloas")
        .body(opaque_auth(&[0xde, 0xad], TEST_SLOT).as_ssz_bytes())
        .send()
        .await?;
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

    let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
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
    let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![])
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

    let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
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
    let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
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

    let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![])
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
        .header("Eth-Consensus-Version", "gloas")
        .body(opaque_auth(&[0xde, 0xad], TEST_SLOT).as_ssz_bytes())
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

    let data = vec![0xde, 0xad, 0xbe, 0xef];
    let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
    let mock_relay =
        generate_mock_relay_with_auth_data(relay_port, mock_state.signer.public_key(), &data)?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

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
        .header("Eth-Consensus-Version", "gloas")
        .header(HEADER_START_TIME_UNIX_MS, utcnow_ms())
        .header(HEADER_TIMEOUT_MS, 60_000u64)
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

/// Boot PBS in front of a single timing-games relay driven by `mock_state`, so
/// a test can observe the bid poll ladder from the builder's side.
async fn setup_timing_games_relay(
    mock_state: Arc<MockRelayState>,
    frequency_get_header_ms: u64,
    bid_poll_timeout_ms: Option<u64>,
) -> Result<MockValidator> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mock_relay = generate_mock_relay_with_timing_games(
        relay_port,
        mock_state.signer.public_key(),
        frequency_get_header_ms,
        bid_poll_timeout_ms,
    )?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state, relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;
    Ok(mock_validator)
}

/// Request a bid advertising `budget_ms` as the proposer's `X-Timeout-Ms`.
async fn get_bid_with_budget(
    mock_validator: &MockValidator,
    budget_ms: u64,
) -> Result<reqwest::Response> {
    let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT);
    Ok(mock_validator
        .do_get_execution_payload_bid_with_timeout(
            TEST_SLOT,
            B256::ZERO,
            B256::ZERO,
            None,
            Some(&auth),
            vec![EncodingType::Json],
            budget_ms,
        )
        .await?)
}

/// No poll may promise the builder more time than the shared deadline still has
/// left when it is sent. Poll `i` goes out one cadence step after poll `i - 1`,
/// so the budget left for it is at most `budget_ms - i * frequency_ms`.
fn assert_no_poll_overspends(timeouts: &[u64], budget_ms: u64, frequency_ms: u64) {
    for (i, timeout) in timeouts.iter().enumerate() {
        assert!(
            timeout + i as u64 * frequency_ms <= budget_ms,
            "poll {i} promised more than the deadline had left: {timeouts:?}"
        );
    }
}

/// The ladder's shape: with timing games on, a known cadence and a generous
/// deadline, every poll but the last carries the bounded `bid_poll_timeout_ms`
/// and the last one carries the whole remaining budget.
#[tokio::test]
async fn test_get_execution_payload_bid_ladder_timeout_shape() -> Result<()> {
    const FREQ_MS: u64 = 500;
    const POLL_TIMEOUT_MS: u64 = 100;
    const BUDGET_MS: u64 = 2_000;

    let mock_state = Arc::new(MockRelayState::new(Chain::Hoodi, random_secret()));
    let mock_validator =
        setup_timing_games_relay(mock_state.clone(), FREQ_MS, Some(POLL_TIMEOUT_MS)).await?;

    let res = get_bid_with_budget(&mock_validator, BUDGET_MS).await?;
    assert_eq!(res.status(), StatusCode::OK);

    // The exact poll count is driven by real cadence sleeps, which only ever
    // overrun under load, so assert the ladder SHAPE rather than a fixed count:
    // every rung but the last is bounded by bid_poll_timeout_ms, and the last
    // holds longer for the remaining budget. No poll may overspend the deadline.
    let timeouts = mock_state.received_bid_timeouts();
    assert!(
        timeouts.len() >= 2,
        "the ladder must fire bounded rungs plus a final poll, got {timeouts:?}"
    );
    let (last, bounded) = timeouts.split_last().unwrap();
    assert!(
        bounded.iter().all(|timeout| *timeout == POLL_TIMEOUT_MS),
        "every poll but the last must be bounded by bid_poll_timeout_ms: {timeouts:?}"
    );
    assert!(
        *last > POLL_TIMEOUT_MS,
        "the last poll must hold longer than a bounded rung for the remaining budget, got {last}"
    );
    assert_no_poll_overspends(&timeouts, BUDGET_MS, FREQ_MS);

    // A sleep never returns early, so arrivals only drift later; 10ms covers ms
    // rounding
    let arrivals = mock_state.received_bid_arrivals_ms();
    for pair in arrivals.windows(2) {
        assert!(
            pair[1].saturating_sub(pair[0]) + 10 >= FREQ_MS,
            "polls must be spaced by the configured cadence: {arrivals:?}"
        );
    }
    Ok(())
}

/// Best-of across the whole ladder: with a builder improving its bid on every
/// poll, the returned bid is the LAST poll's, proving `select_max_bid` spans
/// every rung instead of returning the first one that landed.
#[tokio::test]
async fn test_get_execution_payload_bid_ladder_returns_best_poll() -> Result<()> {
    const FREQ_MS: u64 = 400;
    const POLL_TIMEOUT_MS: u64 = 300;
    const BUDGET_MS: u64 = 1_200;
    const STEP_GWEI: u64 = 7;
    const BASE_GWEI: u64 = 10;

    let mock_state = Arc::new(
        MockRelayState::new(Chain::Hoodi, random_secret())
            .with_trustless_bid_gwei(BASE_GWEI)
            .with_improving_bids(STEP_GWEI),
    );
    let mock_validator =
        setup_timing_games_relay(mock_state.clone(), FREQ_MS, Some(POLL_TIMEOUT_MS)).await?;

    let res = get_bid_with_budget(&mock_validator, BUDGET_MS).await?;
    assert_eq!(res.status(), StatusCode::OK);

    // This builder answers instantly, so every rung lands a bid and the last is the
    // best
    let polls = mock_state.received_execution_payload_bid();
    assert!(polls > 1, "the ladder must have fired more than one poll, got {polls}");

    let decoded = serde_json::from_slice::<GetExecutionPayloadBidResponse>(&res.bytes().await?)?;
    assert_eq!(
        decoded.value(),
        BASE_GWEI + STEP_GWEI * (polls - 1),
        "the winner must be the last poll's bid, not the first one to land"
    );
    Ok(())
}

/// A builder that holds every request longer than `bid_poll_timeout_ms` times
/// out the early rungs, but the last poll holds for the full remainder, so the
/// run still yields a bid.
#[tokio::test]
async fn test_get_execution_payload_bid_ladder_slow_builder_still_bids() -> Result<()> {
    const FREQ_MS: u64 = 500;
    const POLL_TIMEOUT_MS: u64 = 100;
    const DELAY_MS: u64 = 150;
    const BUDGET_MS: u64 = 1_500;

    let mock_state =
        Arc::new(MockRelayState::new(Chain::Hoodi, random_secret()).with_bid_delay_ms(DELAY_MS));
    let mock_validator =
        setup_timing_games_relay(mock_state.clone(), FREQ_MS, Some(POLL_TIMEOUT_MS)).await?;

    let res = get_bid_with_budget(&mock_validator, BUDGET_MS).await?;
    assert_eq!(res.status(), StatusCode::OK, "the last poll outlasts the builder's delay");

    // Cadence sleeps only overrun under load, so the count can dip; assert the
    // ladder shape (bounded early rungs plus a final poll that outlasts the
    // builder's delay) rather than a fixed count.
    let timeouts = mock_state.received_bid_timeouts();
    assert!(
        timeouts.len() >= 2,
        "the ladder must fire early rungs plus a final poll, got {timeouts:?}"
    );
    let (last, early) = timeouts.split_last().unwrap();
    assert!(
        early.iter().all(|timeout| *timeout < DELAY_MS),
        "the early polls must expire before this builder answers: {timeouts:?}"
    );
    assert!(*last > DELAY_MS, "the last poll must outlast the builder's delay, got {last}");
    assert_no_poll_overspends(&timeouts, BUDGET_MS, FREQ_MS);
    Ok(())
}

/// The converse that motivates the ladder: when the builder answers inside
/// `bid_poll_timeout_ms`, the early rungs land bids in hand well before the
/// deadline instead of every poll being staked on the final instant.
#[tokio::test]
async fn test_get_execution_payload_bid_ladder_early_polls_land_bids() -> Result<()> {
    const FREQ_MS: u64 = 400;
    const POLL_TIMEOUT_MS: u64 = 300;
    const DELAY_MS: u64 = 100;
    const BUDGET_MS: u64 = 1_500;

    let mock_state =
        Arc::new(MockRelayState::new(Chain::Hoodi, random_secret()).with_bid_delay_ms(DELAY_MS));
    let mock_validator =
        setup_timing_games_relay(mock_state.clone(), FREQ_MS, Some(POLL_TIMEOUT_MS)).await?;

    let res = get_bid_with_budget(&mock_validator, BUDGET_MS).await?;
    assert_eq!(res.status(), StatusCode::OK);

    // Each early poll has 200ms of slack over the builder's delay
    let served = mock_state.served_execution_payload_bid();
    assert!(served > 1, "the early rungs must land bids, only {served} poll(s) were answered");
    let timeouts = mock_state.received_bid_timeouts();
    assert!(
        timeouts.split_last().unwrap().1.iter().all(|timeout| *timeout > DELAY_MS),
        "the early polls must outlast this builder's delay: {timeouts:?}"
    );
    Ok(())
}

/// The proposer's deadline, not the cadence alone, sizes the ladder: a small
/// `X-Timeout-Ms` buys fewer polls than a large one, and no poll ever promises
/// more than the budget it was cut from.
#[tokio::test]
async fn test_get_execution_payload_bid_deadline_clamps_ladder() -> Result<()> {
    const FREQ_MS: u64 = 200;
    const POLL_TIMEOUT_MS: u64 = 100;
    const SMALL_BUDGET_MS: u64 = 400;
    const LARGE_BUDGET_MS: u64 = 1_600;

    let mut polls = Vec::new();
    for budget_ms in [SMALL_BUDGET_MS, LARGE_BUDGET_MS] {
        let mock_state = Arc::new(MockRelayState::new(Chain::Hoodi, random_secret()));
        let mock_validator =
            setup_timing_games_relay(mock_state.clone(), FREQ_MS, Some(POLL_TIMEOUT_MS)).await?;

        let res = get_bid_with_budget(&mock_validator, budget_ms).await?;
        assert_eq!(res.status(), StatusCode::OK, "budget {budget_ms}");

        let timeouts = mock_state.received_bid_timeouts();
        assert_no_poll_overspends(&timeouts, budget_ms, FREQ_MS);
        polls.push(timeouts);
    }

    // 400ms of budget buys the first poll plus a last one for the remainder
    assert_eq!(polls[0].len(), 2, "a tight deadline must cut the ladder short: {:?}", polls[0]);
    assert!(
        polls[1].len() > polls[0].len(),
        "a larger deadline must buy more polls: {:?} vs {:?}",
        polls[1],
        polls[0]
    );
    Ok(())
}

/// Degradation to the pre-ladder behavior: a budget shorter than
/// `bid_poll_timeout_ms` leaves no room to bound anything, so CB sends exactly
/// one poll carrying the whole budget.
#[tokio::test]
async fn test_get_execution_payload_bid_short_budget_single_poll() -> Result<()> {
    const FREQ_MS: u64 = 1_000;
    const BUDGET_MS: u64 = 300;

    // Default bid_poll_timeout_ms, which is larger than the whole budget here
    assert!(DEFAULT_BID_POLL_TIMEOUT_MS > BUDGET_MS);
    let mock_state = Arc::new(MockRelayState::new(Chain::Hoodi, random_secret()));
    let mock_validator = setup_timing_games_relay(mock_state.clone(), FREQ_MS, None).await?;

    let res = get_bid_with_budget(&mock_validator, BUDGET_MS).await?;
    assert_eq!(res.status(), StatusCode::OK);

    let timeouts = mock_state.received_bid_timeouts();
    assert_eq!(timeouts.len(), 1, "a budget under one cadence step is a single poll: {timeouts:?}");
    // The single poll gets the budget minus transit; 150ms of slack for transit
    assert!(
        timeouts[0] <= BUDGET_MS && timeouts[0] >= 150,
        "the only poll must carry the whole budget, got {}",
        timeouts[0]
    );
    Ok(())
}

/// A relay's `bid_poll_timeout_ms` overrides the default bound on every poll
/// but the last.
#[tokio::test]
async fn test_get_execution_payload_bid_poll_timeout_override() -> Result<()> {
    const FREQ_MS: u64 = 600;
    const BUDGET_MS: u64 = 2_000;
    const CUSTOM_POLL_TIMEOUT_MS: u64 = 150;

    for (configured, expected) in [
        (None, DEFAULT_BID_POLL_TIMEOUT_MS),
        (Some(CUSTOM_POLL_TIMEOUT_MS), CUSTOM_POLL_TIMEOUT_MS),
    ] {
        let mock_state = Arc::new(MockRelayState::new(Chain::Hoodi, random_secret()));
        let mock_validator =
            setup_timing_games_relay(mock_state.clone(), FREQ_MS, configured).await?;

        let res = get_bid_with_budget(&mock_validator, BUDGET_MS).await?;
        assert_eq!(res.status(), StatusCode::OK, "configured={configured:?}");

        let timeouts = mock_state.received_bid_timeouts();
        assert!(timeouts.len() > 1, "configured={configured:?}, got {timeouts:?}");
        assert!(
            timeouts.split_last().unwrap().1.iter().all(|timeout| *timeout == expected),
            "configured={configured:?} must bound the early polls at {expected}: {timeouts:?}"
        );
    }
    Ok(())
}

/// A relay with nothing to offer answers 204 on every poll. That is an answer,
/// not a failure, so the ladder must surface it exactly like the single-request
/// path does rather than reporting the relay as timed out.
#[tokio::test]
async fn test_get_execution_payload_bid_ladder_no_bid_is_204() -> Result<()> {
    const FREQ_MS: u64 = 300;
    const POLL_TIMEOUT_MS: u64 = 200;
    const BUDGET_MS: u64 = 1_000;

    let mock_state =
        Arc::new(MockRelayState::new(Chain::Hoodi, random_secret()).with_no_epbs_bid());
    let mock_validator =
        setup_timing_games_relay(mock_state.clone(), FREQ_MS, Some(POLL_TIMEOUT_MS)).await?;

    let res = get_bid_with_budget(&mock_validator, BUDGET_MS).await?;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "a 204 from every poll must stay a 204");

    let polls = mock_state.received_execution_payload_bid();
    assert!(polls > 1, "the ladder must have polled more than once, got {polls}");
    Ok(())
}

/// One of two relays errors on the bid endpoint; the other still serves a valid
/// bid, so the request is a 200 carrying the surviving relay's bid. Guards
/// against a partial failure aborting the join or poisoning `select_max_bid`.
#[tokio::test]
async fn test_get_execution_payload_bid_one_relay_fails_other_wins_200() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, states) = setup_relays(chain, vec![
        MockRelayState::new(chain, random_secret()),
        MockRelayState::new(chain, random_secret()),
    ])
    .await?;

    // The first relay errors; the second serves the default valid bid
    states[0].set_response_override(StatusCode::INTERNAL_SERVER_ERROR);

    let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(res.status(), StatusCode::OK, "a surviving relay still wins the auction");

    let decoded = serde_json::from_slice::<GetExecutionPayloadBidResponse>(&res.bytes().await?)?;
    let object_root = decoded.data.message.tree_hash_root();
    assert_eq!(
        decoded.data.signature,
        sign_execution_payload_bid_root(
            &states[1].signer,
            &object_root,
            GLOAS_FORK_VERSION,
            GENESIS_VALIDATORS_ROOT.into(),
        ),
        "the winning bid must be the surviving relay's"
    );
    assert_ne!(
        decoded.data.signature,
        sign_execution_payload_bid_root(
            &states[0].signer,
            &object_root,
            GLOAS_FORK_VERSION,
            GENESIS_VALIDATORS_ROOT.into(),
        ),
        "the failed relay must not have won"
    );
    Ok(())
}

/// Every relay erroring on the bid endpoint degrades to 204 (no bid), never a
/// 502: this endpoint has no bad-gateway path, a dead or erroring relay simply
/// contributes no bid. This is the documented contract.
#[tokio::test]
async fn test_get_execution_payload_bid_all_relays_fail_204_not_502() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, states) = setup_relays(chain, vec![
        MockRelayState::new(chain, random_secret()),
        MockRelayState::new(chain, random_secret()),
    ])
    .await?;

    for state in &states {
        state.set_response_override(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
            EncodingType::Json,
        ])
        .await?;
    assert_eq!(
        res.status(),
        StatusCode::NO_CONTENT,
        "all relays erroring is a no-bid 204, not a 502"
    );
    assert_eq!(states[0].received_execution_payload_bid(), 1, "every relay is asked");
    assert_eq!(states[1].received_execution_payload_bid(), 1, "every relay is asked");
    Ok(())
}

/// An unsupported request `Content-Type` is a 415 before any relay is queried,
/// mirroring the preferences endpoint.
#[tokio::test]
async fn test_get_execution_payload_bid_unsupported_content_type_415() -> Result<()> {
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;

    let url = mock_validator.comm_boost.get_execution_payload_bid_url(
        TEST_SLOT,
        &B256::ZERO,
        &B256::ZERO,
        &random_secret().public_key(),
    )?;
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, "text/plain")
        .header(HEADER_START_TIME_UNIX_MS, utcnow_ms())
        .header(HEADER_TIMEOUT_MS, 60_000u64)
        .body(opaque_auth(&[0xde, 0xad], TEST_SLOT).as_ssz_bytes())
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        mock_state.received_execution_payload_bid(),
        0,
        "415 short-circuits before any relay call"
    );
    Ok(())
}

/// An SSZ auth body missing `Eth-Consensus-Version` is a 400: builder-specs
/// fork-versions the request wire type, so the header is required to accept the
/// SSZ form (and the same request with the header is served).
#[tokio::test]
async fn test_get_execution_payload_bid_ssz_missing_version_400() -> Result<()> {
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;

    let url = mock_validator.comm_boost.get_execution_payload_bid_url(
        TEST_SLOT,
        &B256::ZERO,
        &B256::ZERO,
        &random_secret().public_key(),
    )?;
    // Note: SSZ Content-Type but no Eth-Consensus-Version
    let res = mock_validator
        .comm_boost
        .client
        .post(url.clone())
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(HEADER_START_TIME_UNIX_MS, utcnow_ms())
        .header(HEADER_TIMEOUT_MS, 60_000u64)
        .body(opaque_auth(&[0xde, 0xad], TEST_SLOT).as_ssz_bytes())
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        mock_state.received_execution_payload_bid(),
        0,
        "an undecodable request must not forward"
    );
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 400);

    // The identical request carrying the literal spec header is served
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header("Eth-Consensus-Version", "gloas")
        .header(HEADER_START_TIME_UNIX_MS, utcnow_ms())
        .header(HEADER_TIMEOUT_MS, 60_000u64)
        .body(opaque_auth(&[0xde, 0xad], TEST_SLOT).as_ssz_bytes())
        .send()
        .await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(mock_state.received_execution_payload_bid(), 1);
    Ok(())
}

/// JSON is self-describing, so per CB policy a JSON auth body with no version
/// header is best-effort accepted rather than rejected over a missing header.
#[tokio::test]
async fn test_get_execution_payload_bid_json_no_version_200() -> Result<()> {
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;

    let url = mock_validator.comm_boost.get_execution_payload_bid_url(
        TEST_SLOT,
        &B256::ZERO,
        &B256::ZERO,
        &random_secret().public_key(),
    )?;
    // No Eth-Consensus-Version: best effort recovers the self-describing JSON
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, "application/json")
        .header(HEADER_START_TIME_UNIX_MS, utcnow_ms())
        .header(HEADER_TIMEOUT_MS, 60_000u64)
        .body(serde_json::to_vec(&opaque_auth(&[0xde, 0xad], TEST_SLOT))?)
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(mock_state.received_execution_payload_bid(), 1);
    Ok(())
}

/// Without timing games, a relay slower than the proposer's `X-Timeout-Ms` is
/// dropped on the single-poll `send_one_*` path, so the request degrades to 204
/// rather than waiting the relay out.
#[tokio::test]
async fn test_get_execution_payload_bid_slow_relay_times_out_204() -> Result<()> {
    const DELAY_MS: u64 = 600;
    const BUDGET_MS: u64 = 200;

    let chain = Chain::Hoodi;
    let (mock_validator, states) = setup_relays(chain, vec![
        MockRelayState::new(chain, random_secret()).with_bid_delay_ms(DELAY_MS),
    ])
    .await?;

    let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid_with_timeout(
            TEST_SLOT,
            B256::ZERO,
            B256::ZERO,
            None,
            Some(&auth),
            vec![EncodingType::Json],
            BUDGET_MS,
        )
        .await?;
    assert_eq!(
        res.status(),
        StatusCode::NO_CONTENT,
        "a relay slower than the deadline is dropped, not awaited"
    );
    assert_eq!(states[0].received_execution_payload_bid(), 1, "the relay was still contacted");
    Ok(())
}

/// A per-relay `max_execution_payment_gwei` cap stricter than the global one
/// rejects a bid whose execution payment exceeds it. Same served bid, same high
/// global cap: only the per-relay override flips accept (200) to reject (204),
/// isolating it as the cause.
#[tokio::test]
async fn test_get_execution_payload_bid_per_relay_max_payment_override() -> Result<()> {
    const GLOBAL_CAP_GWEI: u64 = 100;
    const RELAY_CAP_GWEI: u64 = 5;
    const SERVED_TRUSTED_GWEI: u64 = 10;

    for (relay_cap, expected) in
        [(None, StatusCode::OK), (Some(RELAY_CAP_GWEI), StatusCode::NO_CONTENT)]
    {
        setup_test_env();
        let chain = Chain::Hoodi;
        let pbs_listener = get_free_listener().await;
        let pbs_port = pbs_listener.local_addr()?.port();
        let relay_listener = get_free_listener().await;
        let relay_port = relay_listener.local_addr()?.port();

        let mock_state = Arc::new(
            MockRelayState::new(chain, random_secret()).with_trusted_bid_gwei(SERVED_TRUSTED_GWEI),
        );
        let mock_relay = match relay_cap {
            Some(cap) => generate_mock_relay_with_max_payment(
                relay_port,
                mock_state.signer.public_key(),
                cap,
            )?,
            None => generate_mock_relay(relay_port, mock_state.signer.public_key())?,
        };
        tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

        // Global cap comfortably above the served payment, so only a stricter
        // per-relay cap can reject the bid
        let mut pbs_config = get_pbs_config(pbs_port);
        pbs_config.max_execution_payment_gwei = GLOBAL_CAP_GWEI;
        let config = to_pbs_config(chain, pbs_config, vec![mock_relay]);
        let state = PbsState::new(config, PathBuf::new());
        tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

        let mock_validator = MockValidator::new(pbs_port)?;
        wait_for_ready(&mock_validator).await?;

        let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT);
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
        assert_eq!(res.status(), expected, "relay_cap={relay_cap:?}");
        assert_eq!(mock_state.received_execution_payload_bid(), 1, "relay_cap={relay_cap:?}");
    }
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
    let auth = opaque_auth(&[0xde, 0xad], TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(&auth), vec![
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
