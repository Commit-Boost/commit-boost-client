use std::path::PathBuf;

use cb_common::{
    pbs::SignedBeaconBlock,
    signer::random_secret,
    types::Chain,
    utils::TestRandomSeed,
    wire::{CONSENSUS_VERSION_HEADER, EncodingType},
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::MockRelayState,
    mock_validator::MockValidator,
    utils::{
        generate_mock_relay, get_free_listener, get_pbs_config, setup_relay, setup_relays,
        spawn_mock_relay, to_pbs_config, wait_for_ready,
    },
};
use eyre::Result;
use lh_types::{MainnetEthSpec, SignedBeaconBlockGloas, Slot};
use reqwest::{StatusCode, header::CONTENT_TYPE};
use ssz::Encode;

const TEST_SLOT: u64 = 100;

/// A Gloas `SignedBeaconBlock` at `slot`, otherwise random.
fn gloas_block(slot: u64) -> SignedBeaconBlock {
    let mut block = SignedBeaconBlockGloas::<MainnetEthSpec>::test_random();
    block.message.slot = Slot::new(slot);
    SignedBeaconBlock::Gloas(block)
}

/// The endpoint is stateless: a block sent to the literal spec route
/// `POST /eth/v1/builder/beacon_blocks` is broadcast to every configured
/// builder, and each decodes it, by the forwarded fork header, back to the
/// same slot.
#[tokio::test]
async fn test_submit_signed_beacon_block_broadcasts_to_all_relays() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, states) = setup_relays(chain, vec![
        MockRelayState::new(chain, random_secret()),
        MockRelayState::new(chain, random_secret()),
    ])
    .await?;

    let block = gloas_block(TEST_SLOT);
    let url = format!("{}eth/v1/builder/beacon_blocks", mock_validator.comm_boost.config.entry.url);
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONSENSUS_VERSION_HEADER, "gloas")
        .body(block.as_ssz_bytes())
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED);
    for state in &states {
        assert_eq!(state.received_signed_beacon_block(), 1, "every builder receives the block");
        assert_eq!(state.received_block_slot(), Some(TEST_SLOT));
    }
    Ok(())
}

/// A relay listed only in a `[[mux]]` gets the block too
#[tokio::test]
async fn test_submit_signed_beacon_block_reaches_mux_relays() -> Result<()> {
    let chain = Chain::Hoodi;
    let (default_state, default_port) =
        spawn_mock_relay(MockRelayState::new(chain, random_secret())).await?;
    let (mux_state, mux_port) =
        spawn_mock_relay(MockRelayState::new(chain, random_secret())).await?;
    let default_relay = generate_mock_relay(default_port, default_state.signer.public_key())?;
    let mux_relay = generate_mock_relay(mux_port, mux_state.signer.public_key())?;

    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let mut config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![default_relay.clone()]);
    config.all_relays = vec![default_relay, mux_relay];
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));
    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    let block = gloas_block(TEST_SLOT);
    let res = mock_validator.do_submit_signed_beacon_block(&block, EncodingType::Ssz).await?;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(default_state.received_signed_beacon_block(), 1);
    assert_eq!(mux_state.received_signed_beacon_block(), 1);
    Ok(())
}

/// Every builder rejecting the block is still a 202: the beacon node gossips
/// the block anyway, so a builder's answer is not a failure. Each is asked.
#[tokio::test]
async fn test_submit_signed_beacon_block_broadcast_all_reject_202() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, states) = setup_relays(chain, vec![
        MockRelayState::new(chain, random_secret()),
        MockRelayState::new(chain, random_secret()),
    ])
    .await?;
    for state in &states {
        state.set_response_override(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let block = gloas_block(TEST_SLOT);
    let res = mock_validator.do_submit_signed_beacon_block(&block, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(states[0].received_signed_beacon_block(), 1, "every builder is asked");
    assert_eq!(states[1].received_signed_beacon_block(), 1, "every builder is asked");
    Ok(())
}

/// The block reaches the builder undecoded, in the encoding it arrived in:
/// JSON, the builder-specs default when unlabelled, or SSZ
#[tokio::test]
async fn test_submit_signed_beacon_block_forwards_its_encoding() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;
    let block = gloas_block(TEST_SLOT);
    let (json_body, ssz_body) = (serde_json::to_vec(&block)?, block.as_ssz_bytes());
    let url = mock_validator.comm_boost.submit_signed_beacon_block_url()?;

    // (Content-Type sent, body, Content-Type the builder gets)
    let cases = [
        // Neighbours differ, so each case's own assertions can fail
        (None, &json_body, "application/json"),
        (Some("application/octet-stream"), &ssz_body, "application/octet-stream"),
        (Some("application/json"), &json_body, "application/json"),
    ];
    for (sent, body, forwarded) in cases {
        let mut req = mock_validator.comm_boost.client.post(url.clone());
        if let Some(content_type) = sent {
            req = req.header(CONTENT_TYPE, content_type);
        }
        let res = req.header(CONSENSUS_VERSION_HEADER, "gloas").body(body.clone()).send().await?;
        assert_eq!(res.status(), StatusCode::ACCEPTED, "{sent:?}");
        let (content_type, received) = state.received_block_request().expect("forwarded");
        assert_eq!(content_type.as_deref(), Some(forwarded), "{sent:?}");
        assert_eq!(&received, body, "{sent:?}: forwarded byte for byte");
    }
    assert_eq!(state.received_signed_beacon_block(), 3);
    Ok(())
}

/// Requests refused before anything is broadcast, each with an ErrorMessage
/// body. `Eth-Consensus-Version` is required (builder-specs #165) and checked
/// first, a missing body is named as such, and a type other than JSON or SSZ
/// is a 415.
#[tokio::test]
async fn test_submit_signed_beacon_block_rejected_before_broadcast() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;
    let block = gloas_block(TEST_SLOT);
    let (json_body, ssz_body) = (serde_json::to_vec(&block)?, block.as_ssz_bytes());
    let url = mock_validator.comm_boost.submit_signed_beacon_block_url()?;

    // (Content-Type, Eth-Consensus-Version, body, expected status, message excerpt)
    let cases = [
        (
            Some("application/json"),
            None,
            json_body.clone(),
            StatusCode::BAD_REQUEST,
            "missing consensus version",
        ),
        (None, Some("gloas"), vec![], StatusCode::BAD_REQUEST, "missing request body"),
        (Some("text/plain"), Some("gloas"), ssz_body, StatusCode::UNSUPPORTED_MEDIA_TYPE, ""),
    ];
    for (content_type, version, body, status, message) in cases {
        let mut req = mock_validator.comm_boost.client.post(url.clone());
        if let Some(content_type) = content_type {
            req = req.header(CONTENT_TYPE, content_type);
        }
        if let Some(version) = version {
            req = req.header(CONSENSUS_VERSION_HEADER, version);
        }
        let res = req.body(body).send().await?;
        assert_eq!(res.status(), status, "{content_type:?}, {version:?}");
        let json: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
        assert_eq!(json["code"], status.as_u16(), "{json}");
        assert!(json["message"].as_str().unwrap_or_default().contains(message), "{json}");
    }
    assert_eq!(state.received_signed_beacon_block(), 0, "nothing is broadcast");
    Ok(())
}
