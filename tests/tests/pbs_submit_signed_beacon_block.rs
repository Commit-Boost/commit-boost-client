use alloy::primitives::B256;
use cb_common::{
    pbs::SignedBeaconBlock,
    signer::random_secret,
    types::Chain,
    utils::TestRandomSeed,
    wire::{CONSENSUS_VERSION_HEADER, EncodingType},
};
use cb_tests::{
    mock_relay::MockRelayState,
    utils::{generate_mock_relay, setup_relay, setup_relays},
};
use eyre::Result;
use lh_types::{MainnetEthSpec, SignedBeaconBlockElectra, SignedBeaconBlockGloas, Slot};
use reqwest::{
    StatusCode,
    header::{CONTENT_TYPE, HeaderValue},
};
use ssz::Encode;

const TEST_SLOT: u64 = 100;

/// A fixed committed bid `block_hash` for building test blocks.
fn mock_bid_block_hash() -> B256 {
    let mut hash = B256::ZERO;
    hash.0[0] = 1;
    hash
}

/// A Gloas `SignedBeaconBlock` at `slot` whose committed bid names
/// `committed_block_hash`. Built from a random block with just those two fields
/// pinned.
fn gloas_block(slot: u64, committed_block_hash: B256) -> SignedBeaconBlock {
    let mut block = SignedBeaconBlockGloas::<MainnetEthSpec>::test_random();
    block.message.slot = Slot::new(slot);
    block.message.body.signed_execution_payload_bid.message.block_hash =
        committed_block_hash.into();
    SignedBeaconBlock::Gloas(block)
}

/// The endpoint is stateless: the block is always broadcast to every configured
/// builder, and each relay's received counter increments.
#[tokio::test]
async fn test_submit_signed_beacon_block_broadcasts_to_all_relays() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, states) = setup_relays(chain, vec![
        MockRelayState::new(chain, random_secret()),
        MockRelayState::new(chain, random_secret()),
    ])
    .await?;

    let block = gloas_block(TEST_SLOT, mock_bid_block_hash());
    let res = mock_validator.do_submit_signed_beacon_block(&block, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(states[0].received_signed_beacon_block(), 1, "every builder receives the block");
    assert_eq!(states[1].received_signed_beacon_block(), 1, "every builder receives the block");
    assert_eq!(states[0].received_block_slot(), Some(TEST_SLOT));
    assert_eq!(states[1].received_block_slot(), Some(TEST_SLOT));
    Ok(())
}

/// A valid SSZ submission is a 202 and reaches the builder decoded: the mock
/// recovers the same slot and committed bid hash from the forwarded SSZ.
#[tokio::test]
async fn test_submit_signed_beacon_block_ssz_202() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let committed = B256::repeat_byte(0x07);
    let block = gloas_block(TEST_SLOT, committed);
    let res = mock_validator.do_submit_signed_beacon_block(&block, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(state.received_signed_beacon_block(), 1);
    assert_eq!(state.received_block_slot(), Some(TEST_SLOT));
    assert_eq!(state.received_block_committed_hash(), Some(committed));
    Ok(())
}

/// A JSON submission is accepted and decodes to the same block: CB re-encodes
/// it to SSZ for the builder, which recovers the committed hash unchanged.
#[tokio::test]
async fn test_submit_signed_beacon_block_json_202() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let committed = B256::repeat_byte(0x5a);
    let block = gloas_block(TEST_SLOT, committed);
    let res = mock_validator.do_submit_signed_beacon_block(&block, EncodingType::Json).await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED, "the spec's JSON wire form must be accepted");
    assert_eq!(state.received_signed_beacon_block(), 1);
    assert_eq!(state.received_block_committed_hash(), Some(committed));
    Ok(())
}

/// Pin the literal spec route: `POST /eth/v1/builder/beacon_blocks`.
#[tokio::test]
async fn test_submit_signed_beacon_block_spec_url() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let block = gloas_block(TEST_SLOT, B256::repeat_byte(0x09));
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
    assert_eq!(state.received_signed_beacon_block(), 1);
    Ok(())
}

/// A non-Gloas block, submitted as JSON under the (mandatory) gloas label,
/// is a 400
/// the endpoint is Gloas-only per spec.
#[tokio::test]
async fn test_submit_signed_beacon_block_non_gloas_400() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    // gloas is the only header the wire layer admits, so a non-Gloas BLOCK can
    // only reach the route's Gloas-only check as JSON. The untagged decode
    // picks the FIRST field-matching variant - Electra (a Fulu body would also
    // land on Electra; the two are JSON-identical) - and the route rejects it.
    let block =
        SignedBeaconBlock::Electra(SignedBeaconBlockElectra::<MainnetEthSpec>::test_random());
    let url = mock_validator.comm_boost.submit_signed_beacon_block_url()?;
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .header(CONSENSUS_VERSION_HEADER, "gloas")
        .body(serde_json::to_vec(&block)?)
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(state.received_signed_beacon_block(), 0, "a non-Gloas block must not be forwarded");
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 400);
    assert!(
        body["message"].as_str().unwrap_or_default().contains("Gloas"),
        "the rejection must name the Gloas-only constraint, got: {}",
        body["message"]
    );
    Ok(())
}

/// builder-specs requires `Eth-Consensus-Version` on every body-carrying
/// request (spec PR #165, superseding the earlier best-effort policy): a JSON
/// body with no version header is a 400 and nothing is broadcast.
#[tokio::test]
async fn test_submit_signed_beacon_block_json_no_version_400() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let block = gloas_block(TEST_SLOT, mock_bid_block_hash());
    let url = mock_validator.comm_boost.submit_signed_beacon_block_url()?;
    // No CONSENSUS_VERSION_HEADER: required regardless of encoding
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .body(serde_json::to_vec(&block)?)
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await?;
    assert!(
        body["message"].as_str().unwrap_or_default().contains("missing consensus version"),
        "the 400 must name the missing header: {body}"
    );
    assert_eq!(state.received_signed_beacon_block(), 0, "rejected before any broadcast");

    // Present but unrecognized is also a 400, and the error names the VALUE
    // rather than claiming the header is missing
    let block = gloas_block(TEST_SLOT, mock_bid_block_hash());
    let url = mock_validator.comm_boost.submit_signed_beacon_block_url()?;
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .header(CONSENSUS_VERSION_HEADER, HeaderValue::from_static("futurefork"))
        .body(serde_json::to_vec(&block)?)
        .send()
        .await?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await?;
    assert!(
        body["message"].as_str().unwrap_or_default().contains("futurefork"),
        "the 400 must echo the unrecognized value: {body}"
    );
    assert_eq!(state.received_signed_beacon_block(), 0);
    Ok(())
}

/// The block is broadcast; if every builder rejects it, PBS maps the all-reject
/// outcome to a 500 (no builder accepted).
#[tokio::test]
async fn test_submit_signed_beacon_block_broadcast_all_reject_500() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, states) = setup_relays(chain, vec![
        MockRelayState::new(chain, random_secret()),
        MockRelayState::new(chain, random_secret()),
    ])
    .await?;

    // Make every builder reject the broadcast
    for state in &states {
        state.set_response_override(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let block = gloas_block(TEST_SLOT, mock_bid_block_hash());
    let res = mock_validator.do_submit_signed_beacon_block(&block, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(states[0].received_signed_beacon_block(), 1, "every builder is asked");
    assert_eq!(states[1].received_signed_beacon_block(), 1, "every builder is asked");
    Ok(())
}

/// A broadcast where one builder accepts and the other rejects is still a 202:
/// one acceptance across the broadcast is success. This is the core of the
/// stateless broadcast model, distinct from the all-accept and all-reject
/// extremes the other tests cover.
#[tokio::test]
async fn test_submit_signed_beacon_block_broadcast_one_accepts_202() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, states) = setup_relays(chain, vec![
        MockRelayState::new(chain, random_secret()),
        MockRelayState::new(chain, random_secret()),
    ])
    .await?;

    // Only the second builder accepts; the first rejects. PBS must still 202.
    states[0].set_response_override(StatusCode::INTERNAL_SERVER_ERROR);

    let block = gloas_block(TEST_SLOT, mock_bid_block_hash());
    let res = mock_validator.do_submit_signed_beacon_block(&block, EncodingType::Ssz).await?;

    assert_eq!(
        res.status(),
        StatusCode::ACCEPTED,
        "one accepting builder makes the broadcast a success"
    );
    assert_eq!(states[0].received_signed_beacon_block(), 1, "every builder is asked");
    assert_eq!(states[1].received_signed_beacon_block(), 1, "every builder is asked");
    Ok(())
}

/// gloas is the only value the wire layer admits on these post-fork endpoints:
/// a Gloas JSON block labelled `fulu` is rejected with a 400 naming the value,
/// like every other deprecated fork.
#[tokio::test]
async fn test_submit_signed_beacon_block_fulu_label_400() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let block = gloas_block(TEST_SLOT, mock_bid_block_hash());
    let url = mock_validator.comm_boost.submit_signed_beacon_block_url()?;
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .header(CONSENSUS_VERSION_HEADER, "fulu")
        .body(serde_json::to_vec(&block)?)
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await?;
    assert!(
        body["message"].as_str().unwrap_or_default().contains("fulu"),
        "the 400 must echo the unsupported value: {body}"
    );
    assert_eq!(state.received_signed_beacon_block(), 0, "nothing is broadcast");
    Ok(())
}

/// An unsupported request `Content-Type` is a 415, distinct from the 400 a
/// malformed body of a supported type produces. Mirrors the preferences and bid
/// endpoints.
#[tokio::test]
async fn test_submit_signed_beacon_block_unsupported_content_type_415() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let url = mock_validator.comm_boost.submit_signed_beacon_block_url()?;
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, "text/plain")
        .header(CONSENSUS_VERSION_HEADER, "gloas")
        .body("nonsense")
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        state.received_signed_beacon_block(),
        0,
        "an unsupported media type must not be forwarded"
    );
    Ok(())
}

/// An SSZ submission missing `Eth-Consensus-Version` is a 400: the SSZ block is
/// not self-describing, so the fork header is required to select the variant
/// (and the spec mandates the header regardless of encoding).
#[tokio::test]
async fn test_submit_signed_beacon_block_ssz_missing_version_400() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let block = gloas_block(TEST_SLOT, mock_bid_block_hash());
    let url = mock_validator.comm_boost.submit_signed_beacon_block_url()?;
    // Note: SSZ Content-Type but no CONSENSUS_VERSION_HEADER
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, EncodingType::Ssz.content_type_header().clone())
        .body(block.as_ssz_bytes())
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(state.received_signed_beacon_block(), 0, "an undecodable request must not forward");
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 400);
    Ok(())
}

/// A submission with no body is a 400 (`MissingBody`), distinguished from the
/// decode failure an empty SSZ body would otherwise produce.
#[tokio::test]
async fn test_submit_signed_beacon_block_missing_body_400() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let url = mock_validator.comm_boost.submit_signed_beacon_block_url()?;
    // A version header, but no body at all
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONSENSUS_VERSION_HEADER, "gloas")
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(state.received_signed_beacon_block(), 0);
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert!(
        body["message"].as_str().unwrap_or_default().contains("missing request body"),
        "expected the missing-body error, got {}",
        body["message"]
    );
    Ok(())
}
