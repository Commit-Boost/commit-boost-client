use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Duration};

use cb_common::{
    config::BlockValidationMode,
    pbs::{BuilderApiVersion, GetPayloadInfo, PayloadAndBlobs, SubmitBlindedBlockResponse},
    signer::random_secret,
    types::Chain,
    utils::{EncodingType, ForkName},
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service_with_listener},
    mock_validator::{MockValidator, load_test_signed_blinded_block},
    utils::{
        generate_mock_relay, get_free_listener, get_pbs_config, setup_test_env, to_pbs_config,
    },
};
use eyre::Result;
use lh_types::ForkVersionDecode;
use reqwest::{Response, StatusCode};
use tracing::info;

#[tokio::test]
async fn test_submit_block_v1() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V1,
        HashSet::from([EncodingType::Json]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Json,
        1,
        BlockValidationMode::Standard,
        StatusCode::OK,
        false,
        false,
    )
    .await?;
    let signed_blinded_block = load_test_signed_blinded_block();

    let response_body = serde_json::from_slice::<SubmitBlindedBlockResponse>(&res.bytes().await?)?;
    assert_eq!(
        response_body.data.execution_payload.block_hash(),
        signed_blinded_block.block_hash().into()
    );
    Ok(())
}

#[tokio::test]
async fn test_submit_block_v2() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V2,
        HashSet::from([EncodingType::Json]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Json,
        1,
        BlockValidationMode::Standard,
        StatusCode::ACCEPTED,
        false,
        false,
    )
    .await?;
    assert_eq!(res.bytes().await?.len(), 0);
    Ok(())
}

// Test that when submitting a block using v2 to a relay that does not support
// v2, PBS falls back to v1 and successfully submits the block.
#[tokio::test]
async fn test_submit_block_v2_without_relay_support() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V2,
        HashSet::from([EncodingType::Json]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Json,
        1,
        BlockValidationMode::Standard,
        StatusCode::ACCEPTED,
        true,
        false,
    )
    .await?;
    assert_eq!(res.bytes().await?.len(), 0);
    Ok(())
}

// Test that when submitting a block using v2 to a relay that returns 404s
// for both v1 and v2, PBS doesn't loop forever.
#[tokio::test]
async fn test_submit_block_on_broken_relay() -> Result<()> {
    let _res = submit_block_impl(
        BuilderApiVersion::V2,
        HashSet::from([EncodingType::Json]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Json,
        1,
        BlockValidationMode::Standard,
        StatusCode::BAD_GATEWAY,
        true,
        true,
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_submit_block_v1_ssz() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V1,
        HashSet::from([EncodingType::Ssz]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Ssz,
        1,
        BlockValidationMode::Standard,
        StatusCode::OK,
        false,
        false,
    )
    .await?;
    let signed_blinded_block = load_test_signed_blinded_block();

    let response_body =
        PayloadAndBlobs::from_ssz_bytes_by_fork(&res.bytes().await?, ForkName::Electra).unwrap();
    assert_eq!(
        response_body.execution_payload.block_hash(),
        signed_blinded_block.block_hash().into()
    );
    Ok(())
}

#[tokio::test]
async fn test_submit_block_v2_ssz() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V2,
        HashSet::from([EncodingType::Ssz]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Ssz,
        1,
        BlockValidationMode::Standard,
        StatusCode::ACCEPTED,
        false,
        false,
    )
    .await?;
    assert_eq!(res.bytes().await?.len(), 0);
    Ok(())
}

/// Test that a v1 submit block request in SSZ is converted to JSON if the relay
/// only supports JSON
#[tokio::test]
async fn test_submit_block_v1_ssz_into_json() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V1,
        HashSet::from([EncodingType::Ssz]),
        HashSet::from([EncodingType::Json]),
        EncodingType::Ssz,
        2,
        BlockValidationMode::Standard,
        StatusCode::OK,
        false,
        false,
    )
    .await?;
    let signed_blinded_block = load_test_signed_blinded_block();

    let response_body =
        PayloadAndBlobs::from_ssz_bytes_by_fork(&res.bytes().await?, ForkName::Electra).unwrap();
    assert_eq!(
        response_body.execution_payload.block_hash(),
        signed_blinded_block.block_hash().into()
    );
    Ok(())
}

/// Test that a v2 submit block request in SSZ is converted to JSON if the relay
/// only supports JSON
#[tokio::test]
async fn test_submit_block_v2_ssz_into_json() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V2,
        HashSet::from([EncodingType::Ssz]),
        HashSet::from([EncodingType::Json]),
        EncodingType::Ssz,
        2,
        BlockValidationMode::Standard,
        StatusCode::ACCEPTED,
        false,
        false,
    )
    .await?;
    assert_eq!(res.bytes().await?.len(), 0);
    Ok(())
}

/// Test v1 requesting multiple types when the relay supports SSZ, which should
/// return SSZ
#[tokio::test]
async fn test_submit_block_v1_multitype_ssz() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V1,
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        HashSet::from([EncodingType::Ssz]),
        EncodingType::Ssz,
        1,
        BlockValidationMode::Standard,
        StatusCode::OK,
        false,
        false,
    )
    .await?;
    let signed_blinded_block = load_test_signed_blinded_block();

    let response_body =
        PayloadAndBlobs::from_ssz_bytes_by_fork(&res.bytes().await?, ForkName::Electra).unwrap();
    assert_eq!(
        response_body.execution_payload.block_hash(),
        signed_blinded_block.block_hash().into()
    );
    Ok(())
}

/// Test v1 requesting multiple types when the relay supports JSON, which should
/// still return SSZ
#[tokio::test]
async fn test_submit_block_v1_multitype_json() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V1,
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        HashSet::from([EncodingType::Json]),
        EncodingType::Ssz,
        2,
        BlockValidationMode::Standard,
        StatusCode::OK,
        false,
        false,
    )
    .await?;
    let signed_blinded_block = load_test_signed_blinded_block();

    let response_body =
        PayloadAndBlobs::from_ssz_bytes_by_fork(&res.bytes().await?, ForkName::Electra).unwrap();
    assert_eq!(
        response_body.execution_payload.block_hash(),
        signed_blinded_block.block_hash().into()
    );
    Ok(())
}

#[tokio::test]
async fn test_submit_block_v1_light() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V1,
        HashSet::from([EncodingType::Json]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Json,
        1,
        BlockValidationMode::None,
        StatusCode::OK,
        false,
        false,
    )
    .await?;
    let signed_blinded_block = load_test_signed_blinded_block();

    let response_body = serde_json::from_slice::<SubmitBlindedBlockResponse>(&res.bytes().await?)?;
    assert_eq!(
        response_body.data.execution_payload.block_hash(),
        signed_blinded_block.block_hash().into()
    );
    Ok(())
}

#[tokio::test]
async fn test_submit_block_v2_light() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V2,
        HashSet::from([EncodingType::Json]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Json,
        1,
        BlockValidationMode::None,
        StatusCode::ACCEPTED,
        false,
        false,
    )
    .await?;
    assert_eq!(res.bytes().await?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn test_submit_block_v1_ssz_light() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V1,
        HashSet::from([EncodingType::Ssz]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Ssz,
        1,
        BlockValidationMode::None,
        StatusCode::OK,
        false,
        false,
    )
    .await?;
    let signed_blinded_block = load_test_signed_blinded_block();

    let response_body =
        PayloadAndBlobs::from_ssz_bytes_by_fork(&res.bytes().await?, ForkName::Electra).unwrap();
    assert_eq!(
        response_body.execution_payload.block_hash(),
        signed_blinded_block.block_hash().into()
    );
    Ok(())
}

#[tokio::test]
async fn test_submit_block_v2_ssz_light() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V2,
        HashSet::from([EncodingType::Ssz]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Ssz,
        1,
        BlockValidationMode::None,
        StatusCode::ACCEPTED,
        false,
        false,
    )
    .await?;
    assert_eq!(res.bytes().await?.len(), 0);
    Ok(())
}

/// Test that a v1 submit block request in light mode, with SSZ, is converted to
/// JSON if the relay only supports JSON
#[tokio::test]
async fn test_submit_block_v1_ssz_into_json_light() -> Result<()> {
    submit_block_impl(
        BuilderApiVersion::V1,
        HashSet::from([EncodingType::Ssz]),
        HashSet::from([EncodingType::Json]),
        EncodingType::Ssz,
        2,
        BlockValidationMode::None,
        StatusCode::BAD_GATEWAY,
        false,
        false,
    )
    .await?;
    Ok(())
}

/// Test that a v2 submit block request in light mode, with SSZ, is converted to
/// JSON if the relay only supports JSON
#[tokio::test]
async fn test_submit_block_v2_ssz_into_json_light() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V2,
        HashSet::from([EncodingType::Ssz]),
        HashSet::from([EncodingType::Json]),
        EncodingType::Ssz,
        2,
        BlockValidationMode::Standard,
        StatusCode::ACCEPTED,
        false,
        false,
    )
    .await?;
    assert_eq!(res.bytes().await?.len(), 0);
    Ok(())
}

/// Test v1 requesting multiple types in light mode when the relay supports SSZ,
/// which should return SSZ
#[tokio::test]
async fn test_submit_block_v1_multitype_ssz_light() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V1,
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        HashSet::from([EncodingType::Ssz]),
        EncodingType::Ssz,
        1,
        BlockValidationMode::None,
        StatusCode::OK,
        false,
        false,
    )
    .await?;
    let signed_blinded_block = load_test_signed_blinded_block();

    let response_body =
        PayloadAndBlobs::from_ssz_bytes_by_fork(&res.bytes().await?, ForkName::Electra).unwrap();
    assert_eq!(
        response_body.execution_payload.block_hash(),
        signed_blinded_block.block_hash().into()
    );
    Ok(())
}

/// Test v1 requesting multiple types in light mode when the relay supports
/// JSON, which should be able to handle an SSZ request by converting to JSON
#[tokio::test]
async fn test_submit_block_v1_multitype_json_light() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V1,
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        HashSet::from([EncodingType::Json]),
        EncodingType::Ssz,
        2,
        BlockValidationMode::None,
        StatusCode::OK,
        false,
        false,
    )
    .await?;
    let signed_blinded_block = load_test_signed_blinded_block();

    let response_body = serde_json::from_slice::<SubmitBlindedBlockResponse>(&res.bytes().await?)?;
    assert_eq!(
        response_body.data.execution_payload.block_hash(),
        signed_blinded_block.block_hash().into()
    );
    Ok(())
}

#[tokio::test]
async fn test_submit_block_too_large() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Holesky;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    let relays = vec![generate_mock_relay(relay_port, pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer).with_large_body());
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    let state = PbsState::new(config, PathBuf::new());
    drop(pbs_listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending submit block");
    let res = mock_validator
        .do_submit_block_v1(
            None,
            HashSet::from([EncodingType::Json]),
            EncodingType::Json,
            ForkName::Electra,
        )
        .await;

    // response size exceeds max size: max: 20971520
    assert_eq!(res.unwrap().status(), StatusCode::BAD_GATEWAY);
    assert_eq!(mock_state.received_submit_block(), 1);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn submit_block_impl(
    api_version: BuilderApiVersion,
    accept_types: HashSet<EncodingType>,
    relay_types: HashSet<EncodingType>,
    serialization_mode: EncodingType,
    expected_try_count: u64,
    mode: BlockValidationMode,
    expected_code: StatusCode,
    remove_v2_support: bool,
    force_404s: bool,
) -> Result<Response> {
    // Setup test environment
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Holesky;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    // Run a mock relay
    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    let mut mock_relay_state = MockRelayState::new(chain, signer);
    mock_relay_state.supported_content_types = Arc::new(relay_types);
    if remove_v2_support {
        mock_relay_state = mock_relay_state.with_no_submit_block_v2();
    }
    if force_404s {
        mock_relay_state = mock_relay_state.with_not_found_for_submit_block();
    }
    let mock_state = Arc::new(mock_relay_state);
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    // Run the PBS service
    let mut pbs_config = get_pbs_config(pbs_port);
    pbs_config.block_validation_mode = mode;
    let config = to_pbs_config(chain, pbs_config, vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    drop(pbs_listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send the submit block request
    let signed_blinded_block = load_test_signed_blinded_block();
    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending submit block");
    let res = match api_version {
        BuilderApiVersion::V1 => {
            mock_validator
                .do_submit_block_v1(
                    Some(signed_blinded_block),
                    accept_types,
                    serialization_mode,
                    ForkName::Electra,
                )
                .await?
        }
        BuilderApiVersion::V2 => {
            mock_validator
                .do_submit_block_v2(
                    Some(signed_blinded_block),
                    accept_types,
                    serialization_mode,
                    ForkName::Electra,
                )
                .await?
        }
    };
    let expected_count = if force_404s { 0 } else { expected_try_count };
    assert_eq!(mock_state.received_submit_block(), expected_count);
    assert_eq!(res.status(), expected_code);
    Ok(res)
}
