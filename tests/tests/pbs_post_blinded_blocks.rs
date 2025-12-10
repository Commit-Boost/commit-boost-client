use std::{collections::HashSet, sync::Arc, time::Duration};

use cb_common::{
    pbs::{BuilderApiVersion, GetPayloadInfo, PayloadAndBlobs, SubmitBlindedBlockResponse},
    signer::random_secret,
    types::Chain,
    utils::{EncodingType, ForkName},
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service},
    mock_validator::{MockValidator, load_test_signed_blinded_block},
    utils::{generate_mock_relay, get_pbs_static_config, setup_test_env, to_pbs_config},
};
use eyre::Result;
use lh_types::beacon_response::ForkVersionDecode;
use reqwest::{Response, StatusCode};
use tracing::info;

#[tokio::test]
async fn test_submit_block_v1() -> Result<()> {
    let res = submit_block_impl(
        3800,
        BuilderApiVersion::V1,
        HashSet::from([EncodingType::Json]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Json,
        1,
    )
    .await?;
    assert_eq!(res.status(), StatusCode::OK);

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
        3810,
        BuilderApiVersion::V2,
        HashSet::from([EncodingType::Json]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Json,
        1,
    )
    .await?;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(res.bytes().await?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn test_submit_block_v1_ssz() -> Result<()> {
    let res = submit_block_impl(
        3820,
        BuilderApiVersion::V1,
        HashSet::from([EncodingType::Ssz]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Ssz,
        1,
    )
    .await?;
    assert_eq!(res.status(), StatusCode::OK);

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
        3830,
        BuilderApiVersion::V2,
        HashSet::from([EncodingType::Ssz]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Ssz,
        1,
    )
    .await?;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(res.bytes().await?.len(), 0);
    Ok(())
}

/// Test that a v1 submit block request in SSZ is converted to JSON if the relay
/// only supports JSON
#[tokio::test]
async fn test_submit_block_v1_ssz_into_json() -> Result<()> {
    let res = submit_block_impl(
        3840,
        BuilderApiVersion::V1,
        HashSet::from([EncodingType::Ssz]),
        HashSet::from([EncodingType::Json]),
        EncodingType::Ssz,
        2,
    )
    .await?;
    assert_eq!(res.status(), StatusCode::OK);

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
        3850,
        BuilderApiVersion::V2,
        HashSet::from([EncodingType::Ssz]),
        HashSet::from([EncodingType::Json]),
        EncodingType::Ssz,
        2,
    )
    .await?;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(res.bytes().await?.len(), 0);
    Ok(())
}

/// Test v1 requesting multiple types when the relay supports SSZ, which should
/// return SSZ
#[tokio::test]
async fn test_submit_block_v1_multitype_ssz() -> Result<()> {
    let res = submit_block_impl(
        3860,
        BuilderApiVersion::V1,
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        HashSet::from([EncodingType::Ssz]),
        EncodingType::Ssz,
        1,
    )
    .await?;
    assert_eq!(res.status(), StatusCode::OK);

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
        3870,
        BuilderApiVersion::V1,
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        HashSet::from([EncodingType::Json]),
        EncodingType::Ssz,
        1,
    )
    .await?;
    assert_eq!(res.status(), StatusCode::OK);

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
async fn test_submit_block_too_large() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Holesky;
    let pbs_port = 3900;

    let relays = vec![generate_mock_relay(pbs_port + 1, pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer).with_large_body());
    tokio::spawn(start_mock_relay_service(mock_state.clone(), pbs_port + 1));

    let config = to_pbs_config(chain, get_pbs_static_config(pbs_port), relays);
    let state = PbsState::new(config);
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

async fn submit_block_impl(
    pbs_port: u16,
    api_version: BuilderApiVersion,
    accept_types: HashSet<EncodingType>,
    relay_types: HashSet<EncodingType>,
    serialization_mode: EncodingType,
    expected_try_count: u64,
) -> Result<Response> {
    // Setup test environment
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Holesky;
    let relay_port = pbs_port + 1;

    // Run a mock relay
    let mut mock_state = MockRelayState::new(chain, signer);
    mock_state.supported_content_types = Arc::new(relay_types);
    let mock_state = Arc::new(mock_state);
    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    tokio::spawn(start_mock_relay_service(mock_state.clone(), relay_port));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_static_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config);
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
    assert_eq!(mock_state.received_submit_block(), expected_try_count);
    Ok(res)
}
