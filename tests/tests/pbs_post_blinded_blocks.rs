use std::{sync::Arc, time::Duration};

use cb_common::{
    pbs::{BuilderApiVersion, SubmitBlindedBlockResponse},
    signer::random_secret,
    types::Chain,
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{start_mock_relay_service, MockRelayState},
    mock_validator::{load_test_signed_blinded_block, MockValidator},
    utils::{generate_mock_relay, get_pbs_config, setup_test_env, to_pbs_config},
};
use eyre::Result;
use reqwest::{Response, StatusCode};
use tracing::info;

#[tokio::test]
async fn test_submit_block_v1() -> Result<()> {
    let res = submit_block_impl(3800, &BuilderApiVersion::V1).await?;
    assert_eq!(res.status(), StatusCode::OK);

    let signed_blinded_block = load_test_signed_blinded_block();

    let response_body = serde_json::from_slice::<SubmitBlindedBlockResponse>(&res.bytes().await?)?;
    assert_eq!(response_body.block_hash(), signed_blinded_block.block_hash());
    Ok(())
}

#[tokio::test]
async fn test_submit_block_v2() -> Result<()> {
    let res = submit_block_impl(3850, &BuilderApiVersion::V2).await?;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(res.bytes().await?.len(), 0);
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

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending submit block");
    let res = mock_validator.do_submit_block_v1(None).await;

    // response size exceeds max size: max: 20971520
    assert_eq!(res.unwrap().status(), StatusCode::BAD_GATEWAY);
    assert_eq!(mock_state.received_submit_block(), 1);
    Ok(())
}

async fn submit_block_impl(pbs_port: u16, api_version: &BuilderApiVersion) -> Result<Response> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Holesky;

    // Run a mock relay
    let relays = vec![generate_mock_relay(pbs_port + 1, pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), pbs_port + 1));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let signed_blinded_block = load_test_signed_blinded_block();
    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending submit block");
    let res = match api_version {
        BuilderApiVersion::V1 => {
            mock_validator.do_submit_block_v1(Some(signed_blinded_block)).await?
        }
        BuilderApiVersion::V2 => {
            mock_validator.do_submit_block_v2(Some(signed_blinded_block)).await?
        }
    };
    assert_eq!(mock_state.received_submit_block(), 1);
    Ok(res)
}
