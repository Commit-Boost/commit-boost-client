use std::{
    sync::Arc,
    time::Duration,
};

use alloy::primitives::{B256, U256};
use cb_common::{
    signature::sign_builder_root, signer::{random_secret, BlsPublicKey}, types::Chain, utils::blst_pubkey_to_alloy
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{start_mock_relay_service, MockRelayState},
    mock_validator::MockValidator,
    utils::{generate_mock_relay, setup_test_env, to_pbs_config, get_pbs_static_config},
};
use eyre::Result;
use tracing::info;
use cb_common::utils::timestamp_of_slot_start_sec;
use tree_hash::TreeHash;

#[tokio::test]
async fn test_get_header() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let port = 3000;

    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    let mock_relay = generate_mock_relay(port + 1, *pubkey)?;
    tokio::spawn(start_mock_relay_service(mock_state.clone(), port + 1));

    let config = to_pbs_config(chain, get_pbs_static_config(port), vec![mock_relay.clone()]);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::from_relay(mock_relay)?;
    info!("Sending get header");
    let res = mock_validator.do_get_header(None).await.expect("failed to get header");

    assert_eq!(mock_state.received_get_header(), 1);
    assert_eq!(res.data.message.header.block_hash.0[0], 1);
    assert_eq!(res.data.message.header.parent_hash, B256::ZERO);
    assert_eq!(res.data.message.value, U256::from(10));
    assert_eq!(res.data.message.pubkey, blst_pubkey_to_alloy(&mock_state.signer.sk_to_pk()));
    assert_eq!(res.data.message.header.timestamp, timestamp_of_slot_start_sec(1337, chain));
    assert_eq!(res.data.signature, sign_builder_root(chain, &mock_state.signer, res.data.message.tree_hash_root().0));
    Ok(())
}
