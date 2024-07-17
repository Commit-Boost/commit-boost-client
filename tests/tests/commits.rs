// use alloy::primitives::U256;
// use alloy::rpc::types::beacon::{BlsPublicKey, BlsSignature};
// use cb_cli::runner::{Runner, SignRequestSender};
// use cb_common::{config::BuilderConfig, types::Chain};
// use cb_crypto::{signature::verify_signed_builder_message, types::SignRequest};
// use cb_pbs::{BuilderState, DefaultBuilderApi};
// use cb_tests::utils::setup_test_env;
// use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
// use tree_hash_derive::TreeHash;

// #[derive(TreeHash)]
// struct Message {
//     data: u64,
// }

// const MSG: Message = Message { data: 100 };

// const COMMIT_ID: &str = "TEST_COMMIT";

// async fn test_service(
//     tx: SignRequestSender,
//     pubkeys: Vec<BlsPublicKey>,
//     test_tx: UnboundedSender<(BlsPublicKey, BlsSignature)>,
// ) -> eyre::Result<()> {
//     let validator_pubkey = pubkeys[0];

//     let (request, sign_rx) = SignRequest::new(COMMIT_ID, validator_pubkey, MSG);

//     tx.send(request).expect("failed sending request");

//     let signature = sign_rx.await.expect("failed signing").expect("sign manager is down");

//     test_tx.send((validator_pubkey, signature)).unwrap();

//     Ok(())
// }

// #[tokio::test]
// async fn test_commit() {
//     setup_test_env();

//     let chain = Chain::Holesky;

//     let config = BuilderConfig {
//         address: format!("0.0.0.0:4000").parse().unwrap(),
//         relays: vec![],
//         relay_check: true,
//         timeout_get_header_ms: u64::MAX,
//         timeout_get_payload_ms: u64::MAX,
//         timeout_register_validator_ms: u64::MAX,
//         skip_sigverify: false,
//         min_bid_wei: U256::ZERO,
//     };
//     let state = BuilderState::new(chain, config);

//     let mut runner = Runner::<(), DefaultBuilderApi>::new(state);

//     let (test_tx, mut test_rx) = unbounded_channel();

//     runner.add_commitment(COMMIT_ID, |tx, pubkeys| async move {
//         test_service(tx, pubkeys, test_tx).await
//     });

//     tokio::spawn(runner.run());

//     let (pubkey, signature) = test_rx.recv().await.unwrap();

//     assert!(verify_signed_builder_message(chain, &pubkey, &MSG, &signature).is_ok())
// }
