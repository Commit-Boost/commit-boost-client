use std::fs;

use alloy::rpc::types::beacon::relay::ValidatorRegistration;
use cb_common::pbs::{SignedBlindedBeaconBlock, SubmitBlindedBlockResponse};
#[test]
fn test_registrations() {
    let file = fs::read("data/registration_holesky.json").unwrap();
    let parsed = serde_json::from_slice::<Vec<ValidatorRegistration>>(&file);
    assert!(parsed.is_ok());
}

#[test]
fn test_signed_blinded_block() {
    let file = fs::read("data/signed_blinded_block_holesky.json").unwrap();
    let parsed = serde_json::from_slice::<SignedBlindedBeaconBlock>(&file);
    assert!(parsed.is_ok());
}

#[test]
fn test_submit_block_response() {
    let file = fs::read("data/submit_block_response_holesky.json").unwrap();
    let parsed = serde_json::from_slice::<SubmitBlindedBlockResponse>(&file);
    assert!(parsed.is_ok());
}
