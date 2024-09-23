use alloy::rpc::types::beacon::relay::ValidatorRegistration;
use cb_common::{
    pbs::{SignedBlindedBeaconBlock, SubmitBlindedBlockResponse},
    utils::test_encode_decode,
};
#[test]
fn test_registrations() {
    let data = include_str!("../data/registration_holesky.json");
    test_encode_decode::<Vec<ValidatorRegistration>>(&data);
}

#[test]
fn test_signed_blinded_block() {
    let data = include_str!("../data/signed_blinded_block_holesky.json");
    test_encode_decode::<SignedBlindedBeaconBlock>(&data);
}

#[test]
fn test_submit_block_response() {
    let data = include_str!("../data/submit_block_response_holesky.json");
    test_encode_decode::<SubmitBlindedBlockResponse>(&data);
}
