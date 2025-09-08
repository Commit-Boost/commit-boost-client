use alloy::rpc::types::beacon::relay::ValidatorRegistration;
use cb_common::{
    pbs::{SignedBlindedBeaconBlock, SubmitBlindedBlockResponse},
    utils::test_encode_decode,
};
use serde_json::Value;

// Happy path tests
#[test]
fn test_registrations() {
    let data = include_str!("../data/registration_holesky.json");
    test_encode_decode::<Vec<ValidatorRegistration>>(data);
}

#[test]
fn test_signed_blinded_block() {
    let data = include_str!("../data/signed_blinded_block_holesky.json");
    test_encode_decode::<SignedBlindedBeaconBlock>(data);
}

#[test]
fn test_submit_block_response() {
    let data = include_str!("../data/submit_block_response_holesky.json");
    test_encode_decode::<SubmitBlindedBlockResponse>(data);
}

// Unhappy path tests
fn test_missing_registration_field(field_name: &str) -> String {
    let data = include_str!("../data/registration_holesky.json");
    let mut values: Value = serde_json::from_str(data).unwrap();

    // Remove specified field from the first validator's message
    if let Value::Array(arr) = &mut values &&
        let Some(first_validator) = arr.get_mut(0) &&
        let Some(Value::Object(msg_obj)) = first_validator.get_mut("message")
    {
        msg_obj.remove(field_name);
    }

    // This should fail since the field is required
    let result = serde_json::from_value::<Vec<ValidatorRegistration>>(values);
    assert!(result.is_err());
    result.unwrap_err().to_string()
}

#[test]
fn test_registration_missing_fields() {
    let fields = ["fee_recipient", "gas_limit", "timestamp", "pubkey"];

    for field in fields {
        let error = test_missing_registration_field(field);
        assert!(
            error.contains(&format!("missing field `{}`", field)),
            "Expected error about missing {}, got: {}",
            field,
            error
        );
    }
}

fn test_missing_signed_blinded_block_field(field_name: &str) -> String {
    let data = include_str!("../data/signed_blinded_block_holesky.json");
    let mut values: Value = serde_json::from_str(data).unwrap();

    // Remove specified field from the message
    if let Some(Value::Object(msg_obj)) = values.get_mut("message") {
        msg_obj.remove(field_name);
    }

    // This should fail since the field is required
    let result = serde_json::from_value::<SignedBlindedBeaconBlock>(values);
    assert!(result.is_err());
    result.unwrap_err().to_string()
}

#[ignore = "TODO: this fails because now we have an enum instead of a flat struct"]
#[test]
fn test_signed_blinded_block_missing_fields() {
    let fields = ["slot", "proposer_index", "parent_root", "state_root", "body"];

    for field in fields {
        let error = test_missing_signed_blinded_block_field(field);
        assert!(
            error.contains(&format!("missing field `{}`", field)),
            "Expected error about missing {}, got: {}",
            field,
            error
        );
    }
}

fn test_missing_submit_block_response_field(field_name: &str) -> String {
    let data = include_str!("../data/submit_block_response_holesky.json");
    let mut values: Value = serde_json::from_str(data).unwrap();

    // Remove specified field
    if let Value::Object(obj) = &mut values {
        obj.remove(field_name);
    }

    // This should fail since the field is required
    let result = serde_json::from_value::<SubmitBlindedBlockResponse>(values);
    assert!(result.is_err());
    result.unwrap_err().to_string()
}

#[test]
fn test_submit_block_response_missing_fields() {
    let fields = ["version", "data"];

    for field in fields {
        let error = test_missing_submit_block_response_field(field);
        assert!(
            error.contains(&format!("missing field `{}`", field)),
            "Expected error about missing {}, got: {}",
            field,
            error
        );
    }
}
