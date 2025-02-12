use alloy::rpc::types::beacon::relay::ValidatorRegistration;
use cb_common::{
    pbs::{DenebSpec, ElectraSpec, SignedBlindedBeaconBlock, SubmitBlindedBlockResponse},
    utils::test_encode_decode,
};
use cb_tests::utils::SpecVersion;
use serde_json::Value;

// Happy path tests
#[test]
fn test_registrations() {
    test_encode_decode::<Vec<ValidatorRegistration>>(include_str!(
        "../data/deneb/registration_holesky.json"
    ));
}

#[test]
fn test_signed_blinded_block() {
    // Deneb
    test_encode_decode::<SignedBlindedBeaconBlock<DenebSpec>>(include_str!(
        "../data/deneb/signed_blinded_block_holesky.json"
    ));
    // Electra
    test_encode_decode::<SignedBlindedBeaconBlock<ElectraSpec>>(include_str!(
        "../data/electra/signed_blinded_block_holesky.json"
    ));
}

#[test]
fn test_submit_block_response() {
    // Deneb
    test_encode_decode::<SubmitBlindedBlockResponse<DenebSpec>>(include_str!(
        "../data/deneb/submit_block_response_holesky.json"
    ));
    // Electra
    test_encode_decode::<SubmitBlindedBlockResponse<ElectraSpec>>(include_str!(
        "../data/electra/submit_block_response_holesky.json"
    ));
}

// Unhappy path tests
fn test_missing_registration_field(version: SpecVersion, field_name: &str) -> String {
    let data = match version {
        SpecVersion::Deneb => include_str!("../data/deneb/registration_holesky.json"),
        SpecVersion::Electra => include_str!("../data/electra/registration_holesky.json"),
    };
    let mut values: Value = serde_json::from_str(data).unwrap();

    // Remove specified field from the first validator's message
    if let Value::Array(arr) = &mut values {
        if let Some(first_validator) = arr.get_mut(0) {
            if let Some(message) = first_validator.get_mut("message") {
                if let Value::Object(msg_obj) = message {
                    msg_obj.remove(field_name);
                }
            }
        }
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
        for version in [SpecVersion::Deneb, SpecVersion::Electra] {
            let error = test_missing_registration_field(version, field);
            assert!(
                error.contains(&format!("missing field `{}`", field)),
                "Expected error about missing {}, got: {}",
                field,
                error
            );
        }
    }
}

fn test_missing_signed_blinded_block_field(version: SpecVersion, field_name: &str) -> String {
    let data = match version {
        SpecVersion::Deneb => include_str!("../data/deneb/signed_blinded_block_holesky.json"),
        SpecVersion::Electra => include_str!("../data/electra/signed_blinded_block_holesky.json"),
    };
    let mut values: Value = serde_json::from_str(data).unwrap();

    // Remove specified field from the message
    if let Some(message) = values.get_mut("message") {
        if let Value::Object(msg_obj) = message {
            msg_obj.remove(field_name);
        }
    }

    // This should fail since the field is required
    match version {
        SpecVersion::Deneb => {
            let result = serde_json::from_value::<SignedBlindedBeaconBlock<DenebSpec>>(values);
            assert!(result.is_err());
            result.unwrap_err().to_string()
        }
        SpecVersion::Electra => {
            let result = serde_json::from_value::<SignedBlindedBeaconBlock<ElectraSpec>>(values);
            assert!(result.is_err());
            result.unwrap_err().to_string()
        }
    }
}

#[test]
fn test_signed_blinded_block_missing_fields() {
    let fields = ["slot", "proposer_index", "parent_root", "state_root", "body"];

    for field in fields {
        for version in [SpecVersion::Deneb, SpecVersion::Electra] {
            let error = test_missing_signed_blinded_block_field(version, field);
            assert!(
                error.contains(&format!("missing field `{}`", field)),
                "Expected error about missing {}, got: {}",
                field,
                error
            );
        }
    }
}

fn test_missing_submit_block_response_field(version: SpecVersion, field_name: &str) -> String {
    let data = match version {
        SpecVersion::Deneb => include_str!("../data/deneb/submit_block_response_holesky.json"),
        SpecVersion::Electra => include_str!("../data/electra/submit_block_response_holesky.json"),
    };
    let mut values: Value = serde_json::from_str(data).unwrap();

    // Remove specified field
    if let Value::Object(obj) = &mut values {
        obj.remove(field_name);
    }

    // This should fail since the field is required
    match version {
        SpecVersion::Deneb => {
            let result = serde_json::from_value::<SubmitBlindedBlockResponse<DenebSpec>>(values);
            assert!(result.is_err());
            result.unwrap_err().to_string()
        }
        SpecVersion::Electra => {
            let result = serde_json::from_value::<SubmitBlindedBlockResponse<ElectraSpec>>(values);
            assert!(result.is_err());
            result.unwrap_err().to_string()
        }
    }
}

#[test]
fn test_submit_block_response_missing_fields() {
    let fields = ["version", "data"];

    for field in fields {
        for version in [SpecVersion::Deneb, SpecVersion::Electra] {
            let error = test_missing_submit_block_response_field(version, field);
            assert!(
                error.contains(&format!("missing field `{}`", field)),
                "Expected error about missing {}, got: {}",
                field,
                error
            );
        }
    }
}
