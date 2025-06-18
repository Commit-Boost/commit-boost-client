use alloy::{
    hex,
    primitives::{b256, FixedBytes},
};
use cb_common::{
    commit::{
        constants::REQUEST_SIGNATURE_PATH,
        request::{SignConsensusRequest, SignRequest},
    },
    types::ModuleId,
    utils::create_jwt,
};
use cb_tests::{
    signer_service::start_server,
    utils::{self, setup_test_env},
};
use eyre::Result;
use reqwest::StatusCode;

const MODULE_ID_1: &str = "test-module";
const MODULE_ID_2: &str = "another-module";
const PUBKEY_1: [u8; 48] =
    hex!("883827193f7627cd04e621e1e8d56498362a52b2a30c9a1c72036eb935c4278dee23d38a24d2f7dda62689886f0c39f4");
const PUBKEY_2: [u8; 48] =
    hex!("b3a22e4a673ac7a153ab5b3c17a4dbef55f7e47210b20c0cbb0e66df5b36bb49ef808577610b034172e955d2312a61b9");

/// Makes sure the signer service signs requests correctly, using the module's
/// signing ID
#[tokio::test]
async fn test_signer_sign_request_good() -> Result<()> {
    setup_test_env();
    let module_id = ModuleId(MODULE_ID_1.to_string());
    let jwts = utils::get_jwt_config();
    let start_config = start_server(20200, &jwts).await?;
    let jwt_config = jwts.get(&module_id).expect("JWT config for test module not found");

    // Send a signing request
    let object_root = b256!("0x0123456789012345678901234567890123456789012345678901234567890123");
    let request =
        SignRequest::Consensus(SignConsensusRequest { pubkey: FixedBytes(PUBKEY_1), object_root });
    let jwt = create_jwt(&module_id, &jwt_config.jwt_secret)?;
    let client = reqwest::Client::new();
    let url = format!("http://{}{}", start_config.endpoint, REQUEST_SIGNATURE_PATH);
    let response = client.post(&url).json(&request).bearer_auth(&jwt).send().await?;

    // Verify the response is successful
    assert!(response.status() == StatusCode::OK);

    // Verify the signature is returned
    let signature = response.text().await?;
    assert!(!signature.is_empty(), "Signature should not be empty");

    let expected_signature = "\"0x992e6fc29ba219e6afeceb91df3f58ebaa6c82ea8d00b3f4564a4d47cfd886c076ade87c6df765ba3fdcc5ba71513d8f0f12b17c76e4859126ab902a3ae5e8789eb3c9c49e8e9c5cd70ef0a93c76ca16763a940b991192eaba97dcc8c060ff7a\"";
    assert_eq!(signature, expected_signature, "Signature does not match expected value");

    Ok(())
}

/// Makes sure the signer service returns a signature that is different for each
/// module
#[tokio::test]
async fn test_signer_sign_request_different_module() -> Result<()> {
    setup_test_env();
    let module_id = ModuleId(MODULE_ID_2.to_string());
    let jwts = utils::get_jwt_config();
    let start_config = start_server(20201, &jwts).await?;
    let jwt_config = jwts.get(&module_id).expect("JWT config for 2nd test module not found");

    // Send a signing request
    let object_root = b256!("0x0123456789012345678901234567890123456789012345678901234567890123");
    let request =
        SignRequest::Consensus(SignConsensusRequest { pubkey: FixedBytes(PUBKEY_1), object_root });
    let jwt = create_jwt(&module_id, &jwt_config.jwt_secret)?;
    let client = reqwest::Client::new();
    let url = format!("http://{}{}", start_config.endpoint, REQUEST_SIGNATURE_PATH);
    let response = client.post(&url).json(&request).bearer_auth(&jwt).send().await?;

    // Verify the response is successful
    assert!(response.status() == StatusCode::OK);

    // Verify the signature is returned
    let signature = response.text().await?;
    assert!(!signature.is_empty(), "Signature should not be empty");

    let incorrect_signature = "\"0x992e6fc29ba219e6afeceb91df3f58ebaa6c82ea8d00b3f4564a4d47cfd886c076ade87c6df765ba3fdcc5ba71513d8f0f12b17c76e4859126ab902a3ae5e8789eb3c9c49e8e9c5cd70ef0a93c76ca16763a940b991192eaba97dcc8c060ff7a\"";
    assert_ne!(signature, incorrect_signature, "Signature does not match expected value");

    Ok(())
}
