use std::collections::HashMap;

use alloy::{
    hex,
    primitives::{b256, FixedBytes},
};
use cb_common::{
    commit::{
        constants::REQUEST_SIGNATURE_PATH,
        request::{SignConsensusRequest, SignRequest},
    },
    config::{load_module_signing_configs, ModuleSigningConfig},
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
const ADMIN_SECRET: &str = "test-admin-secret";

async fn create_mod_signing_configs() -> HashMap<ModuleId, ModuleSigningConfig> {
    let mut cfg =
        utils::get_commit_boost_config(utils::get_pbs_static_config(utils::get_pbs_config(0)));

    let module_id_1 = ModuleId(MODULE_ID_1.to_string());
    let signing_id_1 = b256!("0x6a33a23ef26a4836979edff86c493a69b26ccf0b4a16491a815a13787657431b");
    let module_id_2 = ModuleId(MODULE_ID_2.to_string());
    let signing_id_2 = b256!("0x61fe00135d7b4912a8c63ada215ac2e62326e6e7b30f49a29fcf9779d7ad800d");

    cfg.modules = Some(vec![
        utils::create_module_config(module_id_1.clone(), signing_id_1),
        utils::create_module_config(module_id_2.clone(), signing_id_2),
    ]);

    let jwts = HashMap::from([
        (module_id_1.clone(), "supersecret".to_string()),
        (module_id_2.clone(), "anothersecret".to_string()),
    ]);

    load_module_signing_configs(&cfg, &jwts).unwrap()
}

/// Makes sure the signer service signs requests correctly, using the module's
/// signing ID
#[tokio::test]
async fn test_signer_sign_request_good() -> Result<()> {
    setup_test_env();
    let module_id = ModuleId(MODULE_ID_1.to_string());
    let mod_cfgs = create_mod_signing_configs().await;
    let start_config = start_server(20200, &mod_cfgs, ADMIN_SECRET.to_string()).await?;
    let jwt_config = mod_cfgs.get(&module_id).expect("JWT config for test module not found");

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

    let expected_signature = "\"0xa43e623f009e615faa3987368f64d6286a4103de70e9a81d82562c50c91eae2d5d6fb9db9fe943aa8ee42fd92d8210c1149f25ed6aa72a557d74a0ed5646fdd0e8255ec58e3e2931695fe913863ba0cdf90d29f651bce0a34169a6f6ce5b3115\"";
    assert_eq!(signature, expected_signature, "Signature does not match expected value");

    Ok(())
}

/// Makes sure the signer service returns a signature that is different for each
/// module
#[tokio::test]
async fn test_signer_sign_request_different_module() -> Result<()> {
    setup_test_env();
    let module_id = ModuleId(MODULE_ID_2.to_string());
    let mod_cfgs = create_mod_signing_configs().await;
    let start_config = start_server(20201, &mod_cfgs, ADMIN_SECRET.to_string()).await?;
    let jwt_config = mod_cfgs.get(&module_id).expect("JWT config for 2nd test module not found");

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

    let incorrect_signature = "\"0xa43e623f009e615faa3987368f64d6286a4103de70e9a81d82562c50c91eae2d5d6fb9db9fe943aa8ee42fd92d8210c1149f25ed6aa72a557d74a0ed5646fdd0e8255ec58e3e2931695fe913863ba0cdf90d29f651bce0a34169a6f6ce5b3115\"";
    assert_ne!(signature, incorrect_signature, "Signature does not match expected value");

    Ok(())
}
