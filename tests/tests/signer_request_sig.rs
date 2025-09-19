use std::collections::HashMap;

use alloy::primitives::{b256, hex};
use cb_common::{
    commit::{
        constants::REQUEST_SIGNATURE_BLS_PATH, request::SignConsensusRequest,
        response::BlsSignResponse,
    },
    config::{ModuleSigningConfig, load_module_signing_configs},
    types::{BlsPublicKey, BlsSignature, Chain, ModuleId},
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
const PUBKEY_1: [u8; 48] = hex!(
    "883827193f7627cd04e621e1e8d56498362a52b2a30c9a1c72036eb935c4278dee23d38a24d2f7dda62689886f0c39f4"
);
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
    let start_config = start_server(20200, &mod_cfgs, ADMIN_SECRET.to_string(), false).await?;
    let jwt_config = mod_cfgs.get(&module_id).expect("JWT config for test module not found");

    // Send a signing request
    let object_root = b256!("0x0123456789012345678901234567890123456789012345678901234567890123");
    let nonce: u64 = 101;
    let pubkey = BlsPublicKey::deserialize(&PUBKEY_1).unwrap();
    let request = SignConsensusRequest { pubkey: pubkey.clone(), object_root, nonce };
    let payload_bytes = serde_json::to_vec(&request)?;
    let jwt = create_jwt(
        &module_id,
        &jwt_config.jwt_secret,
        REQUEST_SIGNATURE_BLS_PATH,
        Some(&payload_bytes),
    )?;
    let client = reqwest::Client::new();
    let url = format!("http://{}{}", start_config.endpoint, REQUEST_SIGNATURE_BLS_PATH);
    let response = client.post(&url).json(&request).bearer_auth(&jwt).send().await?;

    // Verify the response is successful
    assert!(response.status() == StatusCode::OK);

    // Verify the signature is returned
    let sig_response = response.json::<BlsSignResponse>().await?;
    let expected = BlsSignResponse::new(
        pubkey,
        object_root,
        mod_cfgs.get(&module_id).unwrap().signing_id,
        nonce,
        Chain::Hoodi.id(),
        BlsSignature::deserialize(&hex!("0xb653034a6da0e516cb999d6bbcd5ddd8dde9695322a94aefcd3049e6235e0f4f63b13d81ddcd80d4e1e698c3f88c3b440ae696650ccef2f22329afb4ffecec85a34523e25920ceced54c5bc31168174a3b352977750c222c1c25f72672467e5c")).unwrap());
    assert_eq!(sig_response, expected, "Signature response does not match expected value");

    Ok(())
}

/// Makes sure the signer service returns a signature that is different for each
/// module
#[tokio::test]
async fn test_signer_sign_request_different_module() -> Result<()> {
    setup_test_env();
    let module_id = ModuleId(MODULE_ID_2.to_string());
    let mod_cfgs = create_mod_signing_configs().await;
    let start_config = start_server(20201, &mod_cfgs, ADMIN_SECRET.to_string(), false).await?;
    let jwt_config = mod_cfgs.get(&module_id).expect("JWT config for 2nd test module not found");

    // Send a signing request
    let object_root = b256!("0x0123456789012345678901234567890123456789012345678901234567890123");
    let nonce: u64 = 101;
    let pubkey = BlsPublicKey::deserialize(&PUBKEY_1).unwrap();
    let request = SignConsensusRequest { pubkey: pubkey.clone(), object_root, nonce };
    let payload_bytes = serde_json::to_vec(&request)?;
    let jwt = create_jwt(
        &module_id,
        &jwt_config.jwt_secret,
        REQUEST_SIGNATURE_BLS_PATH,
        Some(&payload_bytes),
    )?;
    let client = reqwest::Client::new();
    let url = format!("http://{}{}", start_config.endpoint, REQUEST_SIGNATURE_BLS_PATH);
    let response = client.post(&url).json(&request).bearer_auth(&jwt).send().await?;

    // Verify the response is successful
    assert!(response.status() == StatusCode::OK);

    // Verify the signature is returned
    let sig_response = response.json::<BlsSignResponse>().await?;
    assert_eq!(sig_response.pubkey, pubkey, "Public key does not match expected value");
    assert_eq!(sig_response.object_root, object_root, "Object root does not match expected value");
    assert_eq!(
        sig_response.module_signing_id,
        mod_cfgs.get(&module_id).unwrap().signing_id,
        "Module signing ID does not match expected value"
    );
    assert_ne!(
        sig_response.signature, BlsSignature::deserialize(&hex!("0xb653034a6da0e516cb999d6bbcd5ddd8dde9695322a94aefcd3049e6235e0f4f63b13d81ddcd80d4e1e698c3f88c3b440ae696650ccef2f22329afb4ffecec85a34523e25920ceced54c5bc31168174a3b352977750c222c1c25f72672467e5c")).unwrap(),
        "Signature matches the reference signature, which should not happen"
    );

    Ok(())
}

/// Makes sure the signer service does not allow requests for JWTs that do
/// not match the JWT hash
#[tokio::test]
async fn test_signer_sign_request_incorrect_hash() -> Result<()> {
    setup_test_env();
    let module_id = ModuleId(MODULE_ID_2.to_string());
    let mod_cfgs = create_mod_signing_configs().await;
    let start_config = start_server(20202, &mod_cfgs, ADMIN_SECRET.to_string(), false).await?;
    let jwt_config = mod_cfgs.get(&module_id).expect("JWT config for 2nd test module not found");

    // Send a signing request
    let fake_object_root =
        b256!("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd");
    let nonce: u64 = 101;
    let pubkey = BlsPublicKey::deserialize(&PUBKEY_1).unwrap();
    let fake_request =
        SignConsensusRequest { pubkey: pubkey.clone(), object_root: fake_object_root, nonce };
    let fake_payload_bytes = serde_json::to_vec(&fake_request)?;
    let true_object_root =
        b256!("0x0123456789012345678901234567890123456789012345678901234567890123");
    let true_request = SignConsensusRequest { pubkey, object_root: true_object_root, nonce };
    let jwt = create_jwt(
        &module_id,
        &jwt_config.jwt_secret,
        REQUEST_SIGNATURE_BLS_PATH,
        Some(&fake_payload_bytes),
    )?;
    let client = reqwest::Client::new();
    let url = format!("http://{}{}", start_config.endpoint, REQUEST_SIGNATURE_BLS_PATH);
    let response = client.post(&url).json(&true_request).bearer_auth(&jwt).send().await?;

    // Verify that authorization failed
    assert!(response.status() == StatusCode::UNAUTHORIZED);
    Ok(())
}

/// Makes sure the signer service does not allow signer requests for JWTs that
/// do not include a payload hash
#[tokio::test]
async fn test_signer_sign_request_missing_hash() -> Result<()> {
    setup_test_env();
    let module_id = ModuleId(MODULE_ID_2.to_string());
    let mod_cfgs = create_mod_signing_configs().await;
    let start_config = start_server(20203, &mod_cfgs, ADMIN_SECRET.to_string(), false).await?;
    let jwt_config = mod_cfgs.get(&module_id).expect("JWT config for 2nd test module not found");

    // Send a signing request
    let nonce: u64 = 101;
    let pubkey = BlsPublicKey::deserialize(&PUBKEY_1).unwrap();
    let object_root = b256!("0x0123456789012345678901234567890123456789012345678901234567890123");
    let request = SignConsensusRequest { pubkey, object_root, nonce };
    let jwt = create_jwt(&module_id, &jwt_config.jwt_secret, REQUEST_SIGNATURE_BLS_PATH, None)?;
    let client = reqwest::Client::new();
    let url = format!("http://{}{}", start_config.endpoint, REQUEST_SIGNATURE_BLS_PATH);
    let response = client.post(&url).json(&request).bearer_auth(&jwt).send().await?;

    // Verify that authorization failed
    assert!(response.status() == StatusCode::UNAUTHORIZED);
    Ok(())
}
