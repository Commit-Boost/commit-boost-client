use std::collections::HashMap;

use alloy::primitives::b256;
use cb_common::{
    commit::constants::GET_PUBKEYS_PATH,
    config::{ModuleSigningConfig, load_module_signing_configs},
    types::ModuleId,
    utils::create_jwt,
};
use cb_tests::{
    signer_service::{start_server, verify_pubkeys},
    utils::{self, setup_test_env},
};
use eyre::{Result, bail};
use reqwest::Certificate;

const JWT_MODULE: &str = "test-module";
const JWT_SECRET: &str = "test-jwt-secret";
const ADMIN_SECRET: &str = "test-admin-secret";

async fn create_mod_signing_configs() -> HashMap<ModuleId, ModuleSigningConfig> {
    let mut cfg =
        utils::get_commit_boost_config(utils::get_pbs_static_config(utils::get_pbs_config(0)));

    let module_id = ModuleId(JWT_MODULE.to_string());
    let signing_id = b256!("0101010101010101010101010101010101010101010101010101010101010101");

    cfg.modules = Some(vec![utils::create_module_config(module_id.clone(), signing_id)]);

    let jwts = HashMap::from([(module_id.clone(), JWT_SECRET.to_string())]);

    load_module_signing_configs(&cfg, &jwts).unwrap()
}

#[tokio::test]
async fn test_signer_tls() -> Result<()> {
    setup_test_env();
    let module_id = ModuleId(JWT_MODULE.to_string());
    let mod_cfgs = create_mod_signing_configs().await;
    let start_config = start_server(20100, &mod_cfgs, ADMIN_SECRET.to_string(), true).await?;
    let jwt_config = mod_cfgs.get(&module_id).expect("JWT config for test module not found");

    // Run a pubkeys request
    let jwt = create_jwt(&module_id, &jwt_config.jwt_secret, None)?;
    let cert = match start_config.tls_certificates {
        Some(ref certificates) => &certificates.0,
        None => bail!("TLS certificates not found in start config"),
    };
    let client =
        reqwest::Client::builder().add_root_certificate(Certificate::from_pem(cert)?).build()?;
    let url = format!("https://{}{}", start_config.endpoint, GET_PUBKEYS_PATH);
    let response = client.get(&url).bearer_auth(&jwt).send().await?;

    // Verify the expected pubkeys are returned
    verify_pubkeys(response).await?;

    Ok(())
}
