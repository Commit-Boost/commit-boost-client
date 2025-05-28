use std::{collections::HashMap, time::Duration};

use alloy::{hex, primitives::FixedBytes};
use cb_common::{
    commit::{constants::GET_PUBKEYS_PATH, request::GetPubkeysResponse},
    signer::{SignerLoader, ValidatorKeysFormat},
    types::{Chain, ModuleId},
    utils::create_jwt,
};
use cb_signer::service::SigningService;
use cb_tests::utils::{get_signer_config, get_start_signer_config, setup_test_env};
use eyre::Result;
use tracing::info;

const JWT_MODULE: &str = "test-module";
const JWT_SECRET: &str = "test-jwt-secret";

#[tokio::test]
async fn test_signer_jwt_auth_success() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;

    // Mock JWT secrets
    let module_id = ModuleId(JWT_MODULE.to_string());
    let mut jwts = HashMap::new();
    jwts.insert(module_id.clone(), JWT_SECRET.to_string());

    // Create a signer config
    let loader = SignerLoader::ValidatorsDir {
        keys_path: "data/keystores/keys".into(),
        secrets_path: "data/keystores/secrets".into(),
        format: ValidatorKeysFormat::Lighthouse,
    };
    let config = get_signer_config(loader);
    let host = config.host;
    let port = config.port;
    let start_config = get_start_signer_config(config, chain, jwts);

    // Run the Signer
    let server_handle = tokio::spawn(SigningService::run(start_config));

    // Make sure the server is running
    tokio::time::sleep(Duration::from_millis(100)).await;
    if server_handle.is_finished() {
        return Err(eyre::eyre!(
            "Signer service failed to start: {}",
            server_handle.await.unwrap_err()
        ));
    }

    // Create a JWT header
    let jwt = create_jwt(&module_id, JWT_SECRET)?;

    // Run a pubkeys request
    let client = reqwest::Client::new();
    let url = format!("http://{}:{}{}", host, port, GET_PUBKEYS_PATH);
    let response = client.get(&url).bearer_auth(jwt).send().await?;
    assert!(response.status().is_success(), "Failed to authenticate with JWT");
    let pubkey_json = response.json::<GetPubkeysResponse>().await?;

    // Verify the expected pubkeys are returned
    assert_eq!(pubkey_json.keys.len(), 2);
    let expected_pubkeys = vec![
        FixedBytes::new(hex!("883827193f7627cd04e621e1e8d56498362a52b2a30c9a1c72036eb935c4278dee23d38a24d2f7dda62689886f0c39f4")),
        FixedBytes::new(hex!("b3a22e4a673ac7a153ab5b3c17a4dbef55f7e47210b20c0cbb0e66df5b36bb49ef808577610b034172e955d2312a61b9")),
    ];
    for expected in expected_pubkeys {
        assert!(
            pubkey_json.keys.iter().any(|k| k.consensus == expected),
            "Expected pubkey not found: {:?}",
            expected
        );
        info!("Server returned expected pubkey: {:?}", expected);
    }

    Ok(())
}
