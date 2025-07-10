use std::{collections::HashMap, time::Duration};

use alloy::hex;
use cb_common::{
    commit::{constants::GET_PUBKEYS_PATH, request::GetPubkeysResponse},
    config::StartSignerConfig,
    pbs::BlsPublicKey,
    signer::{SignerLoader, ValidatorKeysFormat},
    types::{Chain, ModuleId},
    utils::create_jwt,
};
use cb_signer::service::SigningService;
use cb_tests::utils::{get_signer_config, get_start_signer_config, setup_test_env};
use eyre::Result;
use reqwest::{Response, StatusCode};
use tracing::info;

const JWT_MODULE: &str = "test-module";
const JWT_SECRET: &str = "test-jwt-secret";

#[tokio::test]
async fn test_signer_jwt_auth_success() -> Result<()> {
    setup_test_env();
    let module_id = ModuleId(JWT_MODULE.to_string());
    let start_config = start_server(20100).await?;

    // Run a pubkeys request
    let jwt = create_jwt(&module_id, JWT_SECRET)?;
    let client = reqwest::Client::new();
    let url = format!("http://{}{}", start_config.endpoint, GET_PUBKEYS_PATH);
    let response = client.get(&url).bearer_auth(&jwt).send().await?;

    // Verify the expected pubkeys are returned
    verify_pubkeys(response).await?;

    Ok(())
}

#[tokio::test]
async fn test_signer_jwt_auth_fail() -> Result<()> {
    setup_test_env();
    let module_id = ModuleId(JWT_MODULE.to_string());
    let start_config = start_server(20200).await?;

    // Run a pubkeys request - this should fail due to invalid JWT
    let jwt = create_jwt(&module_id, "incorrect secret")?;
    let client = reqwest::Client::new();
    let url = format!("http://{}{}", start_config.endpoint, GET_PUBKEYS_PATH);
    let response = client.get(&url).bearer_auth(&jwt).send().await?;
    assert!(response.status() == StatusCode::UNAUTHORIZED);
    info!(
        "Server returned expected error code {} for invalid JWT: {}",
        response.status(),
        response.text().await.unwrap_or_else(|_| "No response body".to_string())
    );
    Ok(())
}

#[tokio::test]
async fn test_signer_jwt_rate_limit() -> Result<()> {
    setup_test_env();
    let module_id = ModuleId(JWT_MODULE.to_string());
    let start_config = start_server(20300).await?;

    // Run as many pubkeys requests as the fail limit
    let jwt = create_jwt(&module_id, "incorrect secret")?;
    let client = reqwest::Client::new();
    let url = format!("http://{}{}", start_config.endpoint, GET_PUBKEYS_PATH);
    for _ in 0..start_config.jwt_auth_fail_limit {
        let response = client.get(&url).bearer_auth(&jwt).send().await?;
        assert!(response.status() == StatusCode::UNAUTHORIZED);
    }

    // Run another request - this should fail due to rate limiting now
    let jwt = create_jwt(&module_id, JWT_SECRET)?;
    let response = client.get(&url).bearer_auth(&jwt).send().await?;
    assert!(response.status() == StatusCode::TOO_MANY_REQUESTS);

    // Wait for the rate limit timeout
    tokio::time::sleep(Duration::from_secs(start_config.jwt_auth_fail_timeout_seconds as u64))
        .await;

    // Now the next request should succeed
    let response = client.get(&url).bearer_auth(&jwt).send().await?;
    verify_pubkeys(response).await?;

    Ok(())
}

// Starts the signer moduler server on a separate task and returns its
// configuration
async fn start_server(port: u16) -> Result<StartSignerConfig> {
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
    let mut config = get_signer_config(loader);
    config.port = port;
    config.jwt_auth_fail_limit = 3; // Set a low fail limit for testing
    config.jwt_auth_fail_timeout_seconds = 3; // Set a short timeout for testing
    let start_config = get_start_signer_config(config, chain, jwts);

    // Run the Signer
    let server_handle = tokio::spawn(SigningService::run(start_config.clone()));

    // Make sure the server is running
    tokio::time::sleep(Duration::from_millis(100)).await;
    if server_handle.is_finished() {
        return Err(eyre::eyre!(
            "Signer service failed to start: {}",
            server_handle.await.unwrap_err()
        ));
    }
    Ok(start_config)
}

// Verifies that the pubkeys returned by the server match the pubkeys in the
// test data
async fn verify_pubkeys(response: Response) -> Result<()> {
    // Verify the expected pubkeys are returned
    assert!(response.status() == StatusCode::OK);
    let pubkey_json = response.json::<GetPubkeysResponse>().await?;
    assert_eq!(pubkey_json.keys.len(), 2);
    let expected_pubkeys = vec![
        BlsPublicKey::deserialize(&hex!("883827193f7627cd04e621e1e8d56498362a52b2a30c9a1c72036eb935c4278dee23d38a24d2f7dda62689886f0c39f4")).unwrap(),
        BlsPublicKey::deserialize(&hex!("b3a22e4a673ac7a153ab5b3c17a4dbef55f7e47210b20c0cbb0e66df5b36bb49ef808577610b034172e955d2312a61b9")).unwrap(),
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
