use std::{collections::HashMap, time::Duration};

use alloy::{hex, primitives::FixedBytes};
use cb_common::{
    commit::request::GetPubkeysResponse,
    config::{ModuleSigningConfig, StartSignerConfig},
    constants::SIGNER_JWT_EXPIRATION,
    signer::{SignerLoader, ValidatorKeysFormat},
    types::{Chain, Jwt, JwtAdmin, ModuleId},
};
use cb_signer::service::SigningService;
use eyre::Result;
use reqwest::{Response, StatusCode};
use tracing::info;

use crate::utils::{get_signer_config, get_start_signer_config};

// Starts the signer moduler server on a separate task and returns its
// configuration
pub async fn start_server(
    port: u16,
    mod_signing_configs: &HashMap<ModuleId, ModuleSigningConfig>,
    admin_secret: String,
) -> Result<StartSignerConfig> {
    let chain = Chain::Hoodi;

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
    let start_config = get_start_signer_config(config, chain, mod_signing_configs, admin_secret);

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
pub async fn verify_pubkeys(response: Response) -> Result<()> {
    // Verify the expected pubkeys are returned
    assert!(response.status() == StatusCode::OK);
    let pubkey_json = response.json::<GetPubkeysResponse>().await?;
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

// Creates a JWT for module administration
pub fn create_admin_jwt(admin_secret: String) -> Result<Jwt> {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &JwtAdmin {
            admin: true,
            exp: jsonwebtoken::get_current_timestamp() + SIGNER_JWT_EXPIRATION,
        },
        &jsonwebtoken::EncodingKey::from_secret(admin_secret.as_ref()),
    )
    .map_err(Into::into)
    .map(Jwt::from)
}
