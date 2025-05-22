use std::{collections::HashMap, fs, time::Duration};

use cb_common::{
    signer::{SignerLoader, ValidatorKeysFormat},
    types::{Chain, ModuleId},
};
use cb_signer::service::SigningService;
use cb_tests::utils::{get_signer_config, get_start_signer_config, setup_test_env};
use eyre::Result;
use tempfile::tempdir;

#[tokio::test]
async fn test_signer_jwt_auth_success() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;

    // Mock JWT secrets
    let mut jwts = HashMap::new();
    jwts.insert(ModuleId("test-module".to_string()), "test-jwt-secret".to_string());

    // Create a temp folder and key structure
    let test_folder = tempdir()?;
    let test_path = test_folder.path();
    let keys_path = test_path.join("keys");
    let secrets_path = test_path.join("secrets");
    fs::create_dir_all(&keys_path)?;
    fs::create_dir_all(&secrets_path)?;

    // Create a signer config
    let loader = SignerLoader::ValidatorsDir {
        keys_path,
        secrets_path,
        format: ValidatorKeysFormat::Lighthouse,
    };
    let config = get_signer_config(loader);
    let start_config = get_start_signer_config(config, chain, jwts);

    // Run the Signer
    tokio::spawn(SigningService::run(start_config));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    // TODO: simple client to test the JWT auth endpoint

    Ok(())
}
