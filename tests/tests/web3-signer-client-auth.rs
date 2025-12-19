use std::io::Write;

use cb_common::{
    commit::client::SignerClient,
    config::ClientAuthConfig,
    types::{Jwt, ModuleId},
};
use cb_tests::utils::setup_test_env;
use eyre::Result;
use rcgen::{CertificateParams, KeyPair};

const JWT_MODULE: &str = "test-module";
const JWT_SECRET: &str = "test-jwt-secret";

/// Test that the SignerClient can be created with client authentication
#[tokio::test]
async fn test_web3_signer_client_auth() -> Result<()> {
    setup_test_env();

    // Create a keypair first (default: ECDSA P-256)
    let key_pair = KeyPair::generate().unwrap();

    // Create the certificate
    let params = CertificateParams::new(vec!["web3signer-client-test".to_string()])?;
    let cert = params.self_signed(&key_pair)?;

    // PEM-encode the key and certificate to temp files
    let mut cert_file = tempfile::NamedTempFile::new()?;
    let mut key_file = tempfile::NamedTempFile::new()?;
    write!(cert_file, "{}", cert.pem())?;
    write!(key_file, "{}", key_pair.serialize_pem())?;

    // Create the signer config with client auth - this will create a new client
    // that has client auth enabled, so if it fails anywhere then it'll fail
    // here
    let _client = SignerClient::new(
        "http://localhost:0".parse()?,
        Jwt(JWT_SECRET.to_string()),
        ModuleId(JWT_MODULE.to_string()),
        Some(ClientAuthConfig {
            cert_path: cert_file.path().to_path_buf(),
            key_path: key_file.path().to_path_buf(),
        }),
    )?;

    Ok(())
}
