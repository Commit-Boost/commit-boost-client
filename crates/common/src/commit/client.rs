use std::{fmt, sync::Arc};

use alloy::rpc::types::beacon::BlsPublicKey;
use eyre::WrapErr;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::{Deserialize, Serialize};

use super::{
    constants::{GENERATE_PROXY_KEY_PATH, GET_PUBKEYS_PATH, REQUEST_SIGNATURE_PATH},
    error::SignerClientError,
    request::{GenerateProxyRequest, SignRequest, SignedProxyDelegation},
};
use crate::{signer::GenericPubkey, DEFAULT_REQUEST_TIMEOUT};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetPubkeysResponse {
    pub consensus: Vec<BlsPublicKey>,
    pub proxy: Vec<GenericPubkey>,
}

/// Client used by commit modules to request signatures via the Signer API
#[derive(Debug, Clone)]
pub struct SignerClient {
    /// Url endpoint of the Signer Module
    url: Arc<String>,
    client: reqwest::Client,
}

impl SignerClient {
    /// Create a new SignerClient
    pub fn new(signer_server_address: String, jwt: &str) -> eyre::Result<Self> {
        let url = format!("http://{}", signer_server_address);
        let mut headers = HeaderMap::new();

        let mut auth_value =
            HeaderValue::from_str(&format!("Bearer {}", jwt)).wrap_err("invalid jwt")?;
        auth_value.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth_value);
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .default_headers(headers)
            .build()?;

        Ok(Self { url: url.into(), client })
    }

    /// Request a list of validator pubkeys for which signatures can be
    /// requested.
    // TODO: add more docs on how proxy keys work
    pub async fn get_pubkeys(&self) -> Result<GetPubkeysResponse, SignerClientError> {
        let url = format!("{}{}", self.url, GET_PUBKEYS_PATH);
        let res = self.client.get(&url).send().await?;

        let status = res.status();
        let response_bytes = res.bytes().await?;

        if !status.is_success() {
            return Err(SignerClientError::FailedRequest {
                status: status.as_u16(),
                error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            });
        }

        let parsed_response: GetPubkeysResponse = serde_json::from_slice(&response_bytes)?;

        Ok(parsed_response)
    }

    /// Send a signature request
    pub async fn request_signature(
        &self,
        request: &SignRequest,
    ) -> Result<Signature, SignerClientError> {
        let url = format!("{}{}", self.url, REQUEST_SIGNATURE_PATH);
        let res = self.client.post(&url).json(&request).send().await?;

        let status = res.status();
        let response_bytes = res.bytes().await?;

        if !status.is_success() {
            return Err(SignerClientError::FailedRequest {
                status: status.as_u16(),
                error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            });
        }

        let signature: Vec<u8> = serde_json::from_slice(&response_bytes)?;

        Ok(Signature(signature))
    }

    pub async fn generate_proxy_key(
        &self,
        request: &GenerateProxyRequest,
    ) -> Result<SignedProxyDelegation, SignerClientError> {
        let url = format!("{}{}", self.url, GENERATE_PROXY_KEY_PATH);
        println!("{}", serde_json::to_string(&request).unwrap());
        let res = self.client.post(&url).json(&request).send().await?;

        let status = res.status();
        let response_bytes = res.bytes().await?;

        if !status.is_success() {
            return Err(SignerClientError::FailedRequest {
                status: status.as_u16(),
                error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            });
        }

        let signed_proxy_delegation = serde_json::from_slice(&response_bytes)?;

        Ok(signed_proxy_delegation)
    }
}

// NOTE(David):
// For now, this is a simple displayable wrapper around vec, serving as a
// client-side type. It can be further deliberated whether a separate
// client-side type is preferrable over re-using an SDK in `common::signer`.
pub struct Signature(Vec<u8>);

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}
