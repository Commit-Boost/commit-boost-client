use std::sync::Arc;

use alloy::rpc::types::beacon::{BlsPublicKey, BlsSignature};
use reqwest::{header::{HeaderMap, HeaderValue, AUTHORIZATION}, StatusCode};
use serde::{Deserialize, Serialize};

use super::{
    constants::{GENERATE_PROXY_KEY_PATH, GET_PUBKEYS_PATH, REQUEST_SIGNATURE_PATH},
    error::SignerClientError,
    request::{GenerateProxyRequest, SignRequest, SignedProxyDelegation},
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetPubkeysResponse {
    pub consensus: Vec<BlsPublicKey>,
    pub proxy: Vec<BlsPublicKey>,
}

/// Client used by commit modules to request signatures via the Signer API
#[derive(Debug, Clone)]
pub struct SignerClient {
    /// Url endpoint of the Signer Module
    url: Arc<str>,
    client: reqwest::Client,
}

impl SignerClient {
    /// Create a new SignerClient
    pub fn new(signer_server_address: String, jwt: &str) -> Self {
        let url = format!("http://{}", signer_server_address);
        let mut headers = HeaderMap::new();

        let mut auth_value =
            HeaderValue::from_str(&format!("Bearer {}", jwt)).expect("invalid jwt");
        auth_value.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth_value);

        let client = reqwest::Client::builder().default_headers(headers).build().unwrap();

        Self { url: url.into(), client }
    }

    /// Request a list of validator pubkeys for which signatures can be requested.
    /// TODO: add more docs on how proxy keys work
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
    ) -> Result<BlsSignature, SignerClientError> {
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

        let signature: BlsSignature = serde_json::from_slice(&response_bytes)?;

        Ok(signature)
    }

    pub async fn generate_proxy_key(
        &self,
        pubkey: BlsPublicKey,
    ) -> Result<SignedProxyDelegation, SignerClientError> {
        let url = format!("{}{}", self.url, GENERATE_PROXY_KEY_PATH);
        let request = GenerateProxyRequest::new(pubkey);
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
