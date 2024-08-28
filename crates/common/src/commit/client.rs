use std::sync::Arc;

use alloy::rpc::types::beacon::BlsSignature;
use axum::body::Bytes;
use eyre::WrapErr;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::{Deserialize, Serialize};

use super::{
    constants::{GENERATE_PROXY_KEY_PATH, GET_PUBKEYS_PATH, REQUEST_SIGNATURE_PATH},
    error::SignerClientError,
    request::{
        EncryptionScheme, GenerateProxyRequest, PublicKey, SignConsensusRequest, SignProxyRequest,
        SignRequest, SignedProxyDelegation,
    },
};
use crate::{
    signer::{
        schemes::{bls::BlsPublicKey, ecdsa::EcdsaSignature},
        EcdsaPublicKey,
    },
    DEFAULT_REQUEST_TIMEOUT,
};

// TODO(David): move to `request.rs`
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetPubkeysResponse {
    pub consensus: Vec<BlsPublicKey>,
    pub proxy_bls: Vec<BlsPublicKey>,
    pub proxy_ecdsa: Vec<EcdsaPublicKey>,
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
    async fn request_signature(&self, request: &SignRequest) -> Result<Bytes, SignerClientError> {
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

        Ok(response_bytes)
    }

    pub async fn request_consensus_signature(
        &self,
        request: SignConsensusRequest,
    ) -> Result<BlsSignature, SignerClientError> {
        let request = SignRequest::Consensus(request);
        let raw_signature = self.request_signature(&request).await?;

        let signature = serde_json::from_slice(&raw_signature)?;

        Ok(signature)
    }

    pub async fn request_proxy_ecdsa_signature(
        &self,
        request: SignProxyRequest<EcdsaPublicKey>,
    ) -> Result<EcdsaSignature, SignerClientError> {
        let raw_signature = self.request_signature(&request.into()).await?;
        let signature = serde_json::from_slice(&raw_signature)?;
        Ok(signature)
    }

    pub async fn request_proxy_bls_signature(
        &self,
        request: SignProxyRequest<BlsPublicKey>,
    ) -> Result<BlsSignature, SignerClientError> {
        let raw_signature = self.request_signature(&request.into()).await?;
        let signature = serde_json::from_slice(&raw_signature)?;
        Ok(signature)
    }

    async fn generate_proxy_key<T>(
        &self,
        request: &GenerateProxyRequest,
    ) -> Result<SignedProxyDelegation<T>, SignerClientError>
    where
        T: PublicKey + for<'de> Deserialize<'de>,
    {
        let url = format!("{}{}", self.url, GENERATE_PROXY_KEY_PATH);
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

    pub async fn generate_bls_proxy_key(
        &self,
        consensus_pubkey: BlsPublicKey,
    ) -> Result<SignedProxyDelegation<BlsPublicKey>, SignerClientError> {
        let request = GenerateProxyRequest::new(consensus_pubkey, EncryptionScheme::Bls);

        let bls_signed_proxy_delegation = self.generate_proxy_key(&request).await?;

        Ok(bls_signed_proxy_delegation)
    }

    pub async fn generate_ecdsa_proxy_key(
        &self,
        consensus_pubkey: BlsPublicKey,
    ) -> Result<SignedProxyDelegation<EcdsaPublicKey>, SignerClientError> {
        let request = GenerateProxyRequest::new(consensus_pubkey, EncryptionScheme::Ecdsa);

        let ecdsa_signed_proxy_delegation = self.generate_proxy_key(&request).await?;

        Ok(ecdsa_signed_proxy_delegation)
    }
}
