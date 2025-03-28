use std::time::{Duration, Instant};

use alloy::{primitives::Address, rpc::types::beacon::BlsSignature};
use eyre::WrapErr;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::Deserialize;
use url::Url;

use super::{
    constants::{GENERATE_PROXY_KEY_PATH, GET_PUBKEYS_PATH, REQUEST_SIGNATURE_PATH},
    error::SignerClientError,
    request::{
        EncryptionScheme, GenerateProxyRequest, GetPubkeysResponse, ProxyId, SignConsensusRequest,
        SignProxyRequest, SignRequest, SignedProxyDelegation,
    },
};
use crate::{
    constants::SIGNER_JWT_EXPIRATION,
    signer::{BlsPublicKey, EcdsaSignature},
    types::{Jwt, ModuleId},
    utils::create_jwt,
    DEFAULT_REQUEST_TIMEOUT,
};

/// Client used by commit modules to request signatures via the Signer API
#[derive(Debug, Clone)]
pub struct SignerClient {
    /// Url endpoint of the Signer Module
    url: Url,
    client: reqwest::Client,
    last_jwt_refresh: Instant,
    module_id: ModuleId,
    jwt_secret: Jwt,
}

impl SignerClient {
    /// Create a new SignerClient
    pub fn new(signer_server_url: Url, jwt_secret: Jwt, module_id: ModuleId) -> eyre::Result<Self> {
        let jwt = create_jwt(&module_id, &jwt_secret)?;

        let mut auth_value =
            HeaderValue::from_str(&format!("Bearer {}", jwt)).wrap_err("invalid jwt")?;
        auth_value.set_sensitive(true);

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, auth_value);

        let client = reqwest::Client::builder()
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .default_headers(headers)
            .build()?;

        Ok(Self {
            url: signer_server_url,
            client,
            last_jwt_refresh: Instant::now(),
            module_id,
            jwt_secret,
        })
    }

    fn refresh_jwt(&mut self) -> Result<(), SignerClientError> {
        if self.last_jwt_refresh.elapsed() > Duration::from_secs(SIGNER_JWT_EXPIRATION) {
            let jwt = create_jwt(&self.module_id, &self.jwt_secret)?;

            let mut auth_value =
                HeaderValue::from_str(&format!("Bearer {}", jwt)).wrap_err("invalid jwt")?;
            auth_value.set_sensitive(true);

            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, auth_value);

            self.client = reqwest::Client::builder()
                .timeout(DEFAULT_REQUEST_TIMEOUT)
                .default_headers(headers)
                .build()?;
        }

        Ok(())
    }

    /// Request a list of validator pubkeys for which signatures can be
    /// requested.
    // TODO: add more docs on how proxy keys work
    pub async fn get_pubkeys(&mut self) -> Result<GetPubkeysResponse, SignerClientError> {
        self.refresh_jwt()?;

        let url = self.url.join(GET_PUBKEYS_PATH)?;
        let res = self.client.get(url).send().await?;

        if !res.status().is_success() {
            return Err(SignerClientError::FailedRequest {
                status: res.status().as_u16(),
                error_msg: String::from_utf8_lossy(&res.bytes().await?).into_owned(),
            });
        }

        Ok(serde_json::from_slice(&res.bytes().await?)?)
    }

    /// Send a signature request
    async fn request_signature<T>(&mut self, request: &SignRequest) -> Result<T, SignerClientError>
    where
        T: for<'de> Deserialize<'de>,
    {
        self.refresh_jwt()?;

        let url = self.url.join(REQUEST_SIGNATURE_PATH)?;
        let res = self.client.post(url).json(&request).send().await?;

        let status = res.status();
        let response_bytes = res.bytes().await?;

        if !status.is_success() {
            return Err(SignerClientError::FailedRequest {
                status: status.as_u16(),
                error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            });
        }

        let signature = serde_json::from_slice(&response_bytes)?;

        Ok(signature)
    }

    pub async fn request_consensus_signature(
        &mut self,
        request: SignConsensusRequest,
    ) -> Result<BlsSignature, SignerClientError> {
        self.request_signature(&request.into()).await
    }

    pub async fn request_proxy_signature_ecdsa(
        &mut self,
        request: SignProxyRequest<Address>,
    ) -> Result<EcdsaSignature, SignerClientError> {
        self.request_signature(&request.into()).await
    }

    pub async fn request_proxy_signature_bls(
        &mut self,
        request: SignProxyRequest<BlsPublicKey>,
    ) -> Result<BlsSignature, SignerClientError> {
        self.request_signature(&request.into()).await
    }

    async fn generate_proxy_key<T>(
        &mut self,
        request: &GenerateProxyRequest,
    ) -> Result<SignedProxyDelegation<T>, SignerClientError>
    where
        T: ProxyId + for<'de> Deserialize<'de>,
    {
        self.refresh_jwt()?;

        let url = self.url.join(GENERATE_PROXY_KEY_PATH)?;
        let res = self.client.post(url).json(&request).send().await?;

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

    pub async fn generate_proxy_key_bls(
        &mut self,
        consensus_pubkey: BlsPublicKey,
    ) -> Result<SignedProxyDelegation<BlsPublicKey>, SignerClientError> {
        let request = GenerateProxyRequest::new(consensus_pubkey, EncryptionScheme::Bls);

        let bls_signed_proxy_delegation = self.generate_proxy_key(&request).await?;

        Ok(bls_signed_proxy_delegation)
    }

    pub async fn generate_proxy_key_ecdsa(
        &mut self,
        consensus_pubkey: BlsPublicKey,
    ) -> Result<SignedProxyDelegation<Address>, SignerClientError> {
        let request = GenerateProxyRequest::new(consensus_pubkey, EncryptionScheme::Ecdsa);

        let ecdsa_signed_proxy_delegation = self.generate_proxy_key(&request).await?;

        Ok(ecdsa_signed_proxy_delegation)
    }
}
