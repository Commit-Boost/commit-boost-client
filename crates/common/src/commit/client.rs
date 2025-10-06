use std::path::PathBuf;

use alloy::primitives::Address;
use eyre::WrapErr;
use reqwest::{
    Certificate,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
use url::Url;

use super::{
    constants::{GENERATE_PROXY_KEY_PATH, GET_PUBKEYS_PATH},
    error::SignerClientError,
    request::{
        EncryptionScheme, GenerateProxyRequest, GetPubkeysResponse, ProxyId, SignConsensusRequest,
        SignProxyRequest, SignedProxyDelegation,
    },
};
use crate::{
    DEFAULT_REQUEST_TIMEOUT,
    commit::{
        constants::{
            REQUEST_SIGNATURE_BLS_PATH, REQUEST_SIGNATURE_PROXY_BLS_PATH,
            REQUEST_SIGNATURE_PROXY_ECDSA_PATH,
        },
        response::{BlsSignResponse, EcdsaSignResponse},
    },
    constants::SIGNER_JWT_EXPIRATION,
    signer::EcdsaSignature,
    types::{BlsPublicKey, BlsSignature, Jwt, ModuleId},
    utils::create_jwt,
};

/// Client used by commit modules to request signatures via the Signer API
#[derive(Debug, Clone)]
pub struct SignerClient {
    /// Url endpoint of the Signer Module
    url: Url,
    client: reqwest::Client,
    module_id: ModuleId,
    jwt_secret: Jwt,
}

impl SignerClient {
    /// Create a new SignerClient
    pub fn new(
        signer_server_url: Url,
        cert_path: Option<PathBuf>,
        jwt_secret: Jwt,
        module_id: ModuleId,
    ) -> eyre::Result<Self> {
        let mut builder = reqwest::Client::builder().timeout(DEFAULT_REQUEST_TIMEOUT);

        // If a certificate path is provided, use it
        if let Some(cert_path) = cert_path {
            builder = builder
                .use_rustls_tls()
                .add_root_certificate(Certificate::from_pem(&std::fs::read(cert_path)?)?);
        }

        Ok(Self { url: signer_server_url, client: builder.build()?, module_id, jwt_secret })
    }

    fn create_jwt_for_payload<T: Serialize>(
        &mut self,
        route: &str,
        payload: &T,
    ) -> Result<Jwt, SignerClientError> {
        let payload_vec = serde_json::to_vec(payload)?;
        create_jwt(&self.module_id, &self.jwt_secret, route, Some(&payload_vec))
            .wrap_err("failed to create JWT for payload")
            .map_err(SignerClientError::JWTError)
    }

    /// Request a list of validator pubkeys for which signatures can be
    /// requested.
    // TODO: add more docs on how proxy keys work
    pub async fn get_pubkeys(&mut self) -> Result<GetPubkeysResponse, SignerClientError> {
        let jwt = create_jwt(&self.module_id, &self.jwt_secret, GET_PUBKEYS_PATH, None)
            .wrap_err("failed to create JWT for payload")
            .map_err(SignerClientError::JWTError)?;

        let url = self.url.join(GET_PUBKEYS_PATH)?;
        let res = self.client.get(url).bearer_auth(jwt).send().await?;

        if !res.status().is_success() {
            return Err(SignerClientError::FailedRequest {
                status: res.status().as_u16(),
                error_msg: String::from_utf8_lossy(&res.bytes().await?).into_owned(),
            });
        }

        Ok(serde_json::from_slice(&res.bytes().await?)?)
    }

    /// Send a signature request
    async fn request_signature<Q, T>(
        &mut self,
        route: &str,
        request: &Q,
    ) -> Result<T, SignerClientError>
    where
        Q: Serialize,
        T: for<'de> Deserialize<'de>,
    {
        let jwt = self.create_jwt_for_payload(route, request)?;

        let url = self.url.join(route)?;
        let res = self.client.post(url).json(&request).bearer_auth(jwt).send().await?;

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
    ) -> Result<BlsSignResponse, SignerClientError> {
        self.request_signature(REQUEST_SIGNATURE_BLS_PATH, &request).await
    }

    pub async fn request_proxy_signature_ecdsa(
        &mut self,
        request: SignProxyRequest<Address>,
    ) -> Result<EcdsaSignResponse, SignerClientError> {
        self.request_signature(REQUEST_SIGNATURE_PROXY_ECDSA_PATH, &request).await
    }

    pub async fn request_proxy_signature_bls(
        &mut self,
        request: SignProxyRequest<BlsPublicKey>,
    ) -> Result<BlsSignResponse, SignerClientError> {
        self.request_signature(REQUEST_SIGNATURE_PROXY_BLS_PATH, &request).await
    }

    async fn generate_proxy_key<T>(
        &mut self,
        request: &GenerateProxyRequest,
    ) -> Result<SignedProxyDelegation<T>, SignerClientError>
    where
        T: ProxyId + for<'de> Deserialize<'de>,
    {
        let jwt = self.create_jwt_for_payload(GENERATE_PROXY_KEY_PATH, request)?;

        let url = self.url.join(GENERATE_PROXY_KEY_PATH)?;
        let res = self.client.post(url).json(&request).bearer_auth(jwt).send().await?;

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
