use std::{str::FromStr, sync::Arc};

use alloy::{
    primitives::{hex::FromHex, B256},
    rpc::types::beacon::BlsPublicKey,
};
use eyre::WrapErr;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use url::Url;

use super::{
    constants::{BUILDER_API_PATH, GET_STATUS_PATH, REGISTER_VALIDATOR_PATH, SUBMIT_BLOCK_PATH},
    error::PbsError,
    HEADER_VERSION_KEY, HEADER_VERSION_VALUE,
};
use crate::{config::RelayConfig, DEFAULT_REQUEST_TIMEOUT};

/// A parsed entry of the relay url in the format: scheme://pubkey@host
#[derive(Debug, Clone)]
pub struct RelayEntry {
    /// Default if of the relay, the hostname of the url
    pub id: String,
    /// Public key of the relay
    pub pubkey: BlsPublicKey,
    /// Full url of the relay
    pub url: Url,
}

impl Serialize for RelayEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.url.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RelayEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let url = Url::deserialize(deserializer)?;
        let pubkey = BlsPublicKey::from_hex(url.username()).map_err(serde::de::Error::custom)?;
        let id = url.host().ok_or(serde::de::Error::custom("missing host"))?.to_string();

        Ok(RelayEntry { pubkey, url, id })
    }
}

/// A client to interact with a relay, safe to share across threads
#[derive(Debug, Clone)]
pub struct RelayClient {
    /// ID of the relay
    pub id: Arc<String>,
    /// HTTP client to send requests
    pub client: reqwest::Client,
    /// Configuration of the relay
    pub config: Arc<RelayConfig>,
}

impl RelayClient {
    pub fn new(config: RelayConfig) -> eyre::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_VERSION_KEY, HeaderValue::from_static(HEADER_VERSION_VALUE));

        if let Some(custom_headers) = &config.headers {
            for (key, value) in custom_headers {
                headers.insert(
                    HeaderName::from_str(key).wrap_err("{key} is an invalid header name")?,
                    HeaderValue::from_str(value).wrap_err("{key} has an invalid header value")?,
                );
            }
        }

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .build()?;

        Ok(Self {
            id: Arc::new(config.id.clone().unwrap_or(config.entry.id.clone())),
            client,
            config: Arc::new(config),
        })
    }

    pub fn pubkey(&self) -> BlsPublicKey {
        self.config.entry.pubkey
    }

    // URL builders
    pub fn get_url(&self, path: &str) -> Result<Url, PbsError> {
        self.config.entry.url.join(path).map_err(PbsError::UrlParsing)
    }
    pub fn builder_api_url(&self, path: &str) -> Result<Url, PbsError> {
        self.get_url(&format!("{BUILDER_API_PATH}{path}"))
    }

    pub fn get_header_url(
        &self,
        slot: u64,
        parent_hash: B256,
        validator_pubkey: BlsPublicKey,
    ) -> Result<Url, PbsError> {
        self.builder_api_url(&format!("/header/{slot}/{parent_hash}/{validator_pubkey}"))
    }

    pub fn get_status_url(&self) -> Result<Url, PbsError> {
        self.builder_api_url(GET_STATUS_PATH)
    }

    pub fn register_validator_url(&self) -> Result<Url, PbsError> {
        self.builder_api_url(REGISTER_VALIDATOR_PATH)
    }

    pub fn submit_block_url(&self) -> Result<Url, PbsError> {
        self.builder_api_url(SUBMIT_BLOCK_PATH)
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::{hex::FromHex, B256},
        rpc::types::beacon::BlsPublicKey,
    };

    use super::{RelayClient, RelayEntry};
    use crate::config::RelayConfig;

    #[test]
    fn test_relay_entry() {
        let s = "http://0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae@abc.xyz/";

        let parsed = serde_json::from_str::<RelayEntry>(&format!("\"{s}\"")).unwrap();

        assert_eq!(parsed.pubkey, BlsPublicKey::from_hex("0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae").unwrap());
        assert_eq!(parsed.url.as_str(), s);
        assert_eq!(parsed.id, "abc.xyz");
    }

    #[test]
    fn test_relay_url() {
        let slot = 0;
        let parent_hash = B256::ZERO;
        let validator_pubkey = BlsPublicKey::ZERO;
        let expected = format!("http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz/eth/v1/builder/header/{slot}/{parent_hash}/{validator_pubkey}");

        let relay_config = r#"
        {
            "url": "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz"
        }"#;

        let config = serde_json::from_str::<RelayConfig>(relay_config).unwrap();
        let relay = RelayClient::new(config).unwrap();

        assert_eq!(
            relay.get_header_url(slot, parent_hash, validator_pubkey).unwrap().to_string(),
            expected
        );

        let relay_config = r#"
        {
            "url": "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz//"
        }"#;

        let config = serde_json::from_str::<RelayConfig>(relay_config).unwrap();
        let relay = RelayClient::new(config).unwrap();

        assert_eq!(
            relay.get_header_url(slot, parent_hash, validator_pubkey).unwrap().to_string(),
            expected
        );
    }
}
