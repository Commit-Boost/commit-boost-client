use std::{str::FromStr, sync::Arc};

use alloy::primitives::B256;
use eyre::WrapErr;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use url::Url;

use super::{
    HEADER_VERSION_KEY, HEADER_VERSION_VALUE,
    constants::{
        GET_HEADER_STREAM_PATH, GET_STATUS_PATH, REGISTER_VALIDATOR_PATH, SUBMIT_BLOCK_PATH,
        SUBMIT_SIGNED_BEACON_BLOCK_PATH,
    },
    error::PbsError,
};
use crate::{
    DEFAULT_REQUEST_TIMEOUT,
    config::{GetHeaderTransport, RelayConfig},
    pbs::BuilderApiVersion,
    types::BlsPublicKey,
};

/// A parsed entry of the relay url in the format: scheme://pubkey@host
#[derive(Debug, Clone)]
pub struct RelayEntry {
    /// Default ID of the relay, the hostname of the url
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
        let id = url.host().ok_or(serde::de::Error::custom("missing host"))?.to_string();
        let pubkey = BlsPublicKey::from_str(url.username())
            .map_err(|_| serde::de::Error::custom("invalid BLS pubkey"))?;

        Ok(RelayEntry { pubkey, url, id })
    }
}

#[derive(Debug, Clone)]
pub enum GetHeaderRequest {
    Http(Url),
    Stream(Url),
}

fn stream_url(entry: &Url) -> eyre::Result<Url> {
    let scheme = match entry.scheme() {
        "http" | "ws" => "ws",
        "https" | "wss" => "wss",
        other => eyre::bail!("get_header stream needs an http(s) relay url, got {other}"),
    };

    let mut url = entry.clone();
    url.set_scheme(scheme).map_err(|_| eyre::eyre!("cannot use {scheme} for {entry}"))?;
    url.set_username("").map_err(|_| eyre::eyre!("cannot strip credentials from {entry}"))?;
    url.set_password(None).map_err(|_| eyre::eyre!("cannot strip credentials from {entry}"))?;
    url.set_path(&format!("{}{GET_HEADER_STREAM_PATH}", BuilderApiVersion::V1.path()));

    Ok(url)
}

/// A client to interact with a relay, safe to share across threads and cheaply
/// cloneable
#[derive(Debug, Clone)]
pub struct RelayClient {
    /// ID of the relay
    pub id: Arc<String>,
    /// HTTP client to send requests
    pub client: reqwest::Client,
    /// Base url of the get_header stream, `Some` only when the relay streams.
    stream_url: Option<Url>,
    /// Baseline headers for the get_header stream handshake.
    stream_headers: Arc<HeaderMap>,
    /// Configuration of the relay
    pub config: Arc<RelayConfig>,
}

impl RelayClient {
    pub fn new(config: RelayConfig) -> eyre::Result<Self> {
        let stream_url = match config.get_header {
            GetHeaderTransport::Http => None,
            GetHeaderTransport::Stream => Some(stream_url(&config.entry.url)?),
        };

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
            .default_headers(headers.clone())
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .build()?;

        Ok(Self {
            id: Arc::new(config.id().to_owned()),
            client,
            stream_url,
            stream_headers: Arc::new(headers),
            config: Arc::new(config),
        })
    }

    pub fn pubkey(&self) -> &BlsPublicKey {
        &self.config.entry.pubkey
    }

    pub fn stream_headers(&self) -> &HeaderMap {
        &self.stream_headers
    }

    // URL builders
    pub fn get_url(&self, path: &str) -> Result<Url, PbsError> {
        let mut url = self.config.entry.url.join(path).map_err(PbsError::UrlParsing)?;
        self.append_get_params(&mut url);
        Ok(url)
    }

    fn append_get_params(&self, url: &mut Url) {
        if let Some(get_params) = &self.config.get_params {
            let mut query_pairs = url.query_pairs_mut();
            for (key, value) in get_params {
                query_pairs.append_pair(key, value);
            }
        }
    }

    pub fn builder_api_url(
        &self,
        path: &str,
        api_version: BuilderApiVersion,
    ) -> Result<Url, PbsError> {
        self.get_url(&format!("{}{path}", api_version.path()))
    }

    pub fn get_header_url(
        &self,
        slot: u64,
        parent_hash: &B256,
        validator_pubkey: &BlsPublicKey,
    ) -> Result<Url, PbsError> {
        self.builder_api_url(
            &format!("/header/{slot}/{parent_hash}/{validator_pubkey}"),
            BuilderApiVersion::V1,
        )
    }

    pub fn get_header_request(
        &self,
        slot: u64,
        parent_hash: &B256,
        validator_pubkey: &BlsPublicKey,
    ) -> Result<GetHeaderRequest, PbsError> {
        Ok(match &self.stream_url {
            None => {
                GetHeaderRequest::Http(self.get_header_url(slot, parent_hash, validator_pubkey)?)
            }
            Some(base) => {
                let mut url = base.clone();
                url.set_path(&format!("{}/{slot}/{parent_hash}/{validator_pubkey}", base.path()));

                self.append_get_params(&mut url);
                GetHeaderRequest::Stream(url)
            }
        })
    }

    pub fn get_status_url(&self) -> Result<Url, PbsError> {
        self.builder_api_url(GET_STATUS_PATH, BuilderApiVersion::V1)
    }

    pub fn register_validator_url(&self) -> Result<Url, PbsError> {
        self.builder_api_url(REGISTER_VALIDATOR_PATH, BuilderApiVersion::V1)
    }

    pub fn submit_block_url(&self, api_version: BuilderApiVersion) -> Result<Url, PbsError> {
        self.builder_api_url(SUBMIT_BLOCK_PATH, api_version)
    }

    /// builder-API: POST /eth/v1/builder/execution_payload_bid/{slot}/
    /// {parent_hash}/{parent_root}/{proposer_pubkey}
    pub fn get_execution_payload_bid_url(
        &self,
        slot: u64,
        parent_hash: &B256,
        parent_root: &B256,
        validator_pubkey: &BlsPublicKey,
    ) -> Result<Url, PbsError> {
        self.builder_api_url(
            &format!(
                "/execution_payload_bid/{slot}/{parent_hash}/{parent_root}/{validator_pubkey}"
            ),
            BuilderApiVersion::V1,
        )
    }

    /// builder-API: POST /eth/v1/builder/builder_preferences/{proposer_pubkey}
    pub fn submit_builder_preferences_url(
        &self,
        validator_pubkey: &BlsPublicKey,
    ) -> Result<Url, PbsError> {
        self.builder_api_url(
            &format!("/builder_preferences/{validator_pubkey}"),
            BuilderApiVersion::V1,
        )
    }

    /// builder-API: POST /eth/v1/builder/beacon_blocks
    pub fn submit_signed_beacon_block_url(&self) -> Result<Url, PbsError> {
        self.builder_api_url(SUBMIT_SIGNED_BEACON_BLOCK_PATH, BuilderApiVersion::V1)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy::primitives::B256;

    use super::{GetHeaderRequest, RelayClient, RelayEntry};
    use crate::{
        config::{GetHeaderTransport, RelayConfig},
        utils::bls_pubkey_from_hex_unchecked,
    };

    #[test]
    fn test_relay_entry() {
        let pubkey = bls_pubkey_from_hex_unchecked(
            "0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae",
        );
        let s = format!("http://{pubkey}@abc.xyz/");

        let parsed = serde_json::from_str::<RelayEntry>(&format!("\"{s}\"")).unwrap();

        assert_eq!(parsed.pubkey, pubkey);
        assert_eq!(parsed.url.as_str(), s);
        assert_eq!(parsed.id, "abc.xyz");
    }

    #[test]
    fn test_relay_url() {
        let slot = 0;
        let parent_hash = B256::ZERO;
        let validator_pubkey = bls_pubkey_from_hex_unchecked(
            "0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae",
        );
        let expected = format!(
            "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz/eth/v1/builder/header/{slot}/{parent_hash}/{validator_pubkey}"
        );

        let relay_config = r#"
        {
            "url": "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz"
        }"#;

        let config = serde_json::from_str::<RelayConfig>(relay_config).unwrap();
        let relay = RelayClient::new(config).unwrap();

        assert_eq!(
            relay.get_header_url(slot, &parent_hash, &validator_pubkey).unwrap().to_string(),
            expected
        );

        let relay_config = r#"
        {
            "url": "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz//"
        }"#;

        let config = serde_json::from_str::<RelayConfig>(relay_config).unwrap();
        let relay = RelayClient::new(config).unwrap();

        assert_eq!(
            relay.get_header_url(slot, &parent_hash, &validator_pubkey).unwrap().to_string(),
            expected
        );
    }

    #[test]
    fn test_relay_url_with_get_params() {
        let slot = 0;
        let parent_hash = B256::ZERO;
        let validator_pubkey = bls_pubkey_from_hex_unchecked(
            "0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae",
        );
        // Note: HashMap iteration order is not guaranteed, so we can't predict the
        // exact order of parameters Instead of hard-coding the order, we'll
        // check that both parameters are present in the URL
        let url_prefix = format!(
            "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz/eth/v1/builder/header/{slot}/{parent_hash}/{validator_pubkey}?"
        );

        let mut get_params = HashMap::new();
        get_params.insert("param1".to_string(), "value1".to_string());
        get_params.insert("param2".to_string(), "value2".to_string());

        let relay_config = r#"
        {
            "url": "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz"
        }"#;

        let mut config = serde_json::from_str::<RelayConfig>(relay_config).unwrap();
        config.get_params = Some(get_params);
        let relay = RelayClient::new(config).unwrap();

        let url = relay.get_header_url(slot, &parent_hash, &validator_pubkey).unwrap().to_string();
        assert!(url.starts_with(&url_prefix));
        assert!(url.contains("param1=value1"));
        assert!(url.contains("param2=value2"));
    }

    #[test]
    fn test_get_header_request() {
        let slot = 0;
        let parent_hash = B256::ZERO;
        let validator_pubkey = bls_pubkey_from_hex_unchecked(
            "0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae",
        );
        let relay_config = r#"
        {
            "url": "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz"
        }"#;
        let base_config = serde_json::from_str::<RelayConfig>(relay_config).unwrap();

        // Default transport: plain HTTP endpoint
        let relay = RelayClient::new(base_config.clone()).unwrap();
        let GetHeaderRequest::Http(url) =
            relay.get_header_request(slot, &parent_hash, &validator_pubkey).unwrap()
        else {
            panic!("expected http request");
        };
        assert_eq!(
            url,
            relay.get_header_url(slot, &parent_hash, &validator_pubkey).unwrap(),
            "http dispatch must match the plain url builder"
        );

        // Streaming: the relay url over ws, at the fixed stream path, with the
        // pubkey credentials dropped
        let mut config = base_config.clone();
        config.get_header = GetHeaderTransport::Stream;
        let relay = RelayClient::new(config).unwrap();
        let GetHeaderRequest::Stream(url) =
            relay.get_header_request(slot, &parent_hash, &validator_pubkey).unwrap()
        else {
            panic!("expected stream request");
        };
        assert_eq!(
            url.to_string(),
            format!(
                "ws://abc.xyz/eth/v1/builder/header_stream/{slot}/{parent_hash}/{validator_pubkey}"
            )
        );

        // https relays stream over wss, and a port and get_params carry over
        let mut config = base_config.clone();
        config.entry.url =
            format!("https://{}@abc.xyz:4444/relay-api", config.entry.pubkey).parse().unwrap();
        config.get_header = GetHeaderTransport::Stream;
        config.get_params = Some(HashMap::from([("token".to_string(), "abc".to_string())]));
        let relay = RelayClient::new(config).unwrap();
        let GetHeaderRequest::Stream(url) =
            relay.get_header_request(slot, &parent_hash, &validator_pubkey).unwrap()
        else {
            panic!("expected stream request");
        };
        assert_eq!(
            url.to_string(),
            format!(
                "wss://abc.xyz:4444/eth/v1/builder/header_stream/{slot}/{parent_hash}/{validator_pubkey}?token=abc"
            )
        );

        // A relay url we can't stream over is rejected at construction
        let mut config = base_config;
        config.entry.url = "unix:/tmp/relay.sock".parse().unwrap();
        config.get_header = GetHeaderTransport::Stream;
        assert!(RelayClient::new(config).is_err());
    }

    #[test]
    fn test_get_header_transport_config() {
        let with_transport = |value: &str| {
            let relay_config = format!(
                r#"
                {{
                    "url": "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz",
                    "get_header": {value}
                }}"#
            );
            serde_json::from_str::<RelayConfig>(&relay_config).map(|config| config.get_header)
        };

        assert_eq!(with_transport(r#""http""#).unwrap(), GetHeaderTransport::Http);
        assert_eq!(with_transport(r#""stream""#).unwrap(), GetHeaderTransport::Stream);
        assert!(with_transport(r#""grpc""#).is_err());

        // Same shapes in the toml the operator actually writes
        let toml_config = r#"
            url = "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz"
            get_header = "stream"
        "#;
        let config = toml::from_str::<RelayConfig>(toml_config).unwrap();
        assert_eq!(config.get_header, GetHeaderTransport::Stream);

        // Defaults to http when omitted
        let relay_config = r#"
        {
            "url": "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz"
        }"#;
        let config = serde_json::from_str::<RelayConfig>(relay_config).unwrap();
        assert_eq!(config.get_header, GetHeaderTransport::Http);
    }

    #[test]
    fn test_relay_url_get_execution_payload() {
        let slot = 0;
        let parent_hash = B256::ZERO;
        let parent_root = B256::ZERO;
        let validator_pubkey = bls_pubkey_from_hex_unchecked(
            "0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae",
        );
        let expected = format!(
            "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash}/{parent_root}/{validator_pubkey}"
        );

        let relay_config = r#"
        {
            "url": "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz"
        }"#;

        let config = serde_json::from_str::<RelayConfig>(relay_config).unwrap();
        let relay = RelayClient::new(config).unwrap();

        assert_eq!(
            relay
                .get_execution_payload_bid_url(slot, &parent_hash, &parent_root, &validator_pubkey)
                .unwrap()
                .to_string(),
            expected
        );

        let relay_config = r#"
        {
            "url": "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz//"
        }"#;

        let config = serde_json::from_str::<RelayConfig>(relay_config).unwrap();
        let relay = RelayClient::new(config).unwrap();

        assert_eq!(
            relay
                .get_execution_payload_bid_url(slot, &parent_hash, &parent_root, &validator_pubkey)
                .unwrap()
                .to_string(),
            expected
        );
    }

    #[test]
    fn test_relay_url_with_get_params_get_execution_payload() {
        let slot = 0;
        let parent_hash = B256::ZERO;
        let parent_root = B256::ZERO;
        let validator_pubkey = bls_pubkey_from_hex_unchecked(
            "0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae",
        );
        // Note: HashMap iteration order is not guaranteed, so we can't predict the
        // exact order of parameters Instead of hard-coding the order, we'll
        // check that both parameters are present in the URL
        let url_prefix = format!(
            "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash}/{parent_root}/{validator_pubkey}?"
        );

        let mut get_params = HashMap::new();
        get_params.insert("param1".to_string(), "value1".to_string());
        get_params.insert("param2".to_string(), "value2".to_string());

        let relay_config = r#"
        {
            "url": "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz"
        }"#;

        let mut config = serde_json::from_str::<RelayConfig>(relay_config).unwrap();
        config.get_params = Some(get_params);
        let relay = RelayClient::new(config).unwrap();

        let url = relay
            .get_execution_payload_bid_url(slot, &parent_hash, &parent_root, &validator_pubkey)
            .unwrap()
            .to_string();
        assert!(url.starts_with(&url_prefix));
        assert!(url.contains("param1=value1"));
        assert!(url.contains("param2=value2"));
    }
}
