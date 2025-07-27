use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use alloy::{
    primitives::{address, Address, U256},
    providers::ProviderBuilder,
    rpc::{client::RpcClient, types::beacon::constants::BLS_PUBLIC_KEY_BYTES_LEN},
    sol,
    transports::http::Http,
};
use eyre::{bail, ensure, Context};
use reqwest::Client;
use serde::{Deserialize, Deserializer, Serialize};
use tracing::{debug, info, warn};
use url::Url;

use super::{load_optional_env_var, PbsConfig, RelayConfig, MUX_PATH_ENV};
use crate::{
    config::{remove_duplicate_keys, safe_read_http_response},
    pbs::{BlsPublicKey, RelayClient},
    types::Chain,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct PbsMuxes {
    /// List of PBS multiplexers
    #[serde(rename = "mux")]
    pub muxes: Vec<MuxConfig>,
}

#[derive(Debug, Clone)]
pub struct RuntimeMuxConfig {
    pub id: String,
    pub config: Arc<PbsConfig>,
    pub relays: Vec<RelayClient>,
}

impl PbsMuxes {
    pub async fn validate_and_fill(
        self,
        chain: Chain,
        default_pbs: &PbsConfig,
    ) -> eyre::Result<HashMap<BlsPublicKey, RuntimeMuxConfig>> {
        let http_timeout = Duration::from_secs(default_pbs.http_timeout_seconds);

        let mut muxes = self.muxes;

        for mux in muxes.iter_mut() {
            ensure!(!mux.relays.is_empty(), "mux config {} must have at least one relay", mux.id);

            if let Some(loader) = &mux.loader {
                let extra_keys =
                    loader.load(&mux.id, chain, default_pbs.rpc_url.clone(), http_timeout).await?;
                mux.validator_pubkeys.extend(extra_keys);
            }

            ensure!(
                !mux.validator_pubkeys.is_empty(),
                "mux config {} must have at least one validator pubkey",
                mux.id
            );
        }

        // check that validator pubkeys are in disjoint sets
        let mut unique_pubkeys = HashSet::new();
        for mux in muxes.iter() {
            for pubkey in mux.validator_pubkeys.iter() {
                if !unique_pubkeys.insert(pubkey) {
                    bail!("duplicate validator pubkey in muxes: {pubkey}");
                }
            }
        }

        let mut configs = HashMap::new();
        // fill the configs using the default pbs config and relay entries
        for mux in muxes {
            info!(
                id = mux.id,
                keys = mux.validator_pubkeys.len(),
                relays = mux.relays.len(),
                "using mux"
            );

            let mut relay_clients = Vec::with_capacity(mux.relays.len());
            for config in mux.relays.into_iter() {
                relay_clients.push(RelayClient::new(config)?);
            }

            let config = PbsConfig {
                timeout_get_header_ms: mux
                    .timeout_get_header_ms
                    .unwrap_or(default_pbs.timeout_get_header_ms),
                late_in_slot_time_ms: mux
                    .late_in_slot_time_ms
                    .unwrap_or(default_pbs.late_in_slot_time_ms),
                ..default_pbs.clone()
            };
            config.validate(chain).await?;
            let config = Arc::new(config);

            let runtime_config = RuntimeMuxConfig { id: mux.id, config, relays: relay_clients };
            for pubkey in mux.validator_pubkeys.into_iter() {
                configs.insert(pubkey, runtime_config.clone());
            }
        }

        Ok(configs)
    }
}

/// Configuration for the PBS Multiplexer
#[derive(Debug, Deserialize, Serialize)]
pub struct MuxConfig {
    /// Identifier for this mux config
    pub id: String,
    /// Relays to use for this mux config
    pub relays: Vec<RelayConfig>,
    /// Which validator pubkeys to match against this mux config
    #[serde(default)]
    pub validator_pubkeys: Vec<BlsPublicKey>,
    /// Loader for extra validator pubkeys
    pub loader: Option<MuxKeysLoader>,
    pub timeout_get_header_ms: Option<u64>,
    pub late_in_slot_time_ms: Option<u64>,
}

impl MuxConfig {
    /// Returns the env, actual path, and internal path to use for the file
    /// loader
    pub fn loader_env(&self) -> Option<(String, String, String)> {
        self.loader.as_ref().and_then(|loader| match loader {
            MuxKeysLoader::File(path_buf) => {
                let path =
                    path_buf.to_str().unwrap_or_else(|| panic!("invalid path: {:?}", path_buf));
                let internal_path = get_mux_path(&self.id);

                Some((get_mux_env(&self.id), path.to_owned(), internal_path))
            }
            MuxKeysLoader::HTTP { .. } => None,
            MuxKeysLoader::Registry { .. } => None,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MuxKeysLoader {
    /// A file containing a list of validator pubkeys
    File(PathBuf),
    HTTP {
        url: String,
    },
    Registry {
        registry: NORegistry,
        node_operator_id: u64,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum NORegistry {
    #[serde(alias = "lido")]
    Lido,
    #[serde(alias = "ssv")]
    SSV,
}

impl MuxKeysLoader {
    pub async fn load(
        &self,
        mux_id: &str,
        chain: Chain,
        rpc_url: Option<Url>,
        http_timeout: Duration,
    ) -> eyre::Result<Vec<BlsPublicKey>> {
        let keys = match self {
            Self::File(config_path) => {
                // First try loading from env
                let path: PathBuf = load_optional_env_var(&get_mux_env(mux_id))
                    .map(PathBuf::from)
                    .unwrap_or(config_path.clone());
                let file = load_file(path)?;
                serde_json::from_str(&file).wrap_err("failed to parse mux keys file")
            }

            Self::HTTP { url } => {
                let url = Url::parse(url).wrap_err("failed to parse mux keys URL")?;
                if url.scheme() != "https" {
                    warn!(
                        "Mux keys URL {url} is insecure; consider using HTTPS if possible instead"
                    );
                }
                let client = reqwest::ClientBuilder::new().timeout(http_timeout).build()?;
                let response = client.get(url).send().await?;
                let pubkey_bytes = safe_read_http_response(response).await?;
                serde_json::from_slice(&pubkey_bytes)
                    .wrap_err("failed to fetch mux keys from HTTP endpoint")
            }

            Self::Registry { registry, node_operator_id } => match registry {
                NORegistry::Lido => {
                    let Some(rpc_url) = rpc_url else {
                        bail!("Lido registry requires RPC URL to be set in the PBS config");
                    };

                    fetch_lido_registry_keys(
                        rpc_url,
                        chain,
                        U256::from(*node_operator_id),
                        http_timeout,
                    )
                    .await
                }
                NORegistry::SSV => {
                    fetch_ssv_pubkeys(chain, U256::from(*node_operator_id), http_timeout).await
                }
            },
        }?;

        // Remove duplicates
        let deduped_keys = remove_duplicate_keys(keys);
        Ok(deduped_keys)
    }
}

fn load_file<P: AsRef<Path> + std::fmt::Debug>(path: P) -> eyre::Result<String> {
    std::fs::read_to_string(&path).wrap_err(format!("Unable to find mux keys file: {path:?}"))
}

/// A different env var for each mux
fn get_mux_env(mux_id: &str) -> String {
    format!("{MUX_PATH_ENV}_{mux_id}")
}

/// Path to the mux file
fn get_mux_path(mux_id: &str) -> String {
    format!("/{mux_id}-mux_keys.json")
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    LidoRegistry,
    "src/abi/LidoNORegistry.json"
}

// Fetching Lido Curated Module
fn lido_registry_address(chain: Chain) -> eyre::Result<Address> {
    match chain {
        Chain::Mainnet => Ok(address!("55032650b14df07b85bF18A3a3eC8E0Af2e028d5")),
        Chain::Holesky => Ok(address!("595F64Ddc3856a3b5Ff4f4CC1d1fb4B46cFd2bAC")),
        Chain::Hoodi => Ok(address!("5cDbE1590c083b5A2A64427fAA63A7cfDB91FbB5")),
        Chain::Sepolia => Ok(address!("33d6E15047E8644F8DDf5CD05d202dfE587DA6E3")),
        _ => bail!("Lido registry not supported for chain: {chain:?}"),
    }
}

async fn fetch_lido_registry_keys(
    rpc_url: Url,
    chain: Chain,
    node_operator_id: U256,
    http_timeout: Duration,
) -> eyre::Result<Vec<BlsPublicKey>> {
    debug!(?chain, %node_operator_id, "loading operator keys from Lido registry");

    // Create an RPC provider with HTTP timeout support
    let client = Client::builder().timeout(http_timeout).build()?;
    let http = Http::with_client(client, rpc_url);
    let is_local = http.guess_local();
    let rpc_client = RpcClient::new(http, is_local);
    let provider = ProviderBuilder::new().on_client(rpc_client);

    let registry_address = lido_registry_address(chain)?;
    let registry = LidoRegistry::new(registry_address, provider);

    let total_keys =
        registry.getTotalSigningKeyCount(node_operator_id).call().await?._0.try_into()?;

    if total_keys == 0 {
        return Ok(Vec::new());
    }

    debug!("fetching {total_keys} total keys");

    const CALL_BATCH_SIZE: u64 = 250u64;

    let mut keys = vec![];
    let mut offset = 0;

    while offset < total_keys {
        let limit = CALL_BATCH_SIZE.min(total_keys - offset);

        let pubkeys = registry
            .getSigningKeys(node_operator_id, U256::from(offset), U256::from(limit))
            .call()
            .await?
            .pubkeys;

        ensure!(
            pubkeys.len() % BLS_PUBLIC_KEY_BYTES_LEN == 0,
            "unexpected number of keys in batch, expected multiple of {BLS_PUBLIC_KEY_BYTES_LEN}, got {}",
            pubkeys.len()
        );

        for chunk in pubkeys.chunks(BLS_PUBLIC_KEY_BYTES_LEN) {
            keys.push(
                BlsPublicKey::deserialize(chunk)
                    .map_err(|_| eyre::eyre!("invalid BLS public key"))?,
            );
        }

        offset += limit;

        if offset % 1000 == 0 {
            debug!("fetched {offset} keys");
        }
    }

    ensure!(keys.len() == total_keys as usize, "expected {total_keys} keys, got {}", keys.len());

    Ok(keys)
}

async fn fetch_ssv_pubkeys(
    chain: Chain,
    node_operator_id: U256,
    http_timeout: Duration,
) -> eyre::Result<Vec<BlsPublicKey>> {
    const MAX_PER_PAGE: usize = 100;

    let chain_name = match chain {
        Chain::Mainnet => "mainnet",
        Chain::Holesky => "holesky",
        Chain::Hoodi => "hoodi",
        _ => bail!("SSV network is not supported for chain: {chain:?}"),
    };

    let mut pubkeys: Vec<BlsPublicKey> = vec![];
    let mut page = 1;

    loop {
        let url = format!(
            "https://api.ssv.network/api/v4/{}/validators/in_operator/{}?perPage={}&page={}",
            chain_name, node_operator_id, MAX_PER_PAGE, page
        );

        let response = fetch_ssv_pubkeys_from_url(&url, http_timeout).await?;
        let fetched = response.validators.len();
        pubkeys.extend(
            response.validators.into_iter().map(|v| v.pubkey).collect::<Vec<BlsPublicKey>>(),
        );
        page += 1;

        if fetched < MAX_PER_PAGE {
            ensure!(
                pubkeys.len() == response.pagination.total,
                "expected {} keys, got {}",
                response.pagination.total,
                pubkeys.len()
            );
            break;
        }
    }

    Ok(pubkeys)
}

async fn fetch_ssv_pubkeys_from_url(
    url: &str,
    http_timeout: Duration,
) -> eyre::Result<SSVResponse> {
    let client = reqwest::ClientBuilder::new().timeout(http_timeout).build()?;
    let response = client.get(url).send().await.map_err(|e| {
        if e.is_timeout() {
            eyre::eyre!("Request to SSV network API timed out: {e}")
        } else {
            eyre::eyre!("Error sending request to SSV network API: {e}")
        }
    })?;

    // Parse the response as JSON
    let body_bytes = safe_read_http_response(response).await?;
    serde_json::from_slice::<SSVResponse>(&body_bytes).wrap_err("failed to parse SSV response")
}

#[derive(Deserialize)]
struct SSVResponse {
    validators: Vec<SSVValidator>,
    pagination: SSVPagination,
}

struct SSVValidator {
    pubkey: BlsPublicKey,
}

impl<'de> Deserialize<'de> for SSVValidator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SSVValidator {
            public_key: String,
        }

        let s = SSVValidator::deserialize(deserializer)?;
        let bytes = alloy::hex::decode(&s.public_key).map_err(serde::de::Error::custom)?;
        let pubkey = BlsPublicKey::deserialize(&bytes)
            .map_err(|e| serde::de::Error::custom(format!("invalid BLS public key: {e:?}")))?;

        Ok(Self { pubkey })
    }
}

#[derive(Deserialize)]
struct SSVPagination {
    total: usize,
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use alloy::{primitives::U256, providers::ProviderBuilder};
    use axum::{response::Response, routing::get};
    use tokio::{net::TcpListener, task::JoinHandle};
    use url::Url;

    use super::*;
    use crate::{
        config::{HTTP_TIMEOUT_SECONDS_DEFAULT, MUXER_HTTP_MAX_LENGTH},
        utils::{set_ignore_content_length, ResponseReadError},
    };

    const TEST_HTTP_TIMEOUT: u64 = 2;

    #[tokio::test]
    async fn test_lido_registry_address() -> eyre::Result<()> {
        let url = Url::parse("https://ethereum-rpc.publicnode.com")?;
        let provider = ProviderBuilder::new().on_http(url);

        let registry =
            LidoRegistry::new(address!("55032650b14df07b85bF18A3a3eC8E0Af2e028d5"), provider);

        const LIMIT: usize = 3;
        let node_operator_id = U256::from(1);

        let total_keys: u64 =
            registry.getTotalSigningKeyCount(node_operator_id).call().await?._0.try_into()?;

        assert!(total_keys > LIMIT as u64);

        let pubkeys = registry
            .getSigningKeys(node_operator_id, U256::ZERO, U256::from(LIMIT))
            .call()
            .await?
            .pubkeys;

        let mut vec = vec![];
        for chunk in pubkeys.chunks(48) {
            vec.push(
                BlsPublicKey::deserialize(chunk)
                    .map_err(|_| eyre::eyre!("invalid BLS public key"))?,
            );
        }

        assert_eq!(vec.len(), LIMIT);

        Ok(())
    }

    #[tokio::test]
    /// Tests that a successful SSV network fetch is handled and parsed properly
    async fn test_ssv_network_fetch() -> eyre::Result<()> {
        // Start the mock server
        let port = 30100;
        let _server_handle = create_mock_server(port).await?;
        let url = format!("http://localhost:{port}/ssv");
        let response =
            fetch_ssv_pubkeys_from_url(&url, Duration::from_secs(HTTP_TIMEOUT_SECONDS_DEFAULT))
                .await?;

        // Make sure the response is correct
        // NOTE: requires that ssv_data.json dpesn't change
        assert_eq!(response.validators.len(), 3);
        let expected_pubkeys = [
            BlsPublicKey::deserialize(
                &alloy::hex!("967ba17a3e7f82a25aa5350ec34d6923e28ad8237b5a41efe2c5e325240d74d87a015bf04634f21900963539c8229b2a")
            ).unwrap(),
            BlsPublicKey::deserialize(
                &alloy::hex!("ac769e8cec802e8ffee34de3253be8f438a0c17ee84bdff0b6730280d24b5ecb77ebc9c985281b41ee3bda8663b6658c"),
            ).unwrap(),
            BlsPublicKey::deserialize(
                &alloy::hex!("8c866a5a05f3d45c49b457e29365259021a509c5daa82e124f9701a960ee87b8902e87175315ab638a3d8b1115b23639"),
            ).unwrap(),
        ];
        for (i, validator) in response.validators.iter().enumerate() {
            assert_eq!(validator.pubkey, expected_pubkeys[i]);
        }

        // Clean up the server handle
        _server_handle.abort();

        Ok(())
    }

    #[tokio::test]
    /// Tests that the SSV network fetch is handled properly when the response's
    /// body is too large
    async fn test_ssv_network_fetch_big_data() -> eyre::Result<()> {
        // Start the mock server
        let port = 30101;
        let _server_handle = create_mock_server(port).await?;
        let url = format!("http://localhost:{port}/big_data");
        let response = fetch_ssv_pubkeys_from_url(&url, Duration::from_secs(120)).await;

        // The response should fail due to content length being too big
        match response {
            Ok(_) => {
                panic!("Expected an error due to big content length, but got a successful response")
            }
            Err(e) => match e.downcast_ref::<ResponseReadError>() {
                Some(ResponseReadError::PayloadTooLarge { max, content_length, raw }) => {
                    assert_eq!(*max, MUXER_HTTP_MAX_LENGTH);
                    assert!(*content_length > MUXER_HTTP_MAX_LENGTH);
                    assert!(raw.is_empty());
                }
                _ => panic!("Expected PayloadTooLarge error, got: {}", e),
            },
        }

        // Clean up the server handle
        _server_handle.abort();

        Ok(())
    }

    #[tokio::test]
    /// Tests that the SSV network fetch is handled properly when the request
    /// times out
    async fn test_ssv_network_fetch_timeout() -> eyre::Result<()> {
        // Start the mock server
        let port = 30102;
        let _server_handle = create_mock_server(port).await?;
        let url = format!("http://localhost:{port}/timeout");
        let response =
            fetch_ssv_pubkeys_from_url(&url, Duration::from_secs(TEST_HTTP_TIMEOUT)).await;

        // The response should fail due to timeout
        assert!(response.is_err(), "Expected timeout error, but got success");
        if let Err(e) = response {
            assert!(e.to_string().contains("timed out"), "Expected timeout error, got: {}", e);
        }

        // Clean up the server handle
        _server_handle.abort();

        Ok(())
    }

    #[tokio::test]
    /// Tests that the SSV network fetch is handled properly when the response's
    /// content-length header is missing
    async fn test_ssv_network_fetch_big_data_without_content_length() -> eyre::Result<()> {
        // Start the mock server
        let port = 30103;
        set_ignore_content_length(true);
        let _server_handle = create_mock_server(port).await?;
        let url = format!("http://localhost:{port}/big_data");
        let response = fetch_ssv_pubkeys_from_url(&url, Duration::from_secs(120)).await;

        // The response should fail due to the body being too big
        match response {
            Ok(_) => {
                panic!("Expected an error due to excessive data, but got a successful response")
            }
            Err(e) => match e.downcast_ref::<ResponseReadError>() {
                Some(ResponseReadError::PayloadTooLarge { max, content_length, raw }) => {
                    assert_eq!(*max, MUXER_HTTP_MAX_LENGTH);
                    assert_eq!(*content_length, 0);
                    assert!(!raw.is_empty());
                }
                _ => panic!("Expected PayloadTooLarge error, got: {}", e),
            },
        }

        // Clean up the server handle
        _server_handle.abort();

        Ok(())
    }

    /// Creates a simple mock server to simulate the SSV API endpoint under
    /// various conditions for testing
    async fn create_mock_server(port: u16) -> Result<JoinHandle<()>, axum::Error> {
        let router = axum::Router::new()
            .route("/ssv", get(handle_ssv))
            .route("/big_data", get(handle_big_data))
            .route("/timeout", get(handle_timeout))
            .into_make_service();

        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = TcpListener::bind(address).await.map_err(axum::Error::new)?;
        let server = axum::serve(listener, router).with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.expect("Failed to listen for shutdown signal");
        });
        let result = Ok(tokio::spawn(async move {
            if let Err(e) = server.await {
                eprintln!("Server error: {}", e);
            }
        }));
        info!("Mock server started on http://localhost:{port}/");
        result
    }

    /// Sends the good SSV JSON data to the client
    async fn handle_ssv() -> Response {
        // Read the JSON data
        let data = include_str!("../../../../tests/data/ssv_valid.json");

        // Create a valid response
        Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            .body(data.into())
            .unwrap()
    }

    /// Sends a response with a large body - larger than the maximum allowed.
    /// Note that hyper overwrites the content-length header automatically, so
    /// setting it here wouldn't actually change the value that ultimately
    /// gets sent to the server.
    async fn handle_big_data() -> Response {
        let body = "f".repeat(2 * MUXER_HTTP_MAX_LENGTH);
        Response::builder()
            .status(200)
            .header("Content-Type", "application/text")
            .body(body.into())
            .unwrap()
    }

    /// Simulates a timeout by sleeping for a long time
    async fn handle_timeout() -> Response {
        // Sleep for a long time to simulate a timeout
        tokio::time::sleep(std::time::Duration::from_secs(2 * TEST_HTTP_TIMEOUT)).await;
        Response::builder()
            .status(200)
            .header("Content-Type", "application/text")
            .body("Timeout response".into())
            .unwrap()
    }
}
