use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use alloy::{
    primitives::{Address, U256, address},
    providers::ProviderBuilder,
    rpc::{client::RpcClient, types::beacon::constants::BLS_PUBLIC_KEY_BYTES_LEN},
    sol,
    transports::http::Http,
};
use eyre::{Context, bail, ensure};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use url::Url;

use super::{MUX_PATH_ENV, PbsConfig, RelayConfig, load_optional_env_var};
use crate::{
    config::{remove_duplicate_keys, safe_read_http_response},
    interop::ssv::utils::fetch_ssv_pubkeys_from_url,
    pbs::RelayClient,
    types::{BlsPublicKey, Chain},
    utils::default_bool,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    ) -> eyre::Result<(
        HashMap<BlsPublicKey, RuntimeMuxConfig>,
        HashMap<MuxKeysLoader, RuntimeMuxConfig>,
    )> {
        let http_timeout = Duration::from_secs(default_pbs.http_timeout_seconds);

        let mut muxes = self.muxes;

        for mux in muxes.iter_mut() {
            ensure!(!mux.relays.is_empty(), "mux config {} must have at least one relay", mux.id);

            if let Some(loader) = &mux.loader {
                let extra_keys = loader
                    .load(
                        &mux.id,
                        chain,
                        default_pbs.ssv_api_url.clone(),
                        default_pbs.rpc_url.clone(),
                        http_timeout,
                    )
                    .await?;
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
        let mut registry_muxes = HashMap::new();
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

            // Build the map of pubkeys to mux configs
            let runtime_config = RuntimeMuxConfig { id: mux.id, config, relays: relay_clients };
            for pubkey in mux.validator_pubkeys.into_iter() {
                configs.insert(pubkey, runtime_config.clone());
            }

            // Track registry muxes with refreshing enabled
            if let Some(loader) = &mux.loader &&
                let MuxKeysLoader::Registry { enable_refreshing: true, .. } = loader
            {
                info!(
                    "mux {} uses registry loader with dynamic refreshing enabled",
                    runtime_config.id
                );
                registry_muxes.insert(loader.clone(), runtime_config.clone());
            }
        }

        Ok((configs, registry_muxes))
    }
}

/// Configuration for the PBS Multiplexer
#[derive(Debug, Clone, Deserialize, Serialize)]
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
    /// loader. In File mode, validates the mux file prior to returning.   
    pub fn loader_env(&self) -> eyre::Result<Option<(String, String, String)>> {
        let Some(loader) = self.loader.as_ref() else {
            return Ok(None);
        };

        match loader {
            MuxKeysLoader::File(path_buf) => {
                let Some(path) = path_buf.to_str() else {
                    bail!("invalid path: {:?}", path_buf);
                };

                let file = load_file(path)?;
                // make sure we can load the pubkeys correctly
                let _: Vec<BlsPublicKey> =
                    serde_json::from_str(&file).wrap_err("failed to parse mux keys file")?;

                let internal_path = get_mux_path(&self.id);
                Ok(Some((get_mux_env(&self.id), path.to_owned(), internal_path)))
            }
            MuxKeysLoader::HTTP { .. } => Ok(None),
            MuxKeysLoader::Registry { .. } => Ok(None),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
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
        #[serde(default = "default_bool::<false>")]
        enable_refreshing: bool,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
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
        ssv_api_url: Url,
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

            Self::Registry { registry, node_operator_id, enable_refreshing: _ } => match registry {
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
                    fetch_ssv_pubkeys(
                        ssv_api_url,
                        chain,
                        U256::from(*node_operator_id),
                        http_timeout,
                    )
                    .await
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
    let provider = ProviderBuilder::new().connect_client(rpc_client);

    let registry_address = lido_registry_address(chain)?;
    let registry = LidoRegistry::new(registry_address, provider);

    let total_keys = registry.getTotalSigningKeyCount(node_operator_id).call().await?.try_into()?;

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
    mut api_url: Url,
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

    // Validate the URL - this appends a trailing slash if missing as efficiently as
    // possible
    if !api_url.path().ends_with('/') {
        match api_url.path_segments_mut() {
            Ok(mut segments) => segments.push(""), // Analogous to a trailing slash
            Err(_) => bail!("SSV API URL is not a valid base URL"),
        };
    }

    loop {
        let route = format!(
            "{chain_name}/validators/in_operator/{node_operator_id}?perPage={MAX_PER_PAGE}&page={page}",
        );
        let url = api_url.join(&route).wrap_err("failed to construct SSV API URL")?;

        let response = fetch_ssv_pubkeys_from_url(url, http_timeout).await?;
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

#[cfg(test)]
mod tests {
    use alloy::{primitives::U256, providers::ProviderBuilder};
    use url::Url;

    use super::*;

    #[tokio::test]
    async fn test_lido_registry_address() -> eyre::Result<()> {
        let url = Url::parse("https://ethereum-rpc.publicnode.com")?;
        let provider = ProviderBuilder::new().connect_http(url);

        let registry =
            LidoRegistry::new(address!("55032650b14df07b85bF18A3a3eC8E0Af2e028d5"), provider);

        const LIMIT: usize = 3;
        let node_operator_id = U256::from(1);

        let total_keys: u64 =
            registry.getTotalSigningKeyCount(node_operator_id).call().await?.try_into()?;

        assert!(total_keys > LIMIT as u64);

        let pubkeys = registry
            .getSigningKeys(node_operator_id, U256::ZERO, U256::from(LIMIT))
            .call()
            .await?
            .pubkeys;

        let mut vec = vec![];
        for chunk in pubkeys.chunks(BLS_PUBLIC_KEY_BYTES_LEN) {
            vec.push(
                BlsPublicKey::deserialize(chunk)
                    .map_err(|_| eyre::eyre!("invalid BLS public key"))?,
            );
        }

        assert_eq!(vec.len(), LIMIT);

        Ok(())
    }
}
