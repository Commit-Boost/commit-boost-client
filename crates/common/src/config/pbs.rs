//! Configuration for the PBS module

use std::{
    collections::HashMap,
    fmt,
    fs::File,
    io::Read,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use alloy::{
    primitives::{U256, utils::format_ether},
    providers::{Provider, ProviderBuilder},
};
use docker_image::DockerImage;
use eyre::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use url::Url;

use super::{
    CommitBoostConfig, HTTP_TIMEOUT_SECONDS_DEFAULT, PBS_ENDPOINT_ENV, RELAY_HEADER_FILE_MAX_BYTES,
    RuntimeMuxConfig, load_optional_env_var,
};
use crate::{
    commit::client::SignerClient,
    config::{
        COMMIT_BOOST_IMAGE_DEFAULT, CONFIG_ENV, MODULE_JWT_ENV, MuxKeysLoader, PBS_SERVICE_NAME,
        PbsMuxes, SIGNER_TLS_CERTIFICATE_NAME, SIGNER_TLS_CERTIFICATES_PATH_ENV, SIGNER_URL_ENV,
        SignerConfig, TlsMode, load_env_var, load_file_from_env,
    },
    pbs::{
        DEFAULT_PBS_PORT, DEFAULT_REGISTRY_REFRESH_SECONDS, DefaultTimeout, LATE_IN_SLOT_TIME_MS,
        REGISTER_VALIDATOR_RETRY_LIMIT, RelayClient, RelayEntry,
    },
    types::{BlsPublicKey, Chain, Jwt, ModuleId},
    utils::{
        WEI_PER_ETH, as_eth_str, default_bool, default_host, default_u16, default_u32, default_u64,
        default_u256,
    },
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GetHeaderTransport {
    #[default]
    Http,
    Stream,
}

/// A custom relay header value: a literal, or a secret read from a file or an
/// environment variable when the relay client is built (at startup and on every
/// reload), so an API key never has to sit in plaintext in the config file.
///
/// ```toml
/// headers = { X-Api-Key = "literal" }
/// headers = { X-Api-Key = { file = "/run/secrets/relay-key" } }
/// headers = { X-Api-Key = { env = "RELAY_KEY" } }
/// ```
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum HeaderSource {
    Literal(String),
    File { file: PathBuf },
    Env { env: String },
}

impl HeaderSource {
    /// The header value to send. A file or env value has its trailing
    /// whitespace dropped (secret stores write a newline) and must be
    /// non-empty; a literal is sent as written.
    pub fn resolve(&self) -> Result<String> {
        let value = match self {
            Self::Literal(value) => return Ok(value.clone()),
            Self::File { file } => read_secret_file(file)?,
            Self::Env { env } => load_env_var(env)?,
        };
        let value = value.trim_end().to_string();
        ensure!(!value.is_empty(), "header value from {self:?} is empty");
        Ok(value)
    }

    pub(crate) fn as_file(&self) -> Option<&Path> {
        match self {
            Self::File { file } => Some(file),
            _ => None,
        }
    }

    pub(crate) fn as_env(&self) -> Option<&str> {
        match self {
            Self::Env { env } => Some(env),
            _ => None,
        }
    }
}

// A literal is often the secret itself, so Debug never prints it
impl fmt::Debug for HeaderSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(_) => f.write_str("Literal(<redacted>)"),
            Self::File { file } => write!(f, "File({file:?})"),
            Self::Env { env } => write!(f, "Env({env})"),
        }
    }
}

fn read_secret_file(file: &Path) -> Result<String> {
    let mut value = String::new();
    File::open(file)
        .and_then(|f| f.take(RELAY_HEADER_FILE_MAX_BYTES + 1).read_to_string(&mut value))
        .wrap_err_with(|| format!("unable to read header file {file:?}"))?;
    ensure!(
        value.len() as u64 <= RELAY_HEADER_FILE_MAX_BYTES,
        "header file {file:?} is larger than {RELAY_HEADER_FILE_MAX_BYTES} bytes"
    );
    Ok(value)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Relay ID, if missing will default to the URL hostname from the entry
    pub id: Option<String>,
    /// Relay in the form of scheme://pubkey@host
    #[serde(rename = "url")]
    pub entry: RelayEntry,
    /// Optional headers to send with each request
    pub headers: Option<HashMap<String, HeaderSource>>,
    /// Optional GET parameters to add to each request
    pub get_params: Option<HashMap<String, String>>,
    /// How to fetch headers from this relay
    #[serde(default)]
    pub get_header: GetHeaderTransport,
    /// Whether to enable timing games
    #[serde(default = "default_bool::<false>")]
    pub enable_timing_games: bool,
    /// Target time in slot when to send the first header request
    pub target_first_request_ms: Option<u64>,
    /// Frequency in ms to send get_header requests
    pub frequency_get_header_ms: Option<u64>,
    /// Maximum number of validators to send to relays in one registration
    /// request
    #[serde(deserialize_with = "empty_string_as_none", default)]
    pub validator_registration_batch_size: Option<usize>,
}

fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Helper {
        Str(String),
        Number(usize),
    }

    match Helper::deserialize(deserializer)? {
        Helper::Str(str) if str.is_empty() => Ok(None),
        Helper::Str(str) => Ok(Some(str.parse().map_err(|_| {
            serde::de::Error::custom("Expected empty string or number".to_string())
        })?)),
        Helper::Number(number) => Ok(Some(number)),
    }
}

impl RelayConfig {
    pub fn id(&self) -> &str {
        self.id.as_deref().unwrap_or(self.entry.id.as_str())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PbsConfig {
    /// Host to receive BuilderAPI calls from beacon node
    #[serde(default = "default_host")]
    pub host: Ipv4Addr,
    /// Port to receive BuilderAPI calls from beacon node
    #[serde(default = "default_u16::<DEFAULT_PBS_PORT>")]
    pub port: u16,
    /// Whether to forward `get_status` to relays or skip it
    #[serde(default = "default_bool::<true>")]
    pub relay_check: bool,
    /// Whether to wait  for all registrations to complete before returning
    #[serde(default = "default_bool::<true>")]
    pub wait_all_registrations: bool,
    /// Timeout for get_header request in milliseconds
    #[serde(default = "default_u64::<{ DefaultTimeout::GET_HEADER_MS }>")]
    pub timeout_get_header_ms: u64,
    /// Timeout for get_payload request in milliseconds
    #[serde(default = "default_u64::<{ DefaultTimeout::GET_PAYLOAD_MS }>")]
    pub timeout_get_payload_ms: u64,
    /// Timeout for register_validator request in milliseconds
    #[serde(default = "default_u64::<{ DefaultTimeout::REGISTER_VALIDATOR_MS }>")]
    pub timeout_register_validator_ms: u64,
    /// Whether to skip the relay signature verification
    #[serde(default = "default_bool::<false>")]
    pub skip_sigverify: bool,
    /// Minimum bid that will be accepted from get_header
    #[serde(rename = "min_bid_eth", with = "as_eth_str", default = "default_u256")]
    pub min_bid_wei: U256,
    /// How late in the slot we consider to be "late"
    #[serde(default = "default_u64::<LATE_IN_SLOT_TIME_MS>")]
    pub late_in_slot_time_ms: u64,
    /// Enable extra validation of get_header responses
    #[serde(default = "default_bool::<false>")]
    pub extra_validation_enabled: bool,
    /// Execution Layer RPC url to use for extra validation
    pub rpc_url: Option<Url>,
    /// URL for the user's own SSV node API endpoint
    #[serde(default = "default_ssv_node_api_url")]
    pub ssv_node_api_url: Url,
    /// URL for the public SSV network API server
    #[serde(default = "default_public_ssv_api_url")]
    pub ssv_public_api_url: Url,
    /// Timeout for HTTP requests in seconds
    #[serde(default = "default_u64::<HTTP_TIMEOUT_SECONDS_DEFAULT>")]
    pub http_timeout_seconds: u64,
    /// Maximum number of retries for validator registration request per relay
    #[serde(default = "default_u32::<REGISTER_VALIDATOR_RETRY_LIMIT>")]
    pub register_validator_retry_limit: u32,
    /// Maximum number of validators to send to relays in a single registration
    /// request
    #[serde(deserialize_with = "empty_string_as_none", default)]
    pub validator_registration_batch_size: Option<usize>,
    /// For any Registry-based Mux configurations that have dynamic pubkey
    /// refreshing enabled, this is how often to refresh the list of pubkeys
    /// from the registry, in seconds
    #[serde(default = "default_u64::<{ DEFAULT_REGISTRY_REFRESH_SECONDS }>")]
    pub mux_registry_refresh_interval_seconds: u64,
}

impl PbsConfig {
    /// Validate PBS config parameters
    pub async fn validate(&self, chain: Chain) -> Result<()> {
        // timeouts must be positive
        ensure!(self.timeout_get_header_ms > 0, "timeout_get_header_ms must be greater than 0");
        ensure!(self.timeout_get_payload_ms > 0, "timeout_get_payload_ms must be greater than 0");
        ensure!(
            self.timeout_register_validator_ms > 0,
            "timeout_register_validator_ms must be greater than 0"
        );
        ensure!(self.late_in_slot_time_ms > 0, "late_in_slot_time_ms must be greater than 0");

        ensure!(
            self.timeout_get_header_ms < self.late_in_slot_time_ms,
            "timeout_get_header_ms must be less than late_in_slot_time_ms"
        );
        ensure!(
            self.register_validator_retry_limit > 0,
            "register_validator_retry_limit must be greater than 0"
        );

        ensure!(
            self.min_bid_wei < U256::from(WEI_PER_ETH),
            format!("min bid is too high: {} ETH", format_ether(self.min_bid_wei))
        );

        if self.extra_validation_enabled {
            ensure!(
                self.rpc_url.is_some(),
                "rpc_url is required if extra_validation_enabled is true"
            );
        }

        if let Some(rpc_url) = &self.rpc_url {
            let provider = ProviderBuilder::new().connect_http(rpc_url.clone());
            let chain_id = provider.get_chain_id().await?;
            let chain_id_big = U256::from(chain_id);
            ensure!(
                chain_id_big == chain.id(),
                "Rpc url is for the wrong chain, expected: {} ({:?}) got {}",
                chain.id(),
                chain,
                chain_id_big
            );
        }

        ensure!(
            self.mux_registry_refresh_interval_seconds > 0,
            "registry mux refreshing interval must be greater than 0"
        );

        Ok(())
    }
}

/// Static pbs config from config file
#[derive(Debug, Deserialize, Serialize)]
pub struct StaticPbsConfig {
    /// Docker image of the module
    #[serde(default = "default_pbs")]
    pub docker_image: String,
    /// Config of pbs module
    #[serde(flatten)]
    pub pbs_config: PbsConfig,
    /// Whether to enable the signer client
    #[serde(default = "default_bool::<false>")]
    pub with_signer: bool,
}

impl StaticPbsConfig {
    /// Validate static pbs config
    pub async fn validate(&self, chain: Chain) -> Result<()> {
        // The Docker tag must parse
        ensure!(!self.docker_image.is_empty(), "Docker image is empty");
        ensure!(
            DockerImage::parse(&self.docker_image).is_ok(),
            format!("Invalid Docker image: {}", self.docker_image)
        );

        // Validate the inner pbs config
        self.pbs_config.validate(chain).await
    }
}

/// Runtime config for the pbs module
#[derive(Debug, Clone)]
pub struct PbsModuleConfig {
    /// Chain spec
    pub chain: Chain,
    /// Endpoint to receive BuilderAPI calls from beacon node
    pub endpoint: SocketAddr,
    /// Pbs default config
    pub pbs_config: Arc<PbsConfig>,
    /// List of default relays
    pub relays: Vec<RelayClient>,
    /// List of all default relays plus additional relays from muxes (based on
    /// URL) DO NOT use this for get_header calls, use `relays` or `mux_lookup`
    /// instead
    pub all_relays: Vec<RelayClient>,
    /// Signer client to call Signer API
    pub signer_client: Option<SignerClient>,
    /// List of raw mux details configured, if any
    pub registry_muxes: Option<HashMap<MuxKeysLoader, RuntimeMuxConfig>>,
    /// Lookup of pubkey to mux config
    pub mux_lookup: Option<HashMap<BlsPublicKey, RuntimeMuxConfig>>,
}

fn default_pbs() -> String {
    COMMIT_BOOST_IMAGE_DEFAULT.to_string()
}

/// Loads the default pbs config, i.e. with no signer client or custom data
pub async fn load_pbs_config(config_path: Option<PathBuf>) -> Result<(PbsModuleConfig, PathBuf)> {
    let (config, config_path) = match config_path {
        Some(path) => (CommitBoostConfig::from_file(&path)?, path),
        None => CommitBoostConfig::from_env_path()?,
    };
    config.validate().await?;

    // Make sure relays isn't empty - since the config is still technically valid if
    // there are no relays for things like Docker compose generation, this check
    // isn't in validate().
    ensure!(
        !config.relays.is_empty(),
        "At least one relay must be configured to run the PBS service"
    );

    // use endpoint from env if set, otherwise use default host and port
    let endpoint = if let Some(endpoint) = load_optional_env_var(PBS_ENDPOINT_ENV) {
        endpoint.parse()?
    } else {
        SocketAddr::from((config.pbs.pbs_config.host, config.pbs.pbs_config.port))
    };

    // Get the list of relays from the default config
    let relay_clients =
        config.relays.into_iter().map(RelayClient::new).collect::<Result<Vec<_>>>()?;
    let mut all_relays = HashMap::with_capacity(relay_clients.len());

    // Validate the muxes and build the lookup tables
    let (mux_lookup, registry_muxes) = match config.muxes {
        Some(muxes) => {
            let (mux_lookup, registry_muxes) =
                muxes.validate_and_fill(config.chain, &config.pbs.pbs_config).await?;
            (Some(mux_lookup), Some(registry_muxes))
        }
        None => (None, None),
    };

    // Build the list of all relays, starting with muxes
    if let Some(muxes) = &mux_lookup {
        for (_, mux) in muxes.iter() {
            for relay in mux.relays.iter() {
                all_relays.insert(&relay.config.entry.url, relay.clone());
            }
        }
    }

    // insert default relays after to make sure we keep these as defaults,
    // this means we override timing games which is ok since this won't be used for
    // get_header we also override headers if the same relays has two
    // definitions (in muxes and default)
    for relay in relay_clients.iter() {
        all_relays.insert(&relay.config.entry.url, relay.clone());
    }

    let all_relays = all_relays.into_values().collect();

    Ok((
        PbsModuleConfig {
            chain: config.chain,
            endpoint,
            pbs_config: Arc::new(config.pbs.pbs_config),
            relays: relay_clients,
            all_relays,
            signer_client: None,
            registry_muxes,
            mux_lookup,
        },
        config_path,
    ))
}

/// Loads a custom pbs config, i.e. with signer client and/or custom data
pub async fn load_pbs_custom_config<T: DeserializeOwned>() -> Result<(PbsModuleConfig, T)> {
    #[derive(Debug, Deserialize)]
    struct CustomPbsConfig<U> {
        #[serde(flatten)]
        static_config: StaticPbsConfig,
        #[serde(flatten)]
        extra: U,
    }

    #[derive(Deserialize, Debug)]
    struct StubConfig<U> {
        chain: Chain,
        relays: Vec<RelayConfig>,
        pbs: CustomPbsConfig<U>,
        signer: Option<SignerConfig>,
        muxes: Option<PbsMuxes>,
    }

    // load module config including the extra data (if any)
    let (cb_config, _): (StubConfig<T>, _) = load_file_from_env(CONFIG_ENV)?;
    cb_config.pbs.static_config.validate(cb_config.chain).await?;

    // use endpoint from env if set, otherwise use default host and port
    let endpoint = if let Some(endpoint) = load_optional_env_var(PBS_ENDPOINT_ENV) {
        endpoint.parse()?
    } else {
        SocketAddr::from((
            cb_config.pbs.static_config.pbs_config.host,
            cb_config.pbs.static_config.pbs_config.port,
        ))
    };

    // Get the list of relays from the default config
    let relay_clients =
        cb_config.relays.into_iter().map(RelayClient::new).collect::<Result<Vec<_>>>()?;
    let mut all_relays = HashMap::with_capacity(relay_clients.len());

    // Validate the muxes and build the lookup tables
    let (mux_lookup, registry_muxes) = match cb_config.muxes {
        Some(muxes) => {
            let (mux_lookup, registry_muxes) = muxes
                .validate_and_fill(cb_config.chain, &cb_config.pbs.static_config.pbs_config)
                .await?;
            (Some(mux_lookup), Some(registry_muxes))
        }
        None => (None, None),
    };

    // Build the list of all relays, starting with muxes
    if let Some(muxes) = &mux_lookup {
        for (_, mux) in muxes.iter() {
            for relay in mux.relays.iter() {
                all_relays.insert(&relay.config.entry.url, relay.clone());
            }
        }
    }

    // insert default relays after to make sure we keep these as defaults,
    // this also means we override timing games which is ok since this won't be used
    // for get header we also override headers if the same relays has two
    // definitions (in muxes and default)
    for relay in relay_clients.iter() {
        all_relays.insert(&relay.config.entry.url, relay.clone());
    }

    let all_relays = all_relays.into_values().collect();

    let signer_client = if cb_config.pbs.static_config.with_signer {
        // if custom pbs requires a signer client, load jwt
        let module_jwt = Jwt(load_env_var(MODULE_JWT_ENV)?);
        let signer_server_url = load_env_var(SIGNER_URL_ENV)?.parse()?;
        let certs_path = match cb_config
            .signer
            .ok_or_else(|| eyre::eyre!("with_signer = true but no [signer] section in config"))?
            .tls_mode
        {
            TlsMode::Insecure => None,
            TlsMode::Certificate(path) => Some(
                load_env_var(SIGNER_TLS_CERTIFICATES_PATH_ENV)
                    .map(PathBuf::from)
                    .unwrap_or(path)
                    .join(SIGNER_TLS_CERTIFICATE_NAME),
            ),
        };
        Some(SignerClient::new(
            signer_server_url,
            certs_path,
            module_jwt,
            ModuleId(PBS_SERVICE_NAME.to_string()),
        )?)
    } else {
        None
    };

    Ok((
        PbsModuleConfig {
            chain: cb_config.chain,
            endpoint,
            pbs_config: Arc::new(cb_config.pbs.static_config.pbs_config),
            relays: relay_clients,
            all_relays,
            signer_client,
            registry_muxes,
            mux_lookup,
        },
        cb_config.pbs.extra,
    ))
}

/// Default URL for the user's SSV node API endpoint (/v1/validators).
fn default_ssv_node_api_url() -> Url {
    Url::parse("http://localhost:16000/v1/").expect("default URL is valid")
}

/// Default URL for the public SSV network API.
fn default_public_ssv_api_url() -> Url {
    Url::parse("https://api.ssv.network/api/v4/").expect("default URL is valid")
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::config::test_env::{RELAY_URL, with_env};

    fn relay_with_headers(headers: &str) -> Result<RelayConfig, toml::de::Error> {
        toml::from_str(&format!("url = \"{RELAY_URL}\"\nheaders = {headers}\n"))
    }

    #[test]
    fn test_header_source_parses_all_shapes() {
        let config = relay_with_headers(
            r#"{ X-Literal = "plain", X-File = { file = "/run/secrets/key" }, X-Env = { env = "RELAY_KEY" } }"#,
        )
        .unwrap();
        let headers = config.headers.as_ref().unwrap();
        assert_eq!(headers["X-Literal"], HeaderSource::Literal("plain".into()));
        assert_eq!(headers["X-File"], HeaderSource::File { file: "/run/secrets/key".into() });
        assert_eq!(headers["X-Env"], HeaderSource::Env { env: "RELAY_KEY".into() });
        assert_eq!(headers["X-File"].as_file(), Some(Path::new("/run/secrets/key")));
        assert_eq!(headers["X-Env"].as_env(), Some("RELAY_KEY"));
        assert_eq!(headers["X-Literal"].as_file(), None);
        assert_eq!(headers["X-Literal"].as_env(), None);

        // A table matching neither shape is an error, not a silent literal
        let err = relay_with_headers(r#"{ X-Key = { path = "/x" } }"#).unwrap_err();
        assert!(err.to_string().contains("X-Key"), "{err}");

        // Both keys at once reads the file; the startup log names the source
        let config = relay_with_headers(r#"{ X-Key = { file = "/x", env = "Y" } }"#).unwrap();
        assert_eq!(config.headers.as_ref().unwrap()["X-Key"].as_file(), Some(Path::new("/x")));
    }

    #[test]
    fn test_header_source_file_resolution() {
        let file = |contents: &[u8]| {
            let mut f = tempfile::NamedTempFile::new().unwrap();
            f.write_all(contents).unwrap();
            f
        };
        let resolve = |path: &Path| HeaderSource::File { file: path.to_path_buf() }.resolve();

        // secret stores end the file with a newline; leading whitespace is kept
        assert_eq!(resolve(file(b"s3cret \n").path()).unwrap(), "s3cret");
        assert_eq!(resolve(file(b" pad \n").path()).unwrap(), " pad");
        // a literal is sent exactly as written, empty included
        assert_eq!(HeaderSource::Literal(String::new()).resolve().unwrap(), "");
        assert_eq!(HeaderSource::Literal(" x ".into()).resolve().unwrap(), " x ");

        // the cap is inclusive
        let max = RELAY_HEADER_FILE_MAX_BYTES as usize;
        assert_eq!(resolve(file(&vec![b'a'; max]).path()).unwrap().len(), max);

        let dir = tempfile::tempdir().unwrap();
        let big = file(&vec![b'a'; max + 1]);
        for (path, expected) in [
            (file(b"\n").path().to_path_buf(), "empty"),
            ("/nonexistent/relay-key".into(), "unable to read header file"),
            (dir.path().to_path_buf(), "unable to read header file"),
            (big.path().to_path_buf(), "larger than"),
        ] {
            let err = resolve(&path).unwrap_err();
            assert!(err.to_string().contains(expected), "{path:?}: {err}");
        }
    }

    #[test]
    fn test_header_source_env_var() {
        with_env(&[("CB_TEST_HEADER_SOURCE_KEY", Some("from-env\n"))], || {
            assert_eq!(
                HeaderSource::Env { env: "CB_TEST_HEADER_SOURCE_KEY".into() }.resolve().unwrap(),
                "from-env"
            );
        });
        with_env(&[("CB_TEST_HEADER_SOURCE_ABSENT", None)], || {
            let err = HeaderSource::Env { env: "CB_TEST_HEADER_SOURCE_ABSENT".into() }
                .resolve()
                .unwrap_err();
            assert!(err.to_string().contains("CB_TEST_HEADER_SOURCE_ABSENT"), "{err}");
        });
        with_env(&[("CB_TEST_HEADER_SOURCE_EMPTY", Some(""))], || {
            let err = HeaderSource::Env { env: "CB_TEST_HEADER_SOURCE_EMPTY".into() }
                .resolve()
                .unwrap_err();
            assert!(err.to_string().contains("empty"), "{err}");
        });
    }

    #[test]
    fn test_header_source_debug_redacts_literal() {
        let debug = format!("{:?}", HeaderSource::Literal("s3cret".into()));
        assert!(!debug.contains("s3cret"), "{debug}");
        // and the whole relay config inherits that
        let debug = format!("{:?}", relay_with_headers(r#"{ X-Api-Key = "s3cret" }"#).unwrap());
        assert!(!debug.contains("s3cret"), "{debug}");
    }
}
