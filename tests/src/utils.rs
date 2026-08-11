use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Once},
    time::Duration,
};

use alloy::primitives::{B256, U256};
use cb_common::{
    config::{
        COMMIT_BOOST_IMAGE_DEFAULT, CommitBoostConfig, GetHeaderTransport, LogsSettings,
        ModuleKind, ModuleSigningConfig, PbsConfig, PbsModuleConfig, RelayConfig,
        ReverseProxyHeaderSetup, SIGNER_JWT_AUTH_FAIL_LIMIT_DEFAULT,
        SIGNER_JWT_AUTH_FAIL_TIMEOUT_SECONDS_DEFAULT, SIGNER_PORT_DEFAULT, SignerConfig,
        SignerType, StartSignerConfig, StaticModuleConfig, StaticPbsConfig, TlsMode,
    },
    pbs::{RelayClient, RelayEntry, RequestAuth, SignedRequestAuth},
    signature::sign_request_auth_root,
    signer::{SignerLoader, random_secret},
    types::{BlsPublicKey, BlsSecretKey, BlsSignature, Chain, ModuleId},
    utils::{bls_pubkey_from_hex, default_host},
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use eyre::Result;
use lh_types::Slot;
use rcgen::generate_simple_self_signed;
use reqwest::StatusCode;
use tree_hash::TreeHash;
use url::Url;

use crate::{
    mock_relay::{MockRelayState, start_mock_relay_service_with_listener},
    mock_validator::MockValidator,
};

pub const HEADER_API_KEY: &str = "x-api-key";
pub const API_KEY: &str = "123e4567-e89b-12d3-a456-426614174000";
/// Distinct from [`API_KEY`], which `MockValidator` also sends to PBS: a relay
/// that sees this one can only have got it from its own config.
pub const RELAY_API_KEY: &str = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
/// The auth data the default mock relay declares and most ePBS tests send.
/// Unmatched auth data is a 400 (no catch-all), so a relay must declare the
/// data it serves for opaque-data tests to route.
pub const TEST_AUTH_DATA: &[u8] = &[0xde, 0xad];

pub fn get_local_address(port: u16) -> String {
    format!("http://0.0.0.0:{port}")
}

pub async fn get_free_listener() -> tokio::net::TcpListener {
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap()
}

static SYNC_SETUP: Once = Once::new();
pub fn setup_test_env() {
    SYNC_SETUP.call_once(|| {
        tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE).init();
    });
}

fn mock_relay_config(port: u16, pubkey: BlsPublicKey) -> Result<RelayConfig> {
    Ok(RelayConfig {
        entry: RelayEntry {
            id: format!("mock_{port}"),
            pubkey,
            url: get_local_address(port).parse()?,
        },
        id: None,
        headers: Some(HashMap::from([(HEADER_API_KEY.into(), API_KEY.into())])),
        get_params: None,
        get_header: GetHeaderTransport::Http,
        enable_timing_games: false,
        target_first_request_ms: None,
        frequency_get_header_ms: None,
        bid_poll_timeout_ms: None,
        validator_registration_batch_size: None,
        max_execution_payment_gwei: None,
        expected_auth_data: Some(TEST_AUTH_DATA.to_vec().into()),
    })
}

pub fn generate_mock_relay(port: u16, pubkey: BlsPublicKey) -> Result<RelayClient> {
    RelayClient::new(mock_relay_config(port, pubkey)?)
}

pub fn generate_mock_relay_with_max_payment(
    port: u16,
    pubkey: BlsPublicKey,
    max_execution_payment_gwei: u64,
) -> Result<RelayClient> {
    let mut relay = generate_mock_relay(port, pubkey)?;
    let mut config = (*relay.config).clone();
    config.max_execution_payment_gwei = Some(max_execution_payment_gwei);
    relay.config = std::sync::Arc::new(config);
    Ok(relay)
}

pub fn generate_mock_relay_with_timing_games(
    port: u16,
    pubkey: BlsPublicKey,
    frequency_get_header_ms: u64,
    bid_poll_timeout_ms: Option<u64>,
) -> Result<RelayClient> {
    let mut relay = generate_mock_relay(port, pubkey)?;
    let mut config = (*relay.config).clone();
    config.enable_timing_games = true;
    config.frequency_get_header_ms = Some(frequency_get_header_ms);
    config.bid_poll_timeout_ms = bid_poll_timeout_ms;
    relay.config = std::sync::Arc::new(config);
    Ok(relay)
}

pub fn generate_mock_relay_url_only(port: u16, pubkey: BlsPublicKey) -> Result<RelayClient> {
    let mut relay = generate_mock_relay(port, pubkey)?;
    let mut config = (*relay.config).clone();
    config.expected_auth_data = None;
    relay.config = std::sync::Arc::new(config);
    Ok(relay)
}

pub fn generate_mock_relay_with_auth_data(
    port: u16,
    pubkey: BlsPublicKey,
    expected_auth_data: &[u8],
) -> Result<RelayClient> {
    let mut relay = generate_mock_relay(port, pubkey)?;
    let mut config = (*relay.config).clone();
    config.expected_auth_data = Some(expected_auth_data.to_vec().into());
    relay.config = std::sync::Arc::new(config);
    Ok(relay)
}

pub fn generate_mock_relay_with_batch_size(
    port: u16,
    pubkey: BlsPublicKey,
    batch_size: usize,
) -> Result<RelayClient> {
    let mut config = mock_relay_config(port, pubkey)?;
    config.validator_registration_batch_size = Some(batch_size);
    RelayClient::new(config)
}

pub fn generate_mock_relay_with_api_key(
    port: u16,
    pubkey: BlsPublicKey,
    api_key: &str,
) -> Result<RelayClient> {
    let mut config = mock_relay_config(port, pubkey)?;
    config.headers = Some(HashMap::from([(HEADER_API_KEY.into(), api_key.into())]));
    RelayClient::new(config)
}

pub fn generate_mock_stream_relay(port: u16, pubkey: BlsPublicKey) -> Result<RelayClient> {
    let mut config = mock_relay_config(port, pubkey)?;
    config.get_header = GetHeaderTransport::Stream;
    RelayClient::new(config)
}

pub fn generate_mock_stream_relay_with_timing_games(
    port: u16,
    pubkey: BlsPublicKey,
    target_first_request_ms: u64,
    frequency_get_header_ms: u64,
) -> Result<RelayClient> {
    let mut config = mock_relay_config(port, pubkey)?;
    config.get_header = GetHeaderTransport::Stream;
    config.enable_timing_games = true;
    config.target_first_request_ms = Some(target_first_request_ms);
    config.frequency_get_header_ms = Some(frequency_get_header_ms);
    RelayClient::new(config)
}

pub fn get_pbs_config(port: u16) -> PbsConfig {
    PbsConfig {
        host: Ipv4Addr::UNSPECIFIED,
        port,
        wait_all_registrations: true,
        relay_check: true,
        timeout_get_header_ms: u64::MAX,
        timeout_get_payload_ms: u64::MAX,
        timeout_register_validator_ms: u64::MAX,
        skip_sigverify: false,
        min_bid_wei: U256::ZERO,
        max_execution_payment_gwei: 0,
        fee_recipient: None,
        late_in_slot_time_ms: u64::MAX,
        extra_validation_enabled: false,
        verify_request_auth: false,

        ssv_node_api_url: Url::parse("http://localhost:0").unwrap(),
        ssv_public_api_url: Url::parse("http://localhost:0").unwrap(),
        rpc_url: None,
        http_timeout_seconds: 10,
        register_validator_retry_limit: u32::MAX,
        validator_registration_batch_size: None,
        mux_registry_refresh_interval_seconds: 5,
    }
}

pub fn get_pbs_static_config(pbs_config: PbsConfig) -> StaticPbsConfig {
    StaticPbsConfig { docker_image: String::from(""), pbs_config, with_signer: true }
}

pub fn get_commit_boost_config(pbs_static_config: StaticPbsConfig) -> CommitBoostConfig {
    CommitBoostConfig {
        chain: Chain::Hoodi,
        relays: vec![],
        pbs: pbs_static_config,
        muxes: None,
        modules: Some(vec![]),
        signer: None,
        metrics: None,
        logs: LogsSettings::default(),
    }
}

pub fn to_pbs_config(
    chain: Chain,
    pbs_config: PbsConfig,
    relays: Vec<RelayClient>,
) -> PbsModuleConfig {
    PbsModuleConfig {
        chain,
        endpoint: SocketAddr::new(pbs_config.host.into(), pbs_config.port),
        pbs_config: Arc::new(pbs_config),
        signer_client: None,
        all_relays: relays.clone(),
        relays,
        registry_muxes: None,
        mux_lookup: None,
    }
}

pub fn get_signer_config(loader: SignerLoader, tls: bool) -> SignerConfig {
    SignerConfig {
        host: default_host(),
        port: SIGNER_PORT_DEFAULT,
        docker_image: COMMIT_BOOST_IMAGE_DEFAULT.to_string(),
        jwt_auth_fail_limit: SIGNER_JWT_AUTH_FAIL_LIMIT_DEFAULT,
        jwt_auth_fail_timeout_seconds: SIGNER_JWT_AUTH_FAIL_TIMEOUT_SECONDS_DEFAULT,
        inner: SignerType::Local { loader, store: None },
        tls_mode: if tls { TlsMode::Certificate(PathBuf::new()) } else { TlsMode::Insecure },
        reverse_proxy: ReverseProxyHeaderSetup::None,
    }
}

pub fn get_start_signer_config(
    signer_config: SignerConfig,
    chain: Chain,
    mod_signing_configs: &HashMap<ModuleId, ModuleSigningConfig>,
    admin_secret: String,
) -> StartSignerConfig {
    let tls_certificates = match signer_config.tls_mode {
        TlsMode::Insecure => None,
        TlsMode::Certificate(_) => Some(
            generate_simple_self_signed(vec![signer_config.host.to_string()])
                .map(|x| {
                    (
                        x.cert.pem().as_bytes().to_vec(),
                        x.key_pair.serialize_pem().as_bytes().to_vec(),
                    )
                })
                .expect("Failed to generate TLS certificate"),
        ),
    };

    match signer_config.inner {
        SignerType::Local { loader, .. } => StartSignerConfig {
            chain,
            loader: Some(loader),
            store: None,
            endpoint: SocketAddr::new(signer_config.host.into(), signer_config.port),
            mod_signing_configs: mod_signing_configs.clone(),
            admin_secret,
            jwt_auth_fail_limit: signer_config.jwt_auth_fail_limit,
            jwt_auth_fail_timeout_seconds: signer_config.jwt_auth_fail_timeout_seconds,
            dirk: None,
            tls_certificates,
            reverse_proxy: ReverseProxyHeaderSetup::None,
        },
        _ => panic!("Only local signers are supported in tests"),
    }
}

pub fn create_module_config(id: ModuleId, signing_id: B256) -> StaticModuleConfig {
    StaticModuleConfig {
        id,
        signing_id,
        docker_image: String::from(""),
        env: None,
        env_file: None,
        kind: ModuleKind::Commit,
    }
}

pub fn bls_pubkey_from_hex_unchecked(hex: &str) -> BlsPublicKey {
    bls_pubkey_from_hex(hex).unwrap()
}

/// Build a `SignedRequestAuth` carrying opaque `data`. CB forwards it
/// unmodified; the signature is only verified when `verify_request_auth` is on,
/// so an empty one suffices elsewhere.
pub fn opaque_auth(data: &[u8], slot: u64) -> SignedRequestAuth {
    SignedRequestAuth {
        message: RequestAuth {
            data: ssz_types::VariableList::new(data.to_vec()).expect("data fits in MAX_DATA_SIZE"),
            slot: Slot::new(slot),
        },
        signature: BlsSignature::empty(),
    }
}

/// Same, but signed under the spec's `DOMAIN_REQUEST_AUTH` by `secret_key`.
pub fn signed_auth(
    secret_key: &BlsSecretKey,
    data: &[u8],
    slot: u64,
    chain: Chain,
) -> SignedRequestAuth {
    let mut auth = opaque_auth(data, slot);
    auth.signature = sign_request_auth_root(secret_key, &auth.message.tree_hash_root(), chain);
    auth
}

/// Boot PBS in front of one mock relay, letting the test shape both the PBS
/// config and the relay entry.
pub async fn setup_relay(
    chain: Chain,
    tweak: impl FnOnce(&mut PbsConfig),
    make_relay: impl FnOnce(u16, BlsPublicKey) -> Result<RelayClient>,
) -> Result<(MockValidator, Arc<MockRelayState>)> {
    setup_test_env();
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
    let mock_relay = make_relay(relay_port, mock_state.signer.public_key())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let mut pbs_config = get_pbs_config(pbs_port);
    tweak(&mut pbs_config);
    let config = to_pbs_config(chain, pbs_config, vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;
    Ok((mock_validator, mock_state))
}

/// Boot PBS in front of several mock relays, one per supplied `MockRelayState`,
/// so per-relay knobs and counters stay independent. Returns the validator and
/// the relay states in configuration order.
pub async fn setup_relays(
    chain: Chain,
    states: Vec<MockRelayState>,
) -> Result<(MockValidator, Vec<Arc<MockRelayState>>)> {
    setup_test_env();
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();

    let mut relays = Vec::new();
    let mut arc_states = Vec::new();
    for state in states {
        let relay_listener = get_free_listener().await;
        let relay_port = relay_listener.local_addr()?.port();
        let state = Arc::new(state);
        relays.push(generate_mock_relay(relay_port, state.signer.public_key())?);
        tokio::spawn(start_mock_relay_service_with_listener(state.clone(), relay_listener));
        arc_states.push(state);
    }

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;
    Ok((mock_validator, arc_states))
}

/// Like [`setup_relays`], but each relay declares the `expected_auth_data` it
/// serves, so tests can address one builder among several.
pub async fn setup_relays_with_auth_data(
    chain: Chain,
    states: Vec<(MockRelayState, &[u8])>,
) -> Result<(MockValidator, Vec<Arc<MockRelayState>>)> {
    setup_test_env();
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();

    let mut relays = Vec::new();
    let mut arc_states = Vec::new();
    for (state, auth_data) in states {
        let relay_listener = get_free_listener().await;
        let relay_port = relay_listener.local_addr()?.port();
        let state = Arc::new(state);
        relays.push(generate_mock_relay_with_auth_data(
            relay_port,
            state.signer.public_key(),
            auth_data,
        )?);
        tokio::spawn(start_mock_relay_service_with_listener(state.clone(), relay_listener));
        arc_states.push(state);
    }

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;
    Ok((mock_validator, arc_states))
}

/// Poll /status until PBS and its relays are up. relay_check makes a 200 mean
/// the whole chain is ready; the fixed 100ms sleep used elsewhere flakes under
/// parallel suite load.
pub async fn wait_for_ready(mock_validator: &MockValidator) -> Result<()> {
    for _ in 0..100 {
        if let Ok(res) = mock_validator.do_get_status().await &&
            res.status() == StatusCode::OK
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    eyre::bail!("PBS/relays did not become ready within 2s")
}
