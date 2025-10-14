use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Once},
};

use alloy::primitives::U256;
use cb_common::{
    config::{
        PbsConfig, PbsModuleConfig, RelayConfig, SIGNER_IMAGE_DEFAULT,
        SIGNER_JWT_AUTH_FAIL_LIMIT_DEFAULT, SIGNER_JWT_AUTH_FAIL_TIMEOUT_SECONDS_DEFAULT,
        SIGNER_PORT_DEFAULT, SignerConfig, SignerType, StartSignerConfig,
    },
    pbs::{RelayClient, RelayEntry},
    signer::SignerLoader,
    types::{BlsPublicKey, Chain, ModuleId},
    utils::{bls_pubkey_from_hex, default_host},
};
use eyre::Result;
use url::Url;

pub fn get_local_address(port: u16) -> String {
    format!("http://0.0.0.0:{port}")
}

static SYNC_SETUP: Once = Once::new();
pub fn setup_test_env() {
    SYNC_SETUP.call_once(|| {
        tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE).init();
    });
}

pub fn generate_mock_relay(port: u16, pubkey: BlsPublicKey) -> Result<RelayClient> {
    let entry =
        RelayEntry { id: format!("mock_{port}"), pubkey, url: get_local_address(port).parse()? };
    let config = RelayConfig {
        entry,
        id: None,
        headers: None,
        get_params: None,
        enable_timing_games: false,
        target_first_request_ms: None,
        frequency_get_header_ms: None,
        validator_registration_batch_size: None,
    };
    RelayClient::new(config)
}

pub fn generate_mock_relay_with_batch_size(
    port: u16,
    pubkey: BlsPublicKey,
    batch_size: usize,
) -> Result<RelayClient> {
    let entry =
        RelayEntry { id: format!("mock_{port}"), pubkey, url: get_local_address(port).parse()? };
    let config = RelayConfig {
        entry,
        id: None,
        headers: None,
        get_params: None,
        enable_timing_games: false,
        target_first_request_ms: None,
        frequency_get_header_ms: None,
        validator_registration_batch_size: Some(batch_size),
    };
    RelayClient::new(config)
}

pub fn get_pbs_static_config(port: u16) -> PbsConfig {
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
        late_in_slot_time_ms: u64::MAX,
        extra_validation_enabled: false,
        ssv_api_url: Url::parse("https://example.net").unwrap(),
        rpc_url: None,
        http_timeout_seconds: 10,
        register_validator_retry_limit: u32::MAX,
        validator_registration_batch_size: None,
        mux_registry_refresh_interval_seconds: 5,
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

pub fn get_signer_config(loader: SignerLoader) -> SignerConfig {
    SignerConfig {
        host: default_host(),
        port: SIGNER_PORT_DEFAULT,
        docker_image: SIGNER_IMAGE_DEFAULT.to_string(),
        jwt_auth_fail_limit: SIGNER_JWT_AUTH_FAIL_LIMIT_DEFAULT,
        jwt_auth_fail_timeout_seconds: SIGNER_JWT_AUTH_FAIL_TIMEOUT_SECONDS_DEFAULT,
        inner: SignerType::Local { loader, store: None },
    }
}

pub fn get_start_signer_config(
    signer_config: SignerConfig,
    chain: Chain,
    jwts: HashMap<ModuleId, String>,
) -> StartSignerConfig {
    match signer_config.inner {
        SignerType::Local { loader, .. } => StartSignerConfig {
            chain,
            loader: Some(loader),
            store: None,
            endpoint: SocketAddr::new(signer_config.host.into(), signer_config.port),
            jwts,
            jwt_auth_fail_limit: signer_config.jwt_auth_fail_limit,
            jwt_auth_fail_timeout_seconds: signer_config.jwt_auth_fail_timeout_seconds,
            dirk: None,
        },
        _ => panic!("Only local signers are supported in tests"),
    }
}

pub fn bls_pubkey_from_hex_unchecked(hex: &str) -> BlsPublicKey {
    bls_pubkey_from_hex(hex).unwrap()
}
