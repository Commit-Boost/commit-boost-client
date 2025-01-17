use cb_common::{
    config::{PbsConfig, PbsModuleConfig, RelayConfig},
    pbs::{RelayClient, RelayEntry},
    types::Chain,
};
use eyre::Result;

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Once},
    u64,
};

use alloy::{primitives::U256, rpc::types::beacon::BlsPublicKey};

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
        enable_timing_games: false,
        target_first_request_ms: None,
        frequency_get_header_ms: None,
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
        relay_monitors: vec![],
        extra_validation_enabled: false,
        rpc_url: None,
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
        event_publisher: None,
        all_relays: relays.clone(),
        relays,
        muxes: None,
    }
}
