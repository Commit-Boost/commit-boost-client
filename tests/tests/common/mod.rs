use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    u64,
};

use alloy::primitives::U256;
use cb_common::{
    config::{PbsConfig, PbsModuleConfig},
    pbs::RelayClient,
    types::Chain,
};

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
