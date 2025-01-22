use std::sync::Once;

use alloy::rpc::types::beacon::BlsPublicKey;
use cb_common::{
    config::RelayConfig,
    pbs::{RelayClient, RelayEntry},
};
use eyre::Result;

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
        enable_timing_games: false,
        target_first_request_ms: None,
        frequency_get_header_ms: None,
        validator_registration_batch_size: Some(batch_size),
    };
    RelayClient::new(config)
}
