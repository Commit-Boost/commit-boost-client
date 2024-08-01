use std::sync::Once;

use alloy::rpc::types::beacon::BlsPublicKey;
use cb_common::pbs::{RelayClient, RelayConfig, RelayEntry};
use eyre::Result;

pub fn get_local_address(port: u16) -> String {
    format!("http://0.0.0.0:{port}")
}

static SYNC_SETUP: Once = Once::new();
pub fn setup_test_env() {
    SYNC_SETUP.call_once(|| {
        tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).init();
    });
}

pub fn generate_mock_relay(port: u16, pubkey: BlsPublicKey) -> Result<RelayClient> {
    let entry = RelayEntry { id: format!("mock_{port}"), pubkey, url: get_local_address(port) };
    let config = RelayConfig { entry, ..RelayConfig::default() };
    Ok(RelayClient::new(config)?)
}
