use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use alloy::rpc::types::beacon::BlsPublicKey;
use eyre::{bail, ensure, eyre};
use serde::{Deserialize, Serialize};

use super::{PbsConfig, RelayConfig};
use crate::pbs::{RelayClient, RelayEntry};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PbsMuxes {
    /// List of PBS multiplexers
    #[serde(rename = "mux")]
    pub muxes: Vec<MuxConfig>,
}

#[derive(Debug, Clone)]
pub struct RuntimeMuxConfig {
    pub config: Arc<PbsConfig>,
    pub relays: Vec<RelayClient>,
}

impl PbsMuxes {
    pub fn validate_and_fill(
        self,
        default_pbs: &PbsConfig,
        default_relays: &[RelayConfig],
    ) -> eyre::Result<HashMap<BlsPublicKey, RuntimeMuxConfig>> {
        // check that validator pubkeys are in disjoint sets
        let mut unique_pubkeys = HashSet::new();
        for mux in self.muxes.iter() {
            for pubkey in mux.validator_pubkeys.iter() {
                if !unique_pubkeys.insert(pubkey) {
                    bail!("duplicate validator pubkey in muxes: {pubkey}");
                }
            }
        }

        let mut configs = HashMap::new();
        // fill the configs using the default pbs config and relay entries
        for mux in self.muxes.into_iter() {
            ensure!(!mux.relays.is_empty(), "mux config must have at least one relay");
            ensure!(
                !mux.validator_pubkeys.is_empty(),
                "mux config must have at least one validator pubkey"
            );

            let mut relay_clients = Vec::with_capacity(mux.relays.len());
            for partial_relay in mux.relays.into_iter() {
                // create a new config overriding only the missing fields
                let partial_id = partial_relay.id()?;
                // assume that there is always a relay defined in the default config. If this
                // becomes too much of a burden, we can change this to allow defining relays
                // that are exclusively used by a mux
                let default_relay = default_relays
                    .iter()
                    .find(|r| r.id() == partial_id)
                    .ok_or_else(|| eyre!("default relay config not found for: {}", partial_id))?;

                let full_config = RelayConfig {
                    id: Some(partial_id.to_string()),
                    entry: partial_relay.entry.unwrap_or(default_relay.entry.clone()),
                    headers: partial_relay.headers.or(default_relay.headers.clone()),
                    enable_timing_games: partial_relay
                        .enable_timing_games
                        .unwrap_or(default_relay.enable_timing_games),
                    target_first_request_ms: partial_relay
                        .target_first_request_ms
                        .or(default_relay.target_first_request_ms),
                    frequency_get_header_ms: partial_relay
                        .frequency_get_header_ms
                        .or(default_relay.frequency_get_header_ms),
                };

                relay_clients.push(RelayClient::new(full_config)?);
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
            let config = Arc::new(config);

            let runtime_config = RuntimeMuxConfig { config, relays: relay_clients };
            for pubkey in mux.validator_pubkeys.iter() {
                configs.insert(*pubkey, runtime_config.clone());
            }
        }

        Ok(configs)
    }
}

/// Configuration for the PBS Multiplexer
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MuxConfig {
    /// Relays to use for this mux config
    pub relays: Vec<PartialRelayConfig>,
    /// Which validator pubkeys to match against this mux config
    pub validator_pubkeys: Vec<BlsPublicKey>,
    pub timeout_get_header_ms: Option<u64>,
    pub late_in_slot_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
/// A relay config with all optional fields. See [`RelayConfig`] for the
/// description of the fields.
pub struct PartialRelayConfig {
    pub id: Option<String>,
    #[serde(rename = "url")]
    pub entry: Option<RelayEntry>,
    pub headers: Option<HashMap<String, String>>,
    pub enable_timing_games: Option<bool>,
    pub target_first_request_ms: Option<u64>,
    pub frequency_get_header_ms: Option<u64>,
}

impl PartialRelayConfig {
    pub fn id(&self) -> eyre::Result<&str> {
        match &self.id {
            Some(id) => Ok(id.as_str()),
            None => {
                let entry = self.entry.as_ref().ok_or_else(|| {
                    eyre!("relays in [[mux]] need to specifify either an `id` or a `url`")
                })?;
                Ok(entry.id.as_str())
            }
        }
    }
}
