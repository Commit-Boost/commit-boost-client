use std::{path::PathBuf, sync::Arc};

use cb_common::{
    config::{PbsConfig, PbsModuleConfig},
    pbs::RelayClient,
    types::BlsPublicKey,
};
use parking_lot::RwLock;

pub type PbsStateGuard = Arc<RwLock<PbsState>>;

/// Config for the Pbs module.
#[derive(Clone)]
pub struct PbsState {
    /// Config data for the Pbs service
    pub config: Arc<PbsModuleConfig>,
    /// Path of the config file, for watching changes
    pub config_path: Arc<PathBuf>,
}

impl PbsState {
    pub fn new(config: PbsModuleConfig, config_path: PathBuf) -> Self {
        Self { config: Arc::new(config), config_path: Arc::new(config_path) }
    }

    pub fn pbs_config(&self) -> &PbsConfig {
        &self.config.pbs_config
    }

    /// Returns all the relays (including those in muxes)
    /// DO NOT use this through the PBS module, use
    /// [`PbsState::mux_config_and_relays`] instead
    pub fn all_relays(&self) -> &[RelayClient] {
        &self.config.all_relays
    }

    /// Returns the PBS config and relay clients for the given validator pubkey.
    /// If the pubkey is not found in any mux, the default configs are
    /// returned
    pub fn mux_config_and_relays(
        &self,
        pubkey: &BlsPublicKey,
    ) -> (&PbsConfig, &[RelayClient], Option<&str>) {
        match self.config.mux_lookup.as_ref().and_then(|muxes| muxes.get(pubkey)) {
            Some(mux) => (&mux.config, mux.relays.as_slice(), Some(&mux.id)),
            // return only the default relays if there's no match
            None => (self.pbs_config(), &self.config.relays, None),
        }
    }
}
