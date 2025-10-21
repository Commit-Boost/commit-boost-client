use std::sync::Arc;

use cb_common::{
    config::{PbsConfig, PbsModuleConfig},
    pbs::RelayClient,
    types::BlsPublicKey,
};
use parking_lot::RwLock;

pub trait BuilderApiState: Clone + Sync + Send + 'static {}
impl BuilderApiState for () {}

pub type PbsStateGuard<S> = Arc<RwLock<PbsState<S>>>;

/// Config for the Pbs module. It can be extended by adding extra data to the
/// state for modules that need it
// TODO: consider remove state from the PBS module altogether
#[derive(Clone)]
pub struct PbsState<S: BuilderApiState = ()> {
    /// Config data for the Pbs service
    pub config: Arc<PbsModuleConfig>,
    /// Opaque extra data for library use
    pub data: S,
}

impl PbsState<()> {
    pub fn new(config: PbsModuleConfig) -> Self {
        Self { config: Arc::new(config), data: () }
    }

    pub fn with_data<S: BuilderApiState>(self, data: S) -> PbsState<S> {
        PbsState { data, config: self.config }
    }
}

impl<S> PbsState<S>
where
    S: BuilderApiState,
{
    // Getters
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

    pub fn extra_validation_enabled(&self) -> bool {
        self.config.pbs_config.extra_validation_enabled
    }
}
