use std::sync::Arc;

use alloy::rpc::types::beacon::BlsPublicKey;
use cb_common::{
    config::{PbsConfig, PbsModuleConfig},
    pbs::{BuilderEvent, RelayClient},
};
use tokio::sync::RwLock;

pub trait BuilderApiState: Clone + Sync + Send + 'static {}
impl BuilderApiState for () {}

#[derive(Clone)]
pub struct PbsState<S: BuilderApiState = ()> {
    pub inner: Arc<RwLock<InnerPbsState<S>>>,
}

impl<S> PbsState<S>
where
    S: BuilderApiState,
{
    pub fn new(state: InnerPbsState<S>) -> Self {
        Self { inner: Arc::new(RwLock::new(state)) }
    }
}

/// Config for the Pbs module. It can be extended by adding extra data to the
/// state for modules that need it
// TODO: consider remove state from the PBS module altogether
#[derive(Clone)]
pub struct InnerPbsState<S: BuilderApiState = ()> {
    /// Config data for the Pbs service
    pub config: PbsModuleConfig,
    /// Opaque extra data for library use
    pub data: S,
}

impl InnerPbsState<()> {
    pub fn new(config: PbsModuleConfig) -> Self {
        Self { config, data: () }
    }

    pub fn with_data<S: BuilderApiState>(self, data: S) -> InnerPbsState<S> {
        InnerPbsState { data, config: self.config }
    }
}

impl<S> InnerPbsState<S>
where
    S: BuilderApiState,
{
    pub fn publish_event(&self, e: BuilderEvent) {
        if let Some(publisher) = self.config.event_publisher.as_ref() {
            publisher.publish(e);
        }
    }

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
        match self.config.muxes.as_ref().and_then(|muxes| muxes.get(pubkey)) {
            Some(mux) => (&mux.config, mux.relays.as_slice(), Some(&mux.id)),
            // return only the default relays if there's no match
            None => (self.pbs_config(), &self.config.relays, None),
        }
    }

    pub fn has_monitors(&self) -> bool {
        !self.config.pbs_config.relay_monitors.is_empty()
    }

    pub fn extra_validation_enabled(&self) -> bool {
        self.config.pbs_config.extra_validation_enabled
    }
}
