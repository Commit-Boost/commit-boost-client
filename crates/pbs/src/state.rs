use std::{path::PathBuf, sync::Arc};

use cb_common::{
    DEFAULT_REQUEST_TIMEOUT,
    config::{PbsConfig, PbsModuleConfig},
    pbs::{HEADER_VERSION_KEY, HEADER_VERSION_VALUE, RelayClient},
    types::BlsPublicKey,
};
use parking_lot::RwLock;
use reqwest::header::{HeaderMap, HeaderValue};

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
    /// Path of the config file, for watching changes
    pub config_path: Arc<PathBuf>,
    /// One process-wide HTTP client the ePBS transient pipe reuses across
    /// dials. Configured relays build their client once at load; the pipe
    /// would otherwise pay a cold client (pool + TLS) build on every
    /// request, so it shares this one instead. Cloning a `reqwest::Client`
    /// is a cheap Arc bump.
    pub pipe_client: reqwest::Client,
    /// Opaque extra data for library use
    pub data: S,
}

/// Builds the shared pipe client the same way [`RelayClient::new`] builds its
/// own: the CommitBoost version header as a default header and the shared
/// request timeout.
fn build_pipe_client() -> reqwest::Client {
    let mut headers = HeaderMap::new();
    headers.insert(HEADER_VERSION_KEY, HeaderValue::from_static(HEADER_VERSION_VALUE));
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(DEFAULT_REQUEST_TIMEOUT)
        .build()
        .expect("a static default header and timeout always build a valid reqwest client")
}

impl PbsState<()> {
    pub fn new(config: PbsModuleConfig, config_path: PathBuf) -> Self {
        Self {
            config: Arc::new(config),
            config_path: Arc::new(config_path),
            pipe_client: build_pipe_client(),
            data: (),
        }
    }

    pub fn with_data<S: BuilderApiState>(self, data: S) -> PbsState<S> {
        PbsState {
            data,
            config: self.config,
            config_path: self.config_path,
            pipe_client: self.pipe_client,
        }
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
