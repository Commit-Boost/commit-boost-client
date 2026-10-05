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

/// Redirects are refused: the pipe dials a URL taken from untrusted auth data,
/// and the SSRF guard in `transient_pipe_relay` validates only the first hop,
/// so a 3xx into loopback or link-local space would slip straight past it.
fn build_pipe_client() -> reqwest::Client {
    let mut headers = HeaderMap::new();
    headers.insert(HEADER_VERSION_KEY, HeaderValue::from_static(HEADER_VERSION_VALUE));
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(DEFAULT_REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
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

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use axum::{Router, http::StatusCode, response::IntoResponse, routing::post};
    use tokio::net::TcpListener;

    use super::build_pipe_client;

    /// A 3xx from a pipe target must not be followed. The SSRF guard validates
    /// only the first hop, so following one would let an allowed public host
    /// redirect CB into loopback or link-local space.
    #[tokio::test]
    async fn pipe_client_does_not_follow_redirects() -> eyre::Result<()> {
        // The target a redirect would reach; records whether it was ever dialed.
        let reached = Arc::new(AtomicBool::new(false));
        let internal_listener = TcpListener::bind("127.0.0.1:0").await?;
        let internal_addr = internal_listener.local_addr()?;
        let flag = reached.clone();
        let internal = Router::new().route(
            "/internal",
            post(move || {
                let flag = flag.clone();
                async move {
                    flag.store(true, Ordering::SeqCst);
                    StatusCode::OK.into_response()
                }
            }),
        );
        tokio::spawn(async move { axum::serve(internal_listener, internal).await });

        let redirect_listener = TcpListener::bind("127.0.0.1:0").await?;
        let redirect_addr = redirect_listener.local_addr()?;
        let location = format!("http://{internal_addr}/internal");
        let redirector = Router::new().route(
            "/bid",
            post(move || {
                let location = location.clone();
                async move {
                    (StatusCode::TEMPORARY_REDIRECT, [(axum::http::header::LOCATION, location)])
                        .into_response()
                }
            }),
        );
        tokio::spawn(async move { axum::serve(redirect_listener, redirector).await });

        let res = build_pipe_client().post(format!("http://{redirect_addr}/bid")).send().await?;

        assert_eq!(
            res.status(),
            StatusCode::TEMPORARY_REDIRECT,
            "the 3xx must surface to the caller, not be followed"
        );
        assert!(!reached.load(Ordering::SeqCst), "the redirect target must never be dialed");
        Ok(())
    }
}
