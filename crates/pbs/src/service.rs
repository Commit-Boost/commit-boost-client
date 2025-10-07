use std::{collections::HashMap, sync::Arc, time::Duration};

use cb_common::{
    config::{MuxKeysLoader, PbsModuleConfig},
    constants::{COMMIT_BOOST_COMMIT, COMMIT_BOOST_VERSION},
    pbs::{BUILDER_V1_API_PATH, GET_STATUS_PATH},
    types::Chain,
};
use cb_metrics::provider::MetricsProvider;
use eyre::{Context, Result, bail};
use prometheus::core::Collector;
use tokio::{net::TcpListener, sync::RwLock};
use tracing::{debug, info, warn};
use url::Url;

use crate::{
    api::BuilderApi,
    metrics::PBS_METRICS_REGISTRY,
    routes::create_app_router,
    state::{BuilderApiState, PbsState, PbsStateGuard},
};

pub struct PbsService;

impl PbsService {
    pub async fn run<S: BuilderApiState, A: BuilderApi<S>>(state: PbsState<S>) -> Result<()> {
        let addr = state.config.endpoint;
        info!(version = COMMIT_BOOST_VERSION, commit_hash = COMMIT_BOOST_COMMIT, ?addr, chain =? state.config.chain, "starting PBS service");

        // Check if refreshing registry muxes is required
        let registry_refresh_time = state.config.pbs_config.mux_registry_refresh_interval_seconds;
        let mut is_refreshing_required = false;
        if state.config.pbs_config.mux_registry_refresh_interval_seconds == 0 {
            info!("registry mux refreshing interval is 0; refreshing is disabled");
        } else if let Some(muxes) = &state.config.registry_muxes {
            is_refreshing_required = muxes.iter().any(|(loader, _)| {
                matches!(loader, MuxKeysLoader::Registry { enable_refreshing: true, .. })
            });
        }

        let state: Arc<RwLock<PbsState<S>>> = RwLock::new(state).into();
        let app = create_app_router::<S, A>(state.clone());
        let listener = TcpListener::bind(addr).await?;

        let task =
            tokio::spawn(
                async move { axum::serve(listener, app).await.wrap_err("PBS server exited") },
            );

        // wait for the server to start
        tokio::time::sleep(Duration::from_millis(250)).await;
        let local_url =
            Url::parse(&format!("http://{addr}{BUILDER_V1_API_PATH}{GET_STATUS_PATH}"))?;

        let status = reqwest::get(local_url).await?;
        if !status.status().is_success() {
            bail!("PBS server failed to start. Are the relays properly configured?");
        }

        // Run the registry refresher task
        if is_refreshing_required {
            let mut interval = tokio::time::interval(Duration::from_secs(registry_refresh_time));
            tokio::spawn(async move {
                loop {
                    interval.tick().await;
                    Self::refresh_registry_muxes(state.clone()).await;
                }
            });
        }

        task.await?
    }

    pub fn register_metric(c: Box<dyn Collector>) {
        PBS_METRICS_REGISTRY.register(c).expect("failed to register metric");
    }

    pub fn init_metrics(network: Chain) -> Result<()> {
        MetricsProvider::load_and_run(network, PBS_METRICS_REGISTRY.clone())
    }

    async fn refresh_registry_muxes<S: BuilderApiState>(state: PbsStateGuard<S>) {
        // Read-only portion
        let mut new_pubkeys = HashMap::new();
        {
            let state = state.read().await;
            let config = &state.config;

            // Short circuit if there aren't any registry muxes with dynamic refreshing
            let registry_muxes = match &config.registry_muxes {
                Some(muxes) => muxes,
                None => return,
            };

            // Initialize an empty lookup if the config doesn't have one yet
            let mux_lookup = match &config.mux_lookup {
                Some(lookup) => lookup,
                None => &HashMap::new(),
            };

            // Go through each registry mux and refresh its pubkeys
            let default_pbs = &config.pbs_config;
            let http_timeout = Duration::from_secs(default_pbs.http_timeout_seconds);
            for (loader, runtime_config) in registry_muxes.iter() {
                debug!("refreshing pubkeys for registry mux {}", runtime_config.id);
                match loader
                    .load(
                        &runtime_config.id,
                        config.chain,
                        default_pbs.ssv_api_url.clone(),
                        default_pbs.rpc_url.clone(),
                        http_timeout,
                    )
                    .await
                {
                    Ok(pubkeys) => {
                        debug!(
                            "fetched {} pubkeys for registry mux {}",
                            pubkeys.len(),
                            runtime_config.id
                        );

                        // Add any new pubkeys to the new lookup table
                        for pubkey in pubkeys {
                            if mux_lookup.get(&pubkey).is_none() {
                                new_pubkeys.insert(pubkey, runtime_config.clone());
                            }
                        }
                    }
                    Err(err) => {
                        warn!(%err, "failed to refresh pubkeys for registry mux {}", runtime_config.id);
                    }
                }
            }
        }

        // Write portion
        if new_pubkeys.is_empty() {
            return;
        }
        // Log the new pubkeys
        for (pubkey, runtime_config) in new_pubkeys.iter() {
            info!("adding new pubkey {pubkey} to mux {}", runtime_config.id);
        }
        {
            // Since config isn't an RwLock, the option with the least amount of code churn
            // is to just clone the whole config and replace the mux_lookup
            // field. Cloning the config may be expensive, but this should be a fairly rare
            // operation.
            let mut state = state.write().await;
            let config = state.config.as_ref();
            let new_mux_lookup = match &config.mux_lookup {
                Some(existing) => {
                    new_pubkeys.extend(existing.iter().map(|(k, v)| (k.clone(), v.clone())));
                    new_pubkeys
                }
                None => new_pubkeys,
            };
            state.config =
                Arc::new(PbsModuleConfig { mux_lookup: Some(new_mux_lookup), ..config.clone() });
        }
    }
}
