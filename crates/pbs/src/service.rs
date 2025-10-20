use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use cb_common::{
    config::{MuxKeysLoader, PbsModuleConfig},
    constants::{COMMIT_BOOST_COMMIT, COMMIT_BOOST_VERSION},
    pbs::{BUILDER_V1_API_PATH, GET_STATUS_PATH},
    types::Chain,
};
use cb_metrics::provider::MetricsProvider;
use eyre::{Context, Result, bail};
use parking_lot::RwLock;
use prometheus::core::Collector;
use tokio::net::TcpListener;
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
        let is_refreshing_required = state.config.registry_muxes.as_ref().is_some_and(|muxes| {
            muxes.iter().any(|(loader, _)| {
                matches!(loader, MuxKeysLoader::Registry { enable_refreshing: true, .. })
            })
        });

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
            let state = state.clone();
            tokio::spawn(async move {
                let mut is_first_tick = true;
                loop {
                    interval.tick().await;
                    if is_first_tick {
                        // Don't run immediately on the first tick, since it was just initialized
                        is_first_tick = false;
                        continue;
                    }
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
        let mut removed_pubkeys = HashSet::new();
        {
            let state = state.read().clone();
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
                        let mut pubkey_set = HashSet::new();
                        for pubkey in pubkeys {
                            pubkey_set.insert(pubkey.clone());
                            if mux_lookup.get(&pubkey).is_none() {
                                // New pubkey
                                new_pubkeys.insert(pubkey.clone(), runtime_config.clone());
                            }
                        }

                        // Find any pubkeys that were removed
                        for (pubkey, existing_runtime) in mux_lookup.iter() {
                            if existing_runtime.id == runtime_config.id &&
                                !pubkey_set.contains(pubkey)
                            {
                                removed_pubkeys.insert(pubkey.clone());
                            }
                        }
                    }
                    Err(err) => {
                        warn!(%err, "failed to refresh pubkeys for registry mux {}", runtime_config.id);
                    }
                }
            }
        }

        // Report changes
        let mut no_new_changes = true;
        if !new_pubkeys.is_empty() {
            no_new_changes = false;
            info!("discovered {} new pubkeys from registries", new_pubkeys.len());
        }
        if !removed_pubkeys.is_empty() {
            no_new_changes = false;
            info!("registries have removed {} old pubkeys", removed_pubkeys.len());
        }

        // Write portion
        if no_new_changes {
            return;
        }
        {
            // Since config isn't an RwLock, the option with the least amount of code churn
            // is to just clone the whole config and replace the mux_lookup
            // field. Cloning the config may be expensive, but this should be a fairly rare
            // operation.
            let mut state = state.write();
            let config = state.config.as_ref();
            let new_mux_lookup = if let Some(existing) = &config.mux_lookup {
                let mut map = HashMap::new();
                for (k, v) in existing.iter() {
                    if !removed_pubkeys.contains(k) {
                        map.insert(k.clone(), v.clone());
                    }
                }
                map.extend(new_pubkeys);
                map
            } else {
                new_pubkeys
            };
            state.config =
                Arc::new(PbsModuleConfig { mux_lookup: Some(new_mux_lookup), ..config.clone() });
        }
    }
}
