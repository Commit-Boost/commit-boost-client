use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use cb_common::{
    config::{MuxKeysLoader, PbsModuleConfig, load_pbs_config},
    constants::{COMMIT_BOOST_COMMIT, COMMIT_BOOST_VERSION},
    pbs::{BUILDER_V1_API_PATH, GET_STATUS_PATH},
    types::Chain,
};
use cb_metrics::provider::MetricsProvider;
use eyre::{Context, Result, bail};
use notify::{Error, Event, RecommendedWatcher, RecursiveMode, Watcher};
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

        let config_path = state.config_path.clone();
        let state: Arc<RwLock<PbsState<S>>> = RwLock::new(state).into();

        // Spawn WebSocket clients for relays with `websocket: true`.
        //
        // Per ARCH v3.2 §3.4, `auction_conclusion_ms` is derived from the
        // existing CB config and appended as a URL query param on upgrade
        // (not sent as a separate message).
        let ws_enabled_count = {
            let state_guard = state.read();
            let pbs = state_guard.pbs_config();
            let pbs_late_in_slot = pbs.late_in_slot_time_ms;
            let pbs_timeout_get_header = pbs.timeout_get_header_ms;
            let mut ws_map = state_guard.ws_clients.write();
            let mut count = 0u32;
            for relay in state_guard.all_relays().iter() {
                if !relay.config.websocket {
                    continue;
                }
                // Convert relay URL to ws:// scheme
                let mut ws_url = relay.config.entry.url.clone();
                let _ = ws_url.set_scheme("ws");
                ws_url.set_path("/eth/v1/builder/ws");

                let auction_conclusion_ms = if relay.config.enable_timing_games {
                    // target_first_request_ms + timeout_get_header_ms,
                    // capped at late_in_slot_time_ms so Phase B deadline
                    // arithmetic stays sane.
                    Some(
                        relay
                            .config
                            .target_first_request_ms
                            .map(|t| (t + pbs_timeout_get_header).min(pbs_late_in_slot))
                            .unwrap_or(pbs_late_in_slot),
                    )
                } else {
                    // No timing games: proposer accepts bids until
                    // `late_in_slot_time_ms`.
                    Some(pbs_late_in_slot)
                };

                info!(
                    relay_id = %relay.id,
                    url = %ws_url,
                    ?auction_conclusion_ms,
                    "spawning WebSocket client"
                );
                let client = crate::mev_boost::ws_client::HelixWsClient::spawn(
                    ws_url,
                    auction_conclusion_ms,
                );
                ws_map.insert(relay.id.to_string(), client);
                count += 1;
            }
            count
        };
        if ws_enabled_count > 0 {
            info!(ws_count = ws_enabled_count, "WebSocket clients spawned for relay(s)");
        } else {
            info!("no relays configured with websocket=true, using REST-only mode");
        }

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

        // Set up the filesystem watcher for the config file
        let mut watcher: RecommendedWatcher;
        if config_path.to_str() != Some("") {
            let state_for_watcher = state.clone();
            let config_path_for_watcher = config_path.clone();
            watcher = RecommendedWatcher::new(
                move |result: Result<Event, Error>| {
                    match result {
                        Err(e) => {
                            warn!(%e, "error watching PBS config file for changes");
                            return;
                        }
                        Ok(event) => {
                            if !event.kind.is_modify() {
                                return;
                            }
                        }
                    }

                    // Reload the configuration when the file is modified
                    info!("detected change in PBS config file, reloading configuration");
                    let result = futures::executor::block_on(load_pbs_config(Some(
                        config_path_for_watcher.to_path_buf(),
                    )));
                    match result {
                        Ok((new_config, _)) => {
                            let mut state = state_for_watcher.write();
                            state.config = Arc::new(new_config);
                            info!("configuration reloaded from file after update");
                        }
                        Err(err) => {
                            warn!(%err, "failed to reload configuration from file after update");
                        }
                    }
                },
                notify::Config::default(),
            )?;
            watcher.watch(config_path.as_path(), RecursiveMode::Recursive)?;
            info!("watching PBS config file for changes: {:?}", config_path);
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
                        default_pbs.ssv_node_api_url.clone(),
                        default_pbs.ssv_public_api_url.clone(),
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
