use axum::{extract::State, http::HeaderMap, response::IntoResponse};
use cb_common::{config::load_pbs_config, utils::get_user_agent};
use reqwest::StatusCode;
use tracing::{error, info, warn};

use crate::{
    RELOAD_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{PbsState, PbsStateGuard},
};

pub async fn handle_reload(
    req_headers: HeaderMap,
    State(state): State<PbsStateGuard>,
) -> Result<impl IntoResponse, PbsClientError> {
    let prev_state = state.read().clone();

    let ua = get_user_agent(&req_headers);

    info!(ua, relay_check = prev_state.config.pbs_config.relay_check);

    match reload(prev_state).await {
        Ok(new_state) => {
            info!("config reload successful");

            *state.write() = new_state;

            BEACON_NODE_STATUS.with_label_values(&["200", RELOAD_ENDPOINT_TAG]).inc();
            Ok((StatusCode::OK, "OK"))
        }
        Err(err) => {
            error!(%err, "config reload failed");

            let err = PbsClientError::Internal;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), RELOAD_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}

// ── Relay logic ──────────────────────────────────────────────────────────────

/// Reload the PBS state with the latest configuration in the config file
/// Returns 200 if successful or 500 if failed
pub(crate) async fn reload(state: PbsState) -> eyre::Result<PbsState> {
    let (pbs_config, config_path) = load_pbs_config(None).await?;
    let new_state = PbsState::new(pbs_config, config_path);

    if state.config.pbs_config.host != new_state.config.pbs_config.host {
        warn!(
            "Host change for PBS module require a full restart. Old: {}, New: {}",
            state.config.pbs_config.host, new_state.config.pbs_config.host
        );
    }

    if state.config.pbs_config.port != new_state.config.pbs_config.port {
        warn!(
            "Port change for PBS module require a full restart. Old: {}, New: {}",
            state.config.pbs_config.port, new_state.config.pbs_config.port
        );
    }

    Ok(new_state)
}
