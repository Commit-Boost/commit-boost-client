use cb_common::config::load_pbs_config;
use tracing::warn;

use crate::{BuilderApiState, PbsState};

/// Reload the PBS state with the latest configuration in the config file
/// Returns 200 if successful or 500 if failed
pub async fn reload<S: BuilderApiState>(state: PbsState<S>) -> eyre::Result<PbsState<S>> {
    let (pbs_config, config_path) = load_pbs_config(None).await?;
    let new_state = PbsState::new(pbs_config, config_path).with_data(state.data);

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
