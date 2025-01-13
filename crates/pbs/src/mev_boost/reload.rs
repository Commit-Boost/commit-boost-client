use cb_common::config::load_pbs_config;

use crate::{BuilderApiState, InnerPbsState, PbsState};

/// Reload the PBS state with the latest configuration in the config file
/// Returns 200 if successful or 500 if failed
pub async fn reload<S: BuilderApiState>(state: PbsState<S>) -> eyre::Result<()> {
    let pbs_config = load_pbs_config().await?;
    let new_state = InnerPbsState::new(pbs_config).with_data(state.inner.read().await.data.clone());

    *state.inner.write().await = new_state;

    Ok(())
}
