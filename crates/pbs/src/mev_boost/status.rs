use std::time::Duration;

use cb_common::pbs::RelayEntry;
use futures::future::select_ok;

use crate::{
    error::PbsError,
    state::{BuilderApiState, PbsState},
};

pub async fn get_status<S: BuilderApiState>(pbs_state: PbsState<S>) -> eyre::Result<()> {
    if !pbs_state.config.pbs_config.relay_check {
        Ok(())
    } else {
        let relays = pbs_state.relays();
        let mut handles = Vec::with_capacity(relays.len());

        for relay in relays {
            handles.push(Box::pin(send_relay_check(relay.clone())));
        }

        let results = select_ok(handles).await;

        match results {
            Ok(_) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

async fn send_relay_check(relay: RelayEntry) -> Result<(), PbsError> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap();
    let url = relay.get_status_url();

    let res = client.get(url).send().await?;

    let status = res.status();
    let response_bytes = res.bytes().await?;

    if !status.is_success() {
        return Err(PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: status.as_u16(),
        })
    };

    Ok(())
}
