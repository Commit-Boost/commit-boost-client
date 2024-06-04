use alloy_rpc_types_beacon::BlsPublicKey;
use tokio::sync::mpsc;
use tracing::error;

use crate::{manager::SigningManager, types::SignRequest};

pub struct SigningService {
    manager: SigningManager,
    sig_req_rx: mpsc::UnboundedReceiver<SignRequest>,
}

impl SigningService {
    pub fn new(manager: SigningManager, sig_req_rx: mpsc::UnboundedReceiver<SignRequest>) -> Self {
        Self { manager, sig_req_rx }
    }

    pub async fn pubkey(&self) -> Vec<BlsPublicKey> {
        self.manager.consensus_pubkeys()
    }

    pub async fn run(mut self) {
        while let Some(req) = self.sig_req_rx.recv().await {
            let maybe_sig = if req.is_proxy {
                self.manager.sign_proxy(&req.pubkey, &req.msg).await
            } else {
                self.manager.sign_consensus(&req.pubkey, &req.msg).await
            };

            // ignore error if client dropped
            let _ = req.ans.send(maybe_sig.map_err(|err| err.into()));
        }

        error!("Exiting signing service")
    }
}
