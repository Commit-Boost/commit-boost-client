use std::{collections::HashSet, future::Future, marker::PhantomData};

use alloy_rpc_types_beacon::BlsPublicKey;
use cb_crypto::{
    manager::{Signer, SigningManager},
    service::SigningService,
    types::SignRequest,
};
use cb_pbs::{
    BuilderApi, BuilderApiState, BuilderEvent, BuilderState, DefaultBuilderApi, PbsService,
};
use tokio::sync::{
    broadcast,
    mpsc::{self, unbounded_channel, UnboundedSender},
};

pub type SignRequestSender = mpsc::UnboundedSender<SignRequest>;

pub struct Runner<S: BuilderApiState = (), T: BuilderApi<S> = DefaultBuilderApi> {
    state: BuilderState<S>,
    commit_ids: HashSet<String>,
    hooks_ids: HashSet<String>,
    sign_manager: SigningManager,

    notif_tx: SignRequestSender,
    notif_rx: mpsc::UnboundedReceiver<SignRequest>,
    _marker: PhantomData<T>,
}

impl<S: BuilderApiState, T: BuilderApi<S>> Runner<S, T> {
    pub fn new(state: BuilderState<S>) -> Self {
        let (notif_tx, notif_rx) = unbounded_channel();

        // TODO: move this in run + spawn only if needed
        let mut sign_manager = SigningManager::new(state.chain);
        sign_manager.add_consensus_signer(Signer::new_random());

        Self {
            state,
            commit_ids: HashSet::new(),
            hooks_ids: HashSet::new(),
            sign_manager,
            notif_tx,
            notif_rx,
            _marker: PhantomData,
        }
    }

    pub fn add_commitment<F, R>(&mut self, commit_id: impl Into<String>, commitment: F)
    where
        F: FnOnce(UnboundedSender<SignRequest>, Vec<BlsPublicKey>) -> R + 'static,
        R: Future<Output = eyre::Result<()>> + Send + 'static,
    {
        let id = commit_id.into();

        if !self.commit_ids.insert(id.clone()) {
            eprintln!("Commitments ids need to be unique, found duplicate: {id}");
            std::process::exit(1);
        }

        // move to vector and spawn after signing service
        tokio::spawn(commitment(self.notif_tx.clone(), self.sign_manager.consensus_pubkeys()));
    }

    pub fn add_boost_hook<F, R>(&mut self, hook_id: impl Into<String>, hook: F)
    where
        F: FnOnce(broadcast::Receiver<BuilderEvent>) -> R + 'static,
        R: Future<Output = eyre::Result<()>> + Send + 'static,
    {
        let id = hook_id.into();

        if !self.hooks_ids.insert(id.clone()) {
            eprintln!("Hook ids need to be unique, found duplicate: {id}");
            std::process::exit(1);
        }

        // move to vector and spawn after signing service
        tokio::spawn(hook(self.state.subscribe_events()));
    }

    pub async fn run(self) -> eyre::Result<()> {
        // start signature service
        if !self.commit_ids.is_empty() {
            let sign_service = SigningService::new(self.sign_manager, self.notif_rx);
            tokio::spawn(sign_service.run());
        }

        // TODO: start commitments and hooks here

        // start boost service
        PbsService::run::<S, T>(self.state).await;

        Ok(())
    }
}
