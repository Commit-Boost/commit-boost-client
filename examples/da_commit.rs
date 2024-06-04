//! Example on how to spin up a commit service to request arbitrary signatures from the proposer

use std::time::Duration;

use alloy_rpc_types_beacon::BlsPublicKey;
use cb_cli::runner::{Runner, SignRequestSender};
use cb_common::utils::initialize_tracing_log;
use cb_crypto::types::SignRequest;
use cb_pbs::{BuilderState, DefaultBuilderApi};
use clap::Parser;
use tokio::time::sleep;
use tree_hash_derive::TreeHash;

// This is what the proposer will sign, it needs to derive TreeHash (i.e. it needs to be encoded as
// SSZ). The proposer will the hash root of the message in the builder domain
#[derive(TreeHash)]
struct Datagram {
    data: u64,
}

const COMMIT_ID: &str = "DA_SERVICE";

/// The entrypoint of the commit service is an async function/closure.
/// With the `SignRequestSender` channel you can send arbitrary signature request to the
/// SigningService. Each `SignRequests` needs to specify:
/// - an service ID (this will be used for telemetry purposes)
/// - the validator pubkey for which the request needs to be signed
/// - the message to be signed
async fn run_da_commit_service(
    tx: SignRequestSender,
    pubkeys: Vec<BlsPublicKey>,
) -> eyre::Result<()> {
    let mut data = 0;
    let validator_pubkey = pubkeys[0];

    loop {
        let msg = Datagram { data };

        let (request, sign_rx) = SignRequest::new(COMMIT_ID, validator_pubkey, msg);

        tx.send(request).expect("failed sending request");

        match sign_rx.await {
            Ok(Ok(sig)) => println!("Signed data blob: {sig}"),
            Ok(Err(err)) => eprintln!("Sign error: {err:?}"),
            Err(err) => eprintln!("Sign manager is down: {err:?}"),
        }

        data += 1;

        sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::main]
async fn main() {
    initialize_tracing_log();

    let (chain, config) = cb_cli::Args::parse().to_config();

    let state = BuilderState::new(chain, config);
    let mut runner = Runner::<(), DefaultBuilderApi>::new(state);

    runner.add_commitment(COMMIT_ID, run_da_commit_service);

    if let Err(err) = runner.run().await {
        eprintln!("Error: {err}");
        std::process::exit(1)
    };
}
