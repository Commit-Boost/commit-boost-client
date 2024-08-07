# Commit-Boost

A new Ethereum validator sidecar focused on standardizing the last mile of communication between validators and third-party protocols.

[Docs](https://commit-boost.github.io/commit-boost-client/) |
[Twitter](https://x.com/Commit_Boost)

## Overview
Commit-Boost is a modular sidecar that allows Ethereum validators to opt-in to different commitment protocols

### For node operators
- Run a single sidecar with support for MEV-Boost and other proposer commitments protocols, such as preconfirmations and inclusion lists
- Out-of-the-box support for metrics reporting and dashboards to have clear insight into what is happening in your validator
- Plug-in system to add custom modules, e.g. receive a notification on Telegram if a relay fails to deliver a block

For more information on how to run Commit-Boost, check out our [docs](https://commit-boost.github.io/commit-boost-client/get_started/overview).

### For developers
- A modular platform to develop and distribute proposer commitments protocols
- A single API to interact with validators
- Support for hard-forks and new protocol requirements

For more information on how to develop a module on Commit-Boost, check out our [docs](https://commit-boost.github.io/commit-boost-client/category/developing).

### Example
> **_NOTE:_**  The code is unaudited and NOT ready for production. All APIs are subject to change

A basic commit module with Commit-Boost.

Add the `commit-boost` crate to your `Cargo.toml`:

```toml
commit-boost = { git = "https://github.com/Commit-Boost/commit-boost-client", rev = "..." }
```

Then in `main.rs`:

```rust
use commit_boost::prelude::*;

#[derive(Debug, TreeHash)]
struct Datagram {
    data: u64,
}

#[tokio::main]
async fn main() {
    let config = load_commit_module_config::<()>().unwrap();
    let pubkeys = config.signer_client.get_pubkeys().await.unwrap();

    let pubkey = *pubkeys.consensus.first().unwrap();

    let datagram = Datagram { data: 42 };
    let request = SignRequest::builder(pubkey).with_msg(&datagram);
    let signature = config
        .signer_client
        .request_signature(&request)
        .await
        .unwrap();

    println!("Data: {datagram:?} - Commitment: {signature}");
}
```

Finally, create a Docker image with your binary, e.g. `my_commit_module`, and add it to the `cb-config.toml` file:

```toml
[[modules]]
id = "MY_MODULE"
docker_image = "my_commit_module"
```

For a more detailed example check out [here](/examples/da_commit) and our docs on how to [setup Commit-Boost](https://commit-boost.github.io/commit-boost-client/get_started/overview) for development.

## Acknowledgements
- [MEV boost](https://github.com/flashbots/mev-boost)
- [Reth](https://github.com/paradigmxyz/reth)
- [Lighthouse](https://github.com/sigp/lighthouse)

## License
MIT + Apache-2.0
