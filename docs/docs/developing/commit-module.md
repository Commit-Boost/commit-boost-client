---
sidebar_position: 2
---

# Commit Module

While a module can be written in any language, we currently provide some utilities for Rust, with the goal of supporting more generalized APIs and simplify development in languages other than Rust.

In Rust, we provide utilities to load and run modules. Simply add to your `Cargo.toml`:
```toml
commit-boost = { git = "https://github.com/Commit-Boost/commit-boost-client", version = "..." }
```

You will now be able to import the utils with:
```rust
use commit_boost::prelude::*;
```


## Config
Your module will likely need a configuration for the Node Operator to customize. This will have to be in the `cb-config.toml` file, in the correct `[[module]]` section. In the module, you can define and load your config as follows.

First, define all the parameters needed in a struct:
```rust
#[derive(Debug, Deserialize)]
struct ExtraConfig {
    sleep_secs: u64,
}
```
then pass that struct to the `load_commit_module_config` function, which will load and parse the config. Your custom config will be under the `extra` field.

```rust
let config = load_commit_module_config::<ExtraConfig>().unwrap();
let to_sleep = config.extra.sleep_secs;
```

The loaded `config` also has a few other useful fields:
- the unique `id` of the module
- chain spec
- a `SignerClient` to call the [SignerAPI](/api), already setup with the correct JWT


## Requesting signatures
At its core the Signer Module simply provides a signature on a 32-byte data digest. The signatures are currently provided with either the validator keys (BLS) or a proxy key (BLS or ECDSA) for a given validator key, both on the [builder domain](https://github.com/Commit-Boost/commit-boost-client/blob/main/crates/common/src/signature.rs#L88-L96).

In the example we use `TreeHash`, already used in the CL, to create the digest from a custom struct:
```rust
#[derive(TreeHash)]
struct Datagram {
    data: u64,
}
```

Furthermore, in order to request a signature, we'd need a public key of the validator. You can get a list of available keys by calling:
```rust
let pubkeys = config.signer_client.get_pubkeys().await.unwrap();
```

Which will call the `get_pubkeys` endpoint of the [SignerAPI](/api), returning all the consensus pubkeys and the corresponding proxy keys, of your module.

Note that the requests are authenticated using a JWT, that must be regularly refreshed as it expires after a certain time. To do so, you can call:
```rust
config.signer_client.refresh_token().await.unwrap();
```
You have the `SIGNER_JWT_EXPIRATION` constant available in the `commit-boost` crate, which is the time in seconds after which the JWT will expire.

Then, we can request a signature either with a consensus key or with a proxy key:

### With a consensus key
Requesting a signature is as simple as:
```rust
let datagram = Datagram { data: 1 };
let request = SignConsensusRequest::builder(pubkey).with_msg(&datagram);
let signature = config.signer_client.request_consensus_signature(&request).await.unwrap();
```

Where `pubkey` is the validator (consensus) public key for which the signature is requested.

### With a proxy key
You'll have to first request a proxy key be generated for a given consensus key.
We support two signature schemes for proxies: BLS or ECDSA.

To request a proxy:
```rust
// BLS proxy
let proxy_delegation = self.config.signer_client.generate_proxy_key_bls(pubkey).await?;
let proxy_pubkey = proxy_delegation.message.proxy;

// or ECDSA proxy
let proxy_delegation = self.config.signer_client.generate_proxy_key_ecdsa(pubkey).await?;
let proxy_pubkey = proxy_delegation.message.proxy;
```

Where `pubkey` is the validator (consensus) public key for which a proxy is to be generated.

Then you can use the generated proxy key to request a signature:
```rust
let datagram = Datagram { data: 1 };
let request = SignProxyRequest::builder(proxy_pubkey).with_msg(&datagram);
// if `proxy_pubkey` is a BLS proxy
let signature = config.signer_client.request_proxy_signature_bls(&request).await.unwrap();
// or for ECDSA proxy
let signature = config.signer_client.request_proxy_signature_ecdsa(&request).await.unwrap();
```

## Metrics
We provide support for modules to record custom metrics which are automatically scraped by Prometheus. This involves three steps
### Define metrics
You can use the `prometheus` crate to create a custom registry and metrics, for example:

```rust
static ref MY_CUSTOM_REGISTRY: Registry = Registry::new_custom(Some("da_commit".to_string()), None).unwrap();
static ref SIG_RECEIVED_COUNTER: IntCounter = IntCounter::new("signature_received", "successful signature requests received").unwrap();
```

### Start Metrics Provider
When starting the module, you should register all metrics, and start the `MetricsProvider`:
```rust
MY_CUSTOM_REGISTRY.register(Box::new(SIG_RECEIVED_COUNTER.clone())).unwrap();
MetricsProvider::load_and_run(MY_CUSTOM_REGISTRY.clone());
```
The `MetricsProvider` will load the configuration needed and start a server with a `/metrics` endpoint for Prometheus to scrape.

### Record metrics
All that is left is to use the metrics throughout your code:
```rust
SIG_RECEIVED_COUNTER.inc();
```
These will be automatically scraped by the Prometheus service running, and exposed on port `9090`. We plan to allow developers to ship pre-made dashboards together with their modules, to allow Node Operators to have an improved oversight on the modules they are running.
