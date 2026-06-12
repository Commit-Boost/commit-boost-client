---
sidebar_position: 1
---

# Commit Modules

Commit-Boost provides an open platform for developers to create and distribute commitment protocol sidecars. **Commit Modules** are the primary way to add custom logic — they run as sidecar processes alongside the PBS and Signer services, and can request signatures from the proposer.

> **For system context**, see the [Architecture Overview](../architecture/overview.md).

## Config entry

Each commit module is declared in the `cb-config.toml` file under a `[[modules]]` entry:

```toml
[[modules]]
id = "DA_COMMIT"
type = "commit"
docker_image = "my-module-image"
signing_id = "0x6a33a23ef26a4836979edff86c493a69b26ccf0b4a16491a815a13787657431b"
```

| Field | Description |
|---|---|
| `id` | A unique identifier for the module (used for JWT scoping and container naming). |
| `type` | **Must be `"commit"`.** This is the only valid value. |
| `docker_image` | The Docker image to run for this module. |
| `signing_id` | A 32-byte identifier used to scope signatures to this module (see [Signing structure](#signing-structure)). |
| (custom) | Additional fields are passed through as opaque config to the module's runtime. |

:::warning
Setting `type = "pbs"` in a `[[modules]]` entry is **not** a supported path. The configuration parser will reject it at parse time. If you want to extend the PBS binary itself, see [Extending PBS](./extending-pbs.md).
:::



## Rust SDK usage

While a module can be written in any language, we provide Rust utilities to simplify loading and running modules. Add to your `Cargo.toml`:

```toml
commit-boost = { git = "https://github.com/Commit-Boost/commit-boost-client", version = "..." }
```

Import the prelude:

```rust
use commit_boost::prelude::*;
```

### Loading module config

Your module will likely need a configuration section for the Node Operator to customize. Define it as a struct and pass it to `load_commit_module_config`:

```rust
#[derive(Debug, Deserialize)]
struct ExtraConfig {
    sleep_secs: u64,
}

let config = load_commit_module_config::<ExtraConfig>().unwrap();
let to_sleep = config.extra.sleep_secs;
```

The returned `StartCommitModuleConfig` also provides:
- `id` — unique module ID
- `chain` — chain spec
- `signer_client` — a pre-configured `SignerClient` to call the [SignerAPI](/api)

### Requesting signatures

At its core, the Signer Service provides a signature on a 32-byte data digest. Signatures are provided using either the validator keys (BLS) or a proxy key (BLS or ECDSA), both on the [Commit-Boost domain](#signing-structure).

Use `TreeHash` to create a digest from a custom struct:

```rust
#[derive(TreeHash)]
struct Datagram {
    data: u64,
}
```

To request a signature, you need a public key. Get available keys:

```rust
let pubkeys = config.signer_client.get_pubkeys().await.unwrap();
```

JWT tokens are created and refreshed internally by `SignerClient` — each method generates a fresh token with the correct `route`, `exp`, and `payload_hash` claims automatically. No manual token management is needed.

#### Consensus key signatures

```rust
let datagram = Datagram { data: 1 };
let request = SignConsensusRequest::builder(pubkey).with_msg(&datagram);
let signature = config.signer_client.request_consensus_signature(&request).await.unwrap();
```

Where `pubkey` is the validator (consensus) public key.

#### Proxy key signatures

First, generate a proxy key for a given consensus key. We support BLS and ECDSA:

```rust
// BLS proxy
let proxy_delegation = config.signer_client.generate_proxy_key_bls(pubkey).await?;
let proxy_pubkey = proxy_delegation.message.proxy;

// ECDSA proxy
let proxy_delegation = config.signer_client.generate_proxy_key_ecdsa(pubkey).await?;
let proxy_address = proxy_delegation.message.proxy;
```

Then request a signature using the proxy key:

```rust
// BLS proxy
let datagram = Datagram { data: 1 };
let request = SignProxyRequest::builder(proxy_pubkey).with_msg(&datagram);
let signature = config.signer_client.request_proxy_signature_bls(&request).await.unwrap();

// ECDSA proxy
let datagram = Datagram { data: 1 };
let request = SignProxyRequest::builder(proxy_address).with_msg(&datagram);
let signature = config.signer_client.request_proxy_signature_ecdsa(&request).await.unwrap();
```

### Signing structure

For details on the signing structure — including domain separation, nonces, SSZ Merkle tree construction, and the signing ID format — see [Requesting Proposer Commitment Signatures](./prop-commit-signing.md).

## Metrics

Modules can record custom metrics that are automatically scraped by Prometheus.

### Define metrics

Use the `prometheus` crate:

```rust
static ref MY_CUSTOM_REGISTRY: Registry = Registry::new_custom(Some("da_commit".to_string()), None).unwrap();
static ref SIG_RECEIVED_COUNTER: IntCounter = IntCounter::new("signature_received", "successful signature requests received").unwrap();
```

### Start the metrics provider

```rust
MY_CUSTOM_REGISTRY.register(Box::new(SIG_RECEIVED_COUNTER.clone())).unwrap();
MetricsProvider::load_and_run(MY_CUSTOM_REGISTRY.clone());
```

This starts a server with a `/metrics` endpoint on the configured port (default `9090`).

### Record metrics

```rust
SIG_RECEIVED_COUNTER.inc();
```

For a full reference of available metrics, see the [Metrics catalog](../get_started/running/metrics.md) (once created; the Prometheus scrape target is already configured by the docker-init setup).
