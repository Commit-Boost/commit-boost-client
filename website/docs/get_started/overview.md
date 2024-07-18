---
sidebar_position: 1
---

# Overview

:::warning
Commit-Boost is currently in alpha development and **NOT** ready for production use. Please use caution
:::


Commit-Boost currently uses [Docker](https://www.docker.com/) to enable modularity, sandboxing and cross-platform compatibility. We're also exploring [alternative](https://github.com/Commit-Boost/commit-boost-client/issues/18) approaches.

In the current setup, each component roughly maps to a container: from a single `.toml` config file, the node operator can specify which modules they want to run, and Commit-Boost takes care of spinning up the services and creating links between them.

Commit-Boost ships with two core modules:
- a PBS module which implements implements the [BuilderAPI](https://ethereum.github.io/builder-specs/) for [MEV Boost](https://docs.flashbots.net/flashbots-mev-boost/architecture-overview/specifications)
- a signer module, which implements the [Signer API](/api) and provides the interface for modules to request proposer commitments


## Setup
### Requirements
- Rust 1.79
- Docker Engine up and running

:::note
run `rustup update` to update Rust and Cargo to the latest version
:::

### Build CLI

Since Commit-Boost is still in early development, you will have pull and build from source. Run:

```bash
git clone https://github.com/Commit-Boost/commit-boost-client
```

Now you can build the CLI with:
```bash
cargo build --release --p commit-boost
```

:::note
If you get an `openssl` related error try running: `apt-get update && apt-get install -y openssl ca-certificates libssl3 libssl-dev`
:::

Commit-Boost should now be available at `target/release/commit-boost`.

### Build Modules

The core modules are also required to be built locally as Docker images (eventually these will be available in a public registry). We provide a script for this:
```bash
bash scripts/build_local_images.sh
```

:::note
If you require `sudo` access to run Docker, you will need `sudo` to run some of the Commit-Boost commands. This is because under the hood Commit-Boost invokes the Docker API. You can double check this by running `docker info` in a terminal
:::

This will create two local images called `commitboost_pbs_default` and `commitboost_signer` for the Pbs and Signer module respectively.


