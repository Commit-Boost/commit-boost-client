---
description: Initial setup
---

# Overview

:::warning
Commit-Boost is currently in alpha development and **NOT** ready for production use. Please use caution
:::

Commit-Boost is primarily based on [Docker](https://www.docker.com/) to enable modularity, sandboxing and cross-platform compatibility. It is also possible to run Commit-Boost [natively](/get_started/running/binary) without Docker.

Each component roughly maps to a container: from a single `.toml` config file, the node operator can specify which modules they want to run, and Commit-Boost takes care of spinning up the services and creating links between them.
Commit-Boost ships with two core modules:
- a PBS module which implements the [BuilderAPI](https://ethereum.github.io/builder-specs/) for [MEV Boost](https://docs.flashbots.net/flashbots-mev-boost/architecture-overview/specifications)
- a signer module, which implements the [Signer API](/api) and provides the interface for modules to request proposer commitments

## Setup

The Commit-Boost CLI creates a dynamic `docker-compose` file, with services and ports already set up.

Whether you're using Docker or running the binaries natively, you can compile from source directly from the repo, or download binaries and fetch docker images from the official releases.

### Binaries and images
Find the latest releases at https://github.com/Commit-Boost/commit-boost-client/releases.

The modules are also published at [each release](https://github.com/orgs/Commit-Boost/packages?repo_name=commit-boost-client).

### From source
Requirements: 
- Rust 1.80

:::note
run `rustup update` to update Rust and Cargo to the latest version
:::

```bash
# Pull the repo
git clone https://github.com/Commit-Boost/commit-boost-client

# Stable branch has the latest released version
git checkout stable
```

:::note
If you get an `openssl` related error try running: `apt-get update && apt-get install -y openssl ca-certificates libssl3 libssl-dev build-essential pkg-config`
:::

#### Docker
You will need to build the CLI to create the `docker-compose` file:

```bash
# Build the CLI
cargo build --release --bin commit-boost

# Check that it works
./target/release/commit-boost --version
```

and the modules as Docker images
```bash
bash scripts/build_local_images.sh
```

:::note
If you require `sudo` access to run Docker, you will need `sudo` to run some of the Commit-Boost commands. This is because under the hood Commit-Boost invokes the Docker API. You can double check this by running `docker info` in a terminal
:::

This will create two local images called `commitboost_pbs_default` and `commitboost_signer` for the Pbs and Signer module respectively. Make sure to use these images in the `docker_image` field in the `[pbs]` and `[signer]` sections of the `.toml` config file, respectively.

#### Binaries

Alternatively, you can also build the modules from source and run them without Docker, in which case you can skip the CLI and only compile the modules:

```bash
# Build the PBS module, this corresponds to commit-boost-pbs in the releases
cargo build --release --bin default-pbs

# Build the Signer module, this corresponds to commit-boost-signer in the releases
cargo build --release --bin signer-module
```

