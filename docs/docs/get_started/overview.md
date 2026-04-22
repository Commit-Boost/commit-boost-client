---
description: Initial setup
---

# Overview

Commit-Boost is primarily based on [Docker](https://www.docker.com/) to enable modularity, sandboxing and cross-platform compatibility. It is also possible to run Commit-Boost [natively](/get_started/running/binary) without Docker.

Each component roughly maps to a container: from a single `.toml` config file, the node operator can specify which modules they want to run, and Commit-Boost takes care of spinning up the services and creating links between them.
Commit-Boost ships with two core services:

- A PBS module which implements the [BuilderAPI](https://ethereum.github.io/builder-specs/) for [MEV Boost](https://docs.flashbots.net/flashbots-mev-boost/architecture-overview/specifications).
- A signer module, which implements the [Signer API](/api) and provides the interface for modules to request proposer commitments.

## Setup

The Commit-Boost program can create a dynamic `docker-compose` file, with services and ports already set up.

Whether you're using Docker or running the binaries natively, you can compile from source directly from the repo, or download binaries and fetch docker images from the official releases.

## Binaries and images

Find the latest releases at https://github.com/Commit-Boost/commit-boost-client/releases.

The services are also published at [each release](https://github.com/orgs/Commit-Boost/packages?repo_name=commit-boost-client).

### From source

Requirements:

- Rust 1.89

:::note
Run `rustup update` to update Rust and Cargo to the latest version
:::

```bash
# Pull the repo
git clone https://github.com/Commit-Boost/commit-boost-client

# Stable branch has the latest released version
git checkout stable

# Init submodules
git submodule update --init --recursive
```

:::note
If you get an `openssl` related error try running: `apt-get update && apt-get install -y openssl ca-certificates libssl3 libssl-dev build-essential pkg-config`
:::

Now, build the binary, which will be stored in `build/<git hash>/<OS and arch>`, for example `build/206658b/linux_amd64/`:

```bash
just build-bin $(git rev-parse --short HEAD)
```

You can confirm the binary was built successfully by navigating to the build directory and checking its version:
```bash
./commit-boost --version
```

### Docker

Building the service images requires the binary to be built using the above instructions first, since it will be copied into those images. Once it's built, create the images with the following:

```bash
just build-pbs-img $(git rev-parse --short HEAD)
just build-signer-img $(git rev-parse --short HEAD)
```

This will create two local images called `commit_boost/pbs:<git_hash>` and `commit_boost/signer:<git_hash>` for the PBS and Signer services respectively. Make sure to use these images in the `docker_image` field in the `[pbs]` and `[signer]` sections of the `.toml` config file, respectively.
