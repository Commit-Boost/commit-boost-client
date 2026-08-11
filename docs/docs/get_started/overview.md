---
description: Initial setup
---

# Overview

Commit-Boost is primarily based on [Docker](https://www.docker.com/) to enable modularity, sandboxing and cross-platform compatibility. It is also possible to run Commit-Boost [natively](./running/binary.md) without Docker.

Each component roughly maps to a container: from a single `.toml` config file, the node operator can specify which services they want to run, and Commit-Boost takes care of spinning up the services and creating links between them.
Commit-Boost ships with two core services:

- A PBS service which implements the [BuilderAPI](https://ethereum.github.io/builder-specs/) for [MEV Boost](https://docs.flashbots.net/flashbots-mev-boost/architecture-overview/specifications).
- A Signer Service, which implements the [Signer API](/api) and provides the interface for modules to request proposer commitments.

## Setup

The Commit-Boost binary can create a dynamic `docker-compose` file, with services and ports already set up.

Whether you're using Docker or running the binaries natively, you can compile from source directly from the repo, or download binaries and fetch docker images from the official releases.

## Binaries and images

Find the latest releases at https://github.com/Commit-Boost/commit-boost-client/releases.

The services are also published at [each release](https://github.com/orgs/Commit-Boost/packages?repo_name=commit-boost-client).

### From source

Requirements:

- Rust 1.91

:::note
Run `rustup update` to update Rust and Cargo to the latest version
:::

```bash
# Pull the repo
git clone https://github.com/Commit-Boost/commit-boost-client

# Enter the repo
cd commit-boost-client

# Init submodules
git submodule update --init --recursive
```

:::note
If you get an `openssl` related error try running: `apt-get update && apt-get install -y openssl ca-certificates libssl3 libssl-dev build-essential pkg-config`
:::

Each Commit-Boost release commit is located as a versioned file in the `.releases` folder. For example `.releases/v0.10.0.yml` contains:
```yml
commit: "eeff25750c01f4adfc95fc08d69d541ace8e4087"
reason: "Final release including rc1-rc4 changes"
```

To locally build that release version, checkout the commit:

```bash
# Switch to the specific release
git checkout eeff25750c01f4adfc95fc08d69d541ace8e4087

# Build the binary
just build-bin $(git rev-parse --short HEAD)
```

The binary will be stored in `build/<git hash>/<OS and arch>`, for example `build/eeff257/linux_amd64/`:

You can confirm the binary was built successfully by navigating to the build directory and checking its version:
```bash
./commit-boost --version
```

### Docker

Building the service images requires the binary to be built using the above instructions first, since it will be copied into those images. The `build-all` command compiles the binary and then creates the image in one step:

```bash
# Switch to the specific release
git checkout eeff25750c01f4adfc95fc08d69d541ace8e4087

# Build the binary and create the image
just build-all $(git rev-parse --short HEAD)
```

This will create a local image called `commit-boost/commit-boost:<git_hash>` that can be used to run the PBS and Signer services, as well as the CLI. Make sure to use this image in the `docker_image` field in the `[pbs]` and `[signer]` sections of the `.toml` config file.
