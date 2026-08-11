---
description: Initial setup
---

# Getting started

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

## Build from source

To build the binary and Docker images yourself, see [Building from source](./building.md).
