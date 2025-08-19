# Building Commit-Boost from Source

Commit-Boost's components are all written in [Rust](https://www.rust-lang.org/). This guide will walk you through the setup required to build them from source. It assumes you are on a Debian or Debian-based system (e.g., Ubuntu, Linux Mint, Pop OS). For other systems, please adapt the steps for your system's package manager accordingly.

## Building via the Docker Builder

For convenience, Commit-Boost has Dockerized the build environment for Linux `x64` and `arm64` platforms. It utilizes Docker's powerful [buildx](https://docs.docker.com/reference/cli/docker/buildx/) system. All of the prerequisites, cross-compilation tooling, and configuration are handled by the builder image. If you would like to build the CLI, PBS module, or Signer binaries and Docker images from source, you are welcome to use the Docker builder process.

To use the builder, you will need to have [Docker Engine](https://docs.docker.com/engine/install/) installed on your system. Please follow the instructions to install it first.

:::note
The build system assumes that you've added your user account to the `docker` group with the Linux [post-install steps](https://docs.docker.com/engine/install/linux-postinstall/). If you haven't, then you'll need to run the build script below as `root` or modify it so each call to `docker` within it is run as the root user (e.g., with `sudo`).
:::

The Docker builder is built into the project's `justfile` which is used to invoke many facets of Commit Boost development. To use it, you'll need to install [Just](https://github.com/casey/just) on your system.

Use `just --list` to show all of the actions - there are many. The `justfile` provides granular actions, called "recipes", for building just the binaries of a specific crate (such as the CLI, `pbs`, or `signer`), as well as actions to build the Docker images for the PBS and Signer modules.

Below is a brief summary of the relevant ones for building the Commit-Boost artifacts:

- `build-all <version>` will build the `commit-boost-cli`, `commit-boost-pbs`, and `commit-boost-signer` binaries for your local system architecture. It will also create Docker images called `commit-boost/pbs:<version>` and `commit-boost/signer:<version>` and load them into your local Docker registry for use.
- `build-cli-bin <version>`, `build-pbs-bin <version>`, and `build-signer-bin <version>` can be used to create the `commit-boost-cli`, `commit-boost-pbs`, and `commit-boost-signer` binaries, respectively.
- `build-pbs-img <version>` and `build-signer-img <version>` can be used to create the Docker images for the PBS and Signer modules, respectively.

The `version` provided will be used to house the output binaries in `./build/<version>`, and act as the version tag for the Docker images when they're added to your local system or uploaded to your local Docker repository.

If you're interested in building the binaries and/or Docker images for multiple architectures (currently Linux `amd64` and `arm64`), use the variants of those recipes that have the `-multiarch` suffix. Note that building a multiarch Docker image manifest will require the use of a [custom Docker registry](https://www.digitalocean.com/community/tutorials/how-to-set-up-a-private-docker-registry-on-ubuntu-20-04), as the local registry built into Docker does not have multiarch manifest support.

## Building Manually

If you don't want to use the Docker builder, you can compile the Commit-Boost artifacts locally. The following instructions assume a Debian or Debian-based system (e.g., Ubuntu, Linux Mint, Pop OS) for simplicity. For other systems, please adapt any relevant instructions to your environment accordingly.

### Prerequisites

Requirements:

- Rust 1.85+
- GCC (or another C compiler of your choice)
- OpenSSL development libraries
- Protobuf Compiler (`protoc`)

Start by installing Rust if you don't already have it. Follow [the official directions](https://www.rust-lang.org/learn/get-started) to install it and bring it up to date.

Install the dependencies:

```bash
sudo apt update && sudo apt install -y openssl ca-certificates libssl3 libssl-dev build-essential pkg-config curl
```

Install the Protobuf compiler:

:::note
While many package repositories provide a `protobuf-compiler` package in lieu of manually installing protoc, we've found at the time of this writing that Debian-based ones use v3.21 which is quite out of date. We recommend getting the latest version manually.
:::

We provide a convenient recipe to install the latest version directly from the GitHub releases page:

```bash
just install-protoc
```

This works on OSX and Linux systems, but you are welcome to download and install it manually as well.

With the prerequisites set up, pull the repository:

```bash
git clone https://github.com/Commit-Boost/commit-boost-client
```

Check out the `stable` branch which houses the latest release:

```bash
cd commit-boost-client && git checkout stable
```

Finally, update the submodules:

```
git submodule update --init --recursive
```

Your build environment should now be ready to use.

### Building the CLI

To build the CLI, run:

```
cargo build --release --bin commit-boost-cli
```

This will create a binary in `./target/release/commit-boost-cli`. Confirm that it works:

```
./target/release/commit-boost-cli --version
```

You can now use this to generate the Docker Compose file to drive the other modules if desired. See the [configuration](./configuration.md) guide for more information.

### Building the PBS Module

To build PBS, run:

```
cargo build --release --bin commit-boost-pbs
```

This will create a binary in `./target/release/commit-boost-pbs`. To verify it works, create [a TOML configuration](./configuration.md) for the PBS module (e.g., `cb-config.toml`).

As a quick example, we'll use this configuration that connects to the Flashbots relay on the Hoodi network:

```toml
chain = "Hoodi"

[pbs]
port = 18550
with_signer = true

[[relays]]
url = "https://0xafa4c6985aa049fb79dd37010438cfebeb0f2bd42b115b89dd678dab0670c1de38da0c4e9138c9290a398ecd9a0b3110@boost-relay-hoodi.flashbots.net"

[metrics]
enabled = true

[signer]
port = 20000

[signer.local.loader]
format = "lighthouse"
keys_path = "/tmp/keys"
secrets_path = "/tmp/secrets"
```

Set the path to it in the `CB_CONFIG` environment variable and run the binary:

```
CB_CONFIG=cb-config.toml ./target/release/commit-boost-pbs
```

If it works, you should see output like this:

```
2025-05-07T21:09:17.407245Z  WARN No metrics server configured
2025-05-07T21:09:17.407257Z  INFO starting PBS service version="0.7.0" commit_hash="58082edb1213596667afe8c3950cd997ab85f4f3" addr=127.0.0.1:18550 events_subs=0 chain=Hoodi
2025-05-07T21:09:17.746855Z  INFO : new request ua="" relay_check=true method=/eth/v1/builder/status req_id=5c405c33-0496-42ea-a35d-a7a01dbba356
2025-05-07T21:09:17.896196Z  INFO : relay check successful method=/eth/v1/builder/status req_id=5c405c33-0496-42ea-a35d-a7a01dbba356
```

If you do, then the binary works.

### Building the Signer Module

To build the Signer, run:

```
cargo build --release --bin commit-boost-signer
```

This will create a binary in `./target/release/commit-boost-signer`. To verify it works, create [a TOML configuration](./configuration.md) for the Signer module (e.g., `cb-config.toml`). We'll use the example in the PBS build section above.

The signer needs the following environment variables set:

- `CB_CONFIG` = path of your config file.
- `CB_JWTS` = a dummy key-value pair of [JWT](https://en.wikipedia.org/wiki/JSON_Web_Token) values for various services. Since we don't need them for the sake of just testing the binary, we can use something like `"test_jwts=dummy"`.

Set these values, create the `keys` and `secrets` directories listed in the configuration file, and run the binary:

```
mkdir -p /tmp/keys && mkdir -p /tmp/secrets
CB_CONFIG=cb-config.toml CB_JWTS="test_jwts=dummy" ./target/release/commit-boost-signer
```

You should see output like this:

```
2025-06-03T04:57:19.815702Z  WARN Proxy store not configured. Proxies keys and delegations will not be persisted
2025-06-03T04:57:19.818193Z  INFO Starting signing service version="0.8.0-rc.1" commit_hash="3eed5268f07803c55cca7d7e2e14a7017098f797" modules=["test"] endpoint=127.0.0.1:20000 loaded_consensus=0 loaded_proxies=0
2025-06-03T04:57:19.818229Z  WARN No metrics server configured
```

If you do, then the binary works.
