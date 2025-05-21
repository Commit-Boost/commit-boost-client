# Building Commit-Boost from Source

Commit-Boost's components are all written in [Rust](https://www.rust-lang.org/). This guide will walk you through the setup required to build them from source. It assumes you are on a Debian or Debian-based system (e.g., Ubuntu, Linux Mint, Pop OS). For other systems, please adapt the steps for your system's package manager accordingly.


## Building via the Docker Builder

For convenience, Commit-Boost has Dockerized the build environment for Linux `x64` and `arm64` platforms. All of the prerequisites, cross-compilation tooling, and configuration are handled by the builder image. If you would like to build the CLI, PBS module, or Signer binaries and Docker images from source, you are welcome to use the Docker builder process.

To use the builder, you will need to have [Docker Engine](https://docs.docker.com/engine/install/) installed on your system. Please follow the instructions to install it first.

:::note
The build script assumes that you've added your user account to the `docker` group with the Linux [post-install steps](https://docs.docker.com/engine/install/linux-postinstall/). If you haven't, then you'll need to run the build script below as `root` or modify it so each call to `docker` within it is run as the root user (e.g., with `sudo`).
:::

We provide a build script called `build-linux.sh` to automate the process:

```
$ ./build-linux.sh
Usage: build.sh [options] -v <version number>
This script assumes it is in the commit-boost-client repository directory.
Options:
	-a	Build all of the artifacts (CLI, PBS, and Signer, along with Docker images)
	-c	Build the Commit-Boost CLI binaries
	-p	Build the PBS module binary and its Docker container
	-s	Build the Signer module binary and its Docker container
	-o	When passed with a build, upload the resulting image tags to a local Docker registry specified in $LOCAL_DOCKER_REGISTRY
```

The script utilizes Docker's [buildx](https://docs.docker.com/reference/cli/docker/buildx/) system to both create a multiarch-capable builder and cross-compile for both Linux architectures. You are free to modify it to produce only the artifacts relevant to you if so desired.

The `version` provided will be used to house the output binaries in `./build/$VERSION`, and act as the version tag for the Docker images when they're added to your local system or uploaded to your local Docker repository.


## Building Manually

If you don't want to use the Docker builder, you can compile the Commit-Boost artifacts locally. The following instructions assume a Debian or Debian-based system (e.g., Ubuntu, Linux Mint, Pop OS) for simplicity. For other systems, please adapt any relevant instructions to your environment accordingly.


### Prerequisites

Requirements:

- Rust 1.83+
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
While many package repositories provide a `protobuf-compiler` package in lieu of manually installing protoc, we've found at the time of this writing that most of them use v3.21 which is quite out of date. We recommend getting the latest version manually.
:::

```bash
PROTOC_VERSION=$(curl -s "https://api.github.com/repos/protocolbuffers/protobuf/releases/latest" | grep -Po '"tag_name": "v\K[0-9.]+')
MACHINE_ARCH=$(uname -m)
case "${MACHINE_ARCH}" in
    aarch64) PROTOC_ARCH=aarch_64;;
    x86_64) PROTOC_ARCH=x86_64;;
    *) echo "${MACHINE_ARCH} is not supported."; exit 1;;
esac
curl -sLo protoc.zip https://github.com/protocolbuffers/protobuf/releases/latest/download/protoc-$PROTOC_VERSION-linux-$PROTOC_ARCH.zip
sudo unzip -q protoc.zip bin/protoc -d /usr
sudo unzip -q protoc.zip "include/google/*" -d /usr
sudo chmod a+x /usr/bin/protoc
rm -rf protoc.zip
```

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
CB_CONFIG=cb-config.toml CB_JWTS="test_jwts=dummy" CB_SIGNER_PORT=20000 ./target/release/commit-boost-signer
```

You should see output like this:
```
2025-05-07T21:43:46.385535Z  WARN Proxy store not configured. Proxies keys and delegations will not be persisted
2025-05-07T21:43:46.393507Z  INFO Starting signing service version="0.7.0" commit_hash="58082edb1213596667afe8c3950cd997ab85f4f3" modules=["test_jwts"] port=20000 loaded_consensus=0 loaded_proxies=0
2025-05-07T21:43:46.393574Z  WARN No metrics server configured
```

If you do, then the binary works.