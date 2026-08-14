# Building Commit-Boost from Source

Commit-Boost's components are all written in [Rust](https://www.rust-lang.org/). This guide walks through building them from source.

## Getting the Source

Pull the repository:

```bash
git clone https://github.com/Commit-Boost/commit-boost-client
```

Check out the release you want to build. Each release is pinned in `.releases/`
(e.g. `.releases/v0.10.0.yml` names its `commit:`); check out that commit:

```bash
cd commit-boost-client && git checkout <release-commit>
```

Finally, update the submodules:

```
git submodule update --init --recursive
```

## Building via the Docker Builder

The build environment is Dockerized for the Linux `x64` and `arm64` platforms, using Docker's [buildx](https://docs.docker.com/reference/cli/docker/buildx/) system. The builder image handles all of the prerequisites, cross-compilation tooling, and configuration, so this path does not need a local Rust toolchain.

The builder requires [Docker Engine](https://docs.docker.com/engine/install/).

:::note
The build system assumes that you've added your user account to the `docker` group with the Linux [post-install steps](https://docs.docker.com/engine/install/linux-postinstall/). If you haven't, then you'll need to run the build script below as `root` or modify it so each call to `docker` within it is run as the root user (e.g., with `sudo`).
:::

Builds run through the project's `justfile` (install [Just](https://github.com/casey/just); `just --list` shows all recipes). The relevant recipes: `build-bin <version>` builds the `commit-boost` binary; `build-all <version>` additionally builds the unified Docker image `commit-boost/commit-boost:<version>` (bundling all subcommands) and loads it into your local registry. `<version>` is the output directory name under `./build/` and the Docker tag, e.g. `$(git rev-parse --short HEAD)`. For Linux `amd64` + `arm64` use the `-multiarch` recipe variants; a multiarch image manifest needs a [custom Docker registry](https://www.digitalocean.com/community/tutorials/how-to-set-up-a-private-docker-registry-on-ubuntu-20-04), as Docker's built-in local registry does not support them.

To build the binary, run:

```
just build-bin <version>
```

This will create a binary in `build/<version>/<OS and arch>`, for example `build/206658b/linux_amd64/`. Confirm that it works:

```
./build/<version>/<OS and arch>/commit-boost --version
```

## Building Manually

If you don't want to use the Docker builder, you can compile the Commit-Boost artifacts with a local Rust toolchain. The following instructions assume a Debian or Debian-based system (e.g., Ubuntu, Linux Mint, Pop OS) for simplicity. For other systems, please adapt any relevant instructions to your environment accordingly.

### Prerequisites

Requirements:

- Rust 1.91+
- GCC (or another C compiler of your choice)
- OpenSSL development libraries
- Protobuf Compiler (`protoc`)

Install Rust via [the official directions](https://www.rust-lang.org/learn/get-started) if you don't already have it.

Install the dependencies:

```bash
sudo apt update && sudo apt install -y openssl ca-certificates libssl3 libssl-dev build-essential pkg-config curl
```

Install the Protobuf compiler:

:::note
While many package repositories provide a `protobuf-compiler` package in lieu of manually installing protoc, we've found at the time of this writing that Debian-based ones use v3.21 which is quite out of date. We recommend getting the latest version manually.
:::

The repository provides a recipe to install the latest version directly from the GitHub releases page. It requires [Just](https://github.com/casey/just) and works from anywhere inside the repository:

```bash
just install-protoc
```

This works on OSX and Linux systems. You can also run `provisioning/protoc.sh` directly, or download and install protoc manually.

Your build environment should now be ready to use.

### Building the Binary

From the repository root, build the unified `commit-boost` binary with Cargo:

```
cargo build --release --bin commit-boost
```

This will create the binary at `target/release/commit-boost`. Confirm that it works:

```
./target/release/commit-boost --version
```

You can now use this to generate the Docker Compose file to drive the other modules if desired. See the [configuration](./configuration.md) guide for more information.

### Verifying the PBS Service

The commands below use the manual build's output path (`./target/release/commit-boost`); if you used the Docker builder, substitute `./build/<version>/<OS and arch>/commit-boost`.

To verify the PBS service works, create [a TOML configuration](./configuration.md) for the PBS service (e.g., `cb-config.toml`).

As a quick example, we'll use this configuration that connects to the Flashbots relay on the Hoodi network:

```toml
chain = "Hoodi"

[pbs]
port = 18550

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

[[modules]]
id = "test"
type = "commit"
docker_image = "test_module"
signing_id = "0x6a33a23ef26a4836979edff86c493a69b26ccf0b4a16491a815a13787657431b"
```

Set the path to it in the `CB_CONFIG` environment variable and run the binary:

```
CB_CONFIG=cb-config.toml ./target/release/commit-boost pbs
```

If it works, you should see output like this:

```
2025-11-04T14:22:03.118512Z  INFO starting PBS service version="0.10.0-rc4" commit_hash="eeff25750c01f4adfc95fc08d69d541ace8e4087" addr=127.0.0.1:18550 chain=Hoodi
```

The v0.10.0 release commit self-reports version `0.10.0-rc4`; timestamps will differ, and any other checkout prints its own commit hash and version. A successful relay check follows the `starting PBS service` line; the full annotated healthy-log reference is in [Expected healthy logs](./troubleshooting.md#expected-healthy-logs).

If you see that, then the PBS service works.

### Verifying the Signer Service

To verify the Signer service works, create [a TOML configuration](./configuration.md) for the Signer service (e.g., `cb-config.toml`). We'll use the example in the PBS section above.

The signer needs `CB_CONFIG`, `CB_JWTS`, and `CB_SIGNER_ADMIN_JWT` set (definitions: [Binary > Signer Service](./running/binary.md#signer-service)); for this smoke test use `test=dummy` and a dummy admin secret.

Set these values, create the `keys` and `secrets` directories listed in the configuration file, and run the binary:

```
mkdir -p /tmp/keys && mkdir -p /tmp/secrets
CB_CONFIG=cb-config.toml CB_JWTS="test=dummy" CB_SIGNER_ADMIN_JWT="dummy_admin" ./target/release/commit-boost signer
```

You should see output like this:

```
2025-11-04T14:31:44.815702Z  WARN Proxy store not configured. Proxies keys and delegations will not be persisted
2025-11-04T14:31:44.818193Z  INFO Starting signing service version="0.10.0-rc4" commit_hash="eeff25750c01f4adfc95fc08d69d541ace8e4087" modules=["test"] endpoint=127.0.0.1:20000 loaded_consensus=0 loaded_proxies=0 jwt_auth_fail_limit=3 jwt_auth_fail_timeout=300s reverse_proxy=None
2025-11-04T14:31:44.818229Z  WARN No metrics server configured
2025-11-04T14:31:44.818305Z  WARN Running in insecure HTTP mode, no TLS certificates provided
```

The `insecure HTTP mode` warning is expected: this config does not set a `tls_mode`; see [TLS](./configuration.md#tls) to enable it.

If you see that, then the binary works.
