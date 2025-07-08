---
description: Run Commit-Boost modules natively
---

# Binary

:::warning
Running the modules natively means you opt out of the security guarantees made by Docker and it's up to you how to setup and ensure the modules run safely.
:::


## Setup
Get the binary of the module either by compiling from source or by downloading a [published release](https://github.com/Commit-Boost/commit-boost-client/releases).

Modules need some environment variables to work correctly.

### Common
- `CB_CONFIG`: required, path to the `.toml` config file.
- `CHAIN_SPEC_ENV`: optional, path to a chain spec file. This will override the `[chain]` field in the `.toml` config.
- `CB_METRICS_PORT`: optional, port where to expose the `/metrics` endpoint for Prometheus.
- `CB_LOGS_DIR`: optional, directory to store logs. This will override the directory in the `.toml` config.

### PBS Module
- `CB_BUILDER_URLS`: optional, comma-separated list of urls to `events` modules where to post builder events.
- `CB_PBS_ENDPOINT`: optional, override to specify the `IP:port` endpoint where the PBS module will open the port for the beacon node.
- `CB_MUX_PATH_{ID}`: optional, override where to load mux validator keys for mux with `id=\{ID\}`.

### Signer Module
- `CB_SIGNER_ADMIN_JWT`: secret to use for admin JWT.
- `CB_SIGNER_ENDPOINT`: optional, override to specify the `IP:port` endpoint to bind the signer server to.
- For loading keys we currently support:
  - `CB_SIGNER_LOADER_FILE`: path to a `.json` with plaintext keys (for testing purposes only).
  - `CB_SIGNER_LOADER_FORMAT`, `CB_SIGNER_LOADER_KEYS_DIR` and `CB_SIGNER_LOADER_SECRETS_DIR`: paths to the `keys` and `secrets` directories or files (ERC-2335 style keystores, see [Signer config](../configuration/#signer-module) for more info).
- For storing proxy keys we currently support:
  - `CB_PROXY_STORE_DIR`: directory where proxy keys and delegations will be saved in plaintext (for testing purposes only).
  - `CB_PROXY_KEYS_DIR` and `CB_PROXY_SECRETS_DIR`: paths to the `keys` and `secrets` directories or files (ERC-2335 style keystores, see [Proxy keys store](../configuration/#proxy-keys-store) for more info).
- For Dirk remote signer the following envs are available (see [Dirk config](../configuration/#dirk) for more info):
  - `CB_SIGNER_DIRK_CERT_FILE`: required, path to the client certificate file.
  - `CB_SIGNER_DIRK_KEY_FILE`: required, path to the client key file.
  - `CB_SIGNER_DIRK_SECRETS_DIR`: required, path to the secrets directory.
  - `CB_SIGNER_DIRK_CA_CERT_FILE`: optional, path to the CA certificate file.

### Modules
- `CB_MODULE_ID`: required, unique id of the module.

#### Commit modules
- `CB_SIGNER_URL`: required, url to the signer module server.
- `CB_SIGNER_JWT`: required, jwt to use for signature requests.

#### Events modules
- `CB_BUILDER_PORT`: required, port to open to receive builder events from the PBS module.

Modules might also have additional envs required, which should be detailed by the maintainers.

## Start

After creating the `cb-config.toml` file, setup the required envs and run the binary. For example:

```bash
CB_CONFIG=./cb-config.toml commit-boost-pbs
```

## Security
Running the modules natively means you opt out of the security guarantees made by Docker and it's up to you how to setup and ensure the modules run safely.
