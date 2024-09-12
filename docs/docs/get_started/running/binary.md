---
description: Run Commit-Boost modules natively
---

# Binary
It is also possible to run the native modules without using docker.

:::warning
Running the modules natively means you opt out of the security guarantees made by Docker and it's up to you how to setup and ensure the modules run safely
:::


## Setup
Get the binary of the module either by compiling from source or by downloading a [published release](https://github.com/Commit-Boost/commit-boost-client/releases).

Modules need some environment variables to work correctly. Here is the complete list

### Common
- `CB_CONFIG`: required, path to the `toml` config file
- `CB_METRICS_PORT`: optional, port where to expose the `/metrics` endpoint for Prometheus
- `CB_LOGS_DIR`: optional, directory to store logs. This will override the directory in the `toml` config

### PBS Module
- `CB_BUILDER_URLS`: optional, comma-separated list of urls to `events` modules where to post builder events

### Signer Module
- `CB_JWTS`: required, comma-separated list of `MODULE_ID=JWT` to process signature requests
- `CB_SIGNER_PORT`: required, port to open the signer server on
For loading keys we currently support:
    - `CB_SIGNER_LOADER_FILE`: path to a `.json` with plaintext keys (for testing purposes only)
    - `CB_SIGNER_LOADER_KEYS_DIR` and `CB_SIGNER_LOADER_SECRETS_DIR`: paths to the `keys` and `secrets` directories (ERC-2335 style keystores as used in Lighthouse)


### Modules
- `CB_MODULE_ID`: required, unique id of the module

#### Commit modules
- `CB_SIGNER_URL`: requred, url to the signer module server
- `CB_SIGNER_JWT`: required, jwt to use to for signature requests (needs to match what is in `CB_JWTS`)

#### Events modules
- `CB_BUILDER_PORT`: required, port to open to receive builder events from the PBS module

Modules might also have additional envs required, which should be detailed by the maintainers.

## Start

After creating the `cb-config.toml` file, you need to setup the required envs and run the binary. For example:

```bash
CB_CONFIG=./cb-config.toml commit-boost-pbs
```

## Security
Running the modules natively means you opt out of the security guarantees made by Docker and it's up to you how to setup and ensure the modules run safely. 

