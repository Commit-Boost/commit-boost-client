---
description: Configure Commit-Boost
---

# Configuration

Commit-Boost needs a configuration file detailing all the services that you want to run. Create a `cb-config.toml` and modify it depending on which modules you plan to run.

- For a full explanation of all the fields, see the [annotated config example](https://github.com/Commit-Boost/commit-boost-client/blob/main/config.example.toml).
- For some additional examples, see the [example config presets](https://github.com/Commit-Boost/commit-boost-client/tree/main/examples/configs).

## Minimal PBS setup on Hoodi

```toml
chain = "Hoodi"

[pbs]
port = 18550

[[relays]]
# Replace this with your relay's own URL, in the form scheme://<relay-pubkey>@<host>
url = "https://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@relay.example.com"

[metrics]
enabled = true
```

:::warning
`url` must be a full URL containing the relay's BLS pubkey; an empty URL or one without a pubkey (`invalid BLS pubkey`) prevents the sidecar from starting.
:::

You can find a list of MEV-Boost Hoodi relays [here](https://github.com/ethstaker/ethstaker-guides/blob/main/MEV-relay-list.md#mev-relay-list-for-hoodi-testnet).
After the sidecar is started, it will expose a port (`18550` in this example), that you need to point your CL to. This may be different depending on which CL you're running; see the [consensus client configuration guides](https://docs.flashbots.net/flashbots-mev-boost/getting-started/system-requirements#consensus-client-configuration-guides).

:::note
In this setup, the Signer service will not be started.
:::

## Custom chains

Besides the known chain names (`Mainnet`, `Holesky`, `Sepolia`, `Hoodi`), the `chain` field also accepts a custom chain in two forms:

- **Spec file**: a genesis time plus a path to a chain spec file, either in JSON (as returned by the beacon endpoint `/eth/v1/config/spec`) or YAML format:

```toml
chain = { genesis_time_secs = 1695902400, path = "/path/to/spec.json" }
```

- **Inline object**: all parameters specified directly:

```toml
chain = { genesis_time_secs = 1695902400, slot_time_secs = 12, genesis_fork_version = "0x01017000", fulu_fork_slot = 5283840, chain_id = 17000 }
```

All inline fields are required; omitting one makes the `chain` value fail to parse.

With the spec-file form, the `CB_CHAIN_SPEC` environment variable can override the spec file path at runtime (see [Binary](./running/binary.md#common)).

## PBS safety and tuning options

Beyond the basics shown above, the `[pbs]` section supports additional knobs. The [annotated config example](https://github.com/Commit-Boost/commit-boost-client/blob/main/config.example.toml) is the full field reference with defaults; the options below carry extra operational context:

- `timeout_get_header_ms`: timeout, in milliseconds, for the `get_header` call to relays. Must be greater than 0, and must be less than `late_in_slot_time_ms`. The CL also has a timeout (e.g. 1 second), so this should be lower than that to leave some margin for overhead. Default: `950`.
- `late_in_slot_time_ms`: how late, in milliseconds into the slot, is considered "late". This shortens `get_header` timeouts to make sure a header is returned within this deadline; if the CL request arrives later in the slot, fetching headers is skipped to force local building and minimize the risk of a missed slot. Must be greater than 0. Default: `2000`.
- `extra_validation_enabled`: whether to enable extra validation of `get_header` responses. If enabled, `rpc_url` must also be set to an Execution Layer RPC on the same chain as the sidecar (this is checked at startup). Default: `false`.
- `mux_registry_refresh_interval_seconds`: refresh interval, in seconds, for registry-based muxes with [dynamic refreshing](./mux-key-loaders.md#lido-registry) enabled. Default: `384`.

:::warning
`validator_registration_batch_size` used to be a per-relay option. It is no longer accepted per relay: setting it inside a `[[relays]]` entry makes the sidecar fail at startup; set it in the `[pbs]` section instead.
:::

### Per-relay options

Each `[[relays]]` entry supports, besides `id` and `url`:

- `headers`: optional headers to send with each request to this relay.
- `get_params`: optional GET parameters to add to each request URL for this relay.
- `get_header` (unreleased, from v0.11): how headers are fetched from this relay, either `"http"` (one request per `get_header`) or `"stream"` (a websocket stream of bid updates, only for relays that support it; see the annotated config example for the stream endpoint and header handshake). Default: `"http"`. Released v0.10.0 does not recognize this option: setting it in a `[[relays]]` entry fails config parsing at startup.
- `enable_timing_games`: whether to enable timing games for this relay, as tuned by `target_first_request_ms` and `frequency_get_header_ms`. If neither of those is set, this flag has no effect. Advanced users only: misconfiguration can result in e.g. fetching a lower header value or missing a slot (caveats and worked examples in the annotated config example). Default: `false`.
- `target_first_request_ms`: target time in the slot, in milliseconds, at which to send the first `get_header` request.
- `frequency_get_header_ms`: frequency, in milliseconds, at which to send `get_header` requests.

The same fields are available on `[[mux.relays]]` entries (see [Mux key loaders](./mux-key-loaders.md)).

#### Header streaming

:::info Unreleased
This describes behavior on main, unreleased, targeted for v0.11. With `get_header = "stream"`, PBS opens one websocket connection per `get_header` call, keeps the latest bid received until the deadline, then validates and returns it; the timing-game options do not apply while streaming. Any configured `headers` (e.g. an API key) are sent on the websocket handshake. If the connection cannot be established, PBS falls back to a plain HTTP `get_header` with the remaining timeout; a handshake timeout instead surfaces as status `555` in `cb_pbs_relay_status_code_total`, and a relay that rejects the handshake with an HTTP response records that response's own status code. A stream error before any bid arrives yields no header from that relay for the slot, surfaced as `556`; if a bid already arrived, that bid is still returned.
:::

### SSZ support

All Builder API requests and responses currently use JSON.

:::info Unreleased
This describes behavior on main, unreleased, targeted for v0.11: on `get_header` and v1 `submit_blinded_block` requests, PBS negotiates the response encoding with the beacon node through the `Accept` header. Both SSZ and JSON are supported, the response follows the client's `Accept` preference (q-values, then listing order), defaulting to JSON when no preference is expressed, and a request that accepts neither is rejected with `406`. v2 `submit_blinded_block` responses are empty `202`s, so there is nothing to negotiate. Towards relays, PBS always requests SSZ first and falls back to JSON for relays that do not support it.
:::

## Logs

Logging is configured via the optional `[logs.stdout]` and `[logs.file]` sections:

```toml
[logs.stdout]
enabled = true    # Whether to enable stdout logging. Default: true
level = "info"    # Log level: trace, debug, info, warn, error. Default: "info"
use_json = false  # Log in JSON format. Default: false
color = true      # Whether to use colors in the output. Default: true

[logs.file]
enabled = true    # Whether to enable file logging. Default: false
level = "info"    # Log level: trace, debug, info, warn, error. Default: "info"
use_json = true   # Log in JSON format. Default: true
dir_path = "/var/logs/commit-boost"  # Directory to store logs. Default: "/var/logs/commit-boost"
max_files = 30    # Maximum number of log files to keep. Default: unlimited
```

The `CB_LOGS_DIR` environment variable overrides `dir_path` (see [Binary](./running/binary.md#common)).

## Metrics

Prometheus metrics are configured via the optional `[metrics]` section; if the section is missing, metrics collection is disabled:

```toml
[metrics]
enabled = true        # Whether to collect metrics. Default: true
host = "127.0.0.1"    # Host to expose the metrics servers on. Default: 127.0.0.1
start_port = 10000    # First Prometheus scrape port; each service uses start_port, start_port + 1, ... Default: 10000
```

The `CB_METRICS_PORT` environment variable overrides the port used by a module at runtime (see [Binary](./running/binary.md#common)).

## Signer service

Commit-Boost supports both local and remote signers. The Signer service is responsible for signing the transactions that commit modules generate. It is not used by the default PBS image; custom PBS builds can opt in via `pbs.with_signer`. Only one signer at a time is allowed. The config file must still contain at least one `[[relays]]` entry even on a host that runs only the signer; the shared config schema requires it.

### Local signer

To start a local Signer service, you need to include its parameters in the config file:

```toml
[pbs]
# ...
with_signer = true

[signer]
port = 20000

[signer.local.loader]
format = "lighthouse"
keys_path = "/path/to/keys"
secrets_path = "/path/to/secrets"
```

Supported keystore formats: Lighthouse, Prysm, Teku, Lodestar, and Nimbus. Expected file structures for each format:

<details>
  <summary>Lighthouse</summary>

#### File structure:

```
├── keys
│   ├── <PUBLIC_KEY_1>
│   │   └── voting-keystore.json
│   └── <PUBLIC_KEY_2>
│       └── voting-keystore.json
└── secrets
    ├── <PUBLIC_KEY_1>
    └── <PUBLIC_KEY_2>
```

#### Config:

```toml
[pbs]
# ...
with_signer = true

[signer]
port = 20000

[signer.local.loader]
format = "lighthouse"
keys_path = "keys"
secrets_path = "secrets"
```

</details>

<details>
  <summary>Prysm</summary>

#### File structure:

```
├── wallet
│   └── direct
│       └── accounts
│           └──all-accounts.keystore.json
└── secrets
    └── password.txt
```

#### Config:

```toml
[pbs]
# ...
with_signer = true

[signer]
port = 20000

[signer.local.loader]
format = "prysm"
keys_path = "wallet/direct/accounts/all-accounts.keystore.json"
secrets_path = "secrets/password.txt"
```

</details>

<details>
  <summary>Teku</summary>

#### File structure:

```
├── keys
│   ├── <PUBLIC_KEY_1>.json
│   └── <PUBLIC_KEY_2>.json
└── secrets
    ├── <PUBLIC_KEY_1>.txt
    └── <PUBLIC_KEY_2>.txt
```

#### Config:

```toml
[pbs]
# ...
with_signer = true

[signer]
port = 20000

[signer.local.loader]
format = "teku"
keys_path = "keys"
secrets_path = "secrets"
```

</details>

<details>
  <summary>Lodestar</summary>

#### File structure:

```
├── keys
│   ├── <PUBLIC_KEY_1>.json
│   └── <PUBLIC_KEY_2>.json
└── secrets
    └── password.txt
```

#### Config:

```toml
[pbs]
# ...
with_signer = true

[signer]
port = 20000

[signer.local.loader]
format = "lodestar"
keys_path = "keys"
secrets_path = "secrets/password.txt"
```

:::note
All keys have the same password stored in `secrets/password.txt`
:::

</details>

<details>
  <summary>Nimbus</summary>

  #### File structure:
  ```
  ├── keys
  │   ├── <PUBLIC_KEY_1>
  │   │   └── keystore.json
  │   └── <PUBLIC_KEY_2>
  │       └── keystore.json
  └── secrets
      ├── <PUBLIC_KEY_1>
      └── <PUBLIC_KEY_2>
  ```

  #### Config:
  ```toml
  [pbs]
  # ...
  with_signer = true

  [signer]
  port = 20000

  [signer.local.loader]
  format = "nimbus"
  keys_path = "keys"
  secrets_path = "secrets"
  ```
</details>

### Proxy keys store

Proxy keys can be used to sign transactions with a different key than the one used to sign the block. Proxy keys are generated by the Signer service and authorized by the validator key. Each module can have its own proxy keys, which can be BLS or ECDSA.

To persist proxy keys across restarts, you must enable the proxy store in the config file. There are 2 options for this:

<details>
  <summary>File</summary>

The keys are stored in plain text in a file. This method is unsafe and should only be used for testing.

#### File structure

```
<proxy_dir>
└── <MODULE_ID>
      └── bls
          ├── <PROXY_PUBKEY1>
          └── <PROXY_PUBKEY2>
```

#### Configuration

```toml
[signer.local.store]
proxy_dir = "path/to/proxy_dir"
```

Where each `<PROXY_PUBKEY>` file contains the following:

```json
{
  "secret": "0x...",
  "delegation": {
    "message": {
      "delegator": "0x...",
      "proxy": "0x..."
    },
    "signature": "0x..."
  }
}
```

</details>

<details>
  <summary>ERC2335</summary>

The keys are stored in an ERC-2335-style keystore, along with a password. This way, you can safely share the keys directory: without the password they are useless.

#### File structure

```
├── <keys_path>
│   └── <CONSENSUS_PUBLIC_KEY>
│       └── <MODULE_ID>
│           ├── bls/
│           │   ├── <PROXY_PUBLIC_KEY1>.json
│           │   ├── <PROXY_PUBLIC_KEY1>.sig
│           │   ├── <PROXY_PUBLIC_KEY2>.json
│           │   └── <PROXY_PUBLIC_KEY2>.sig
│           └── ecdsa/
│               ├── <PROXY_PUBLIC_KEY3>.json
│               └── <PROXY_PUBLIC_KEY3>.sig
└── <secrets_path>
    └── <CONSENSUS_PUBLIC_KEY>
        └── <MODULE_ID>
            ├── bls/
            │   ├── <PROXY_PUBLIC_KEY1>
            │   └── <PROXY_PUBLIC_KEY2>
            └── ecdsa
                └── <PROXY_PUBLIC_KEY3>
```

#### Configuration

```toml
[signer.local.store]
keys_path = "path/to/keys"
secrets_path = "path/to/secrets"
```

Where the `<PROXY_PUBLIC_KEY>.json` files contain ERC-2335 keystore, the `<PROXY_PUBLIC_KEY>.sig` files contain the signature of the delegation, and `<PROXY_PUBLIC_KEY>` files contain the password to decrypt the keystores.

</details>

### Remote signer

You might choose to use an external service to sign the transactions. For now, one remote signer is supported: Dirk.

#### Dirk

Dirk is a distributed key management system that can be used to sign transactions. In this case the Signer service is needed as an intermediary between the modules and Dirk. The following parameters are needed:

```toml
[signer.dirk]
cert_path = "/path/to/client.crt"
key_path = "/path/to/client.key"
secrets_path = "/path/to/secrets"
# Optional parameters
ca_cert_path = "/path/to/ca.crt"
max_response_size_bytes = 4194304

# Add one entry like this for each host
[[signer.dirk.hosts]]
server_name = "localhost-1"
url = "https://localhost-1:8081"
wallets = ["SomeWallet", "DistributedWallet"]

[[signer.dirk.hosts]]
server_name = "localhost-2"
url = "https://localhost-2:8082"
wallets = ["AnotherWallet", "DistributedWallet"]
```

- `cert_path` and `key_path` are the paths to the client certificate and key used to authenticate with Dirk.
- `wallets` is a list of wallets from which the Signer service will load all accounts as consensus keys. Generated proxy keys will have format `<WALLET_NAME>/<ACCOUNT>/<MODULE_ID>/<UUID>`, so accounts found with that pattern will be ignored.
- `secrets_path` is the path to the folder containing the passwords of the generated proxy accounts, which will be stored in `<secrets_path>/<WALLET_NAME>/<ACCOUNT>/<MODULE_ID>/<UUID>.pass`.

Additionally, you can set a proxy store so that the delegation signatures for generated proxy keys are stored locally. As these signatures are not sensitive, the only supported store type is `File`:

```toml
[signer.dirk.store]
proxy_dir = "/path/to/proxy_dir"
```

Delegation signatures will be stored in files with the format `<proxy_dir>/delegations/<MODULE_ID>/bls/<PROXY_KEY>.sig`.

A full example of a config file with Dirk can be found [here](https://github.com/Commit-Boost/commit-boost-client/blob/main/examples/configs/dirk_signer.toml).


### TLS

By default the Signer API uses plain HTTP with no TLS. That is fine for testing or a single-machine Docker network; enable TLS for any traffic that crosses machines.

To enable TLS, you must first create a **certificate / key pair**. We **strongly advise** using a well-known Certificate Authority to create and sign the certificate and do not recommend using a self-signed certificate / key pair for production environments.

When configuring TLS support, the Signer service expects a single folder containing:
- `cert.pem`: The SSL certificate file signed by a certificate authority, in PEM format
- `key.pem`: The private key corresponding to `cert.pem` that will be used for signing TLS traffic, in PEM format

Specifying it is done within Commit-Boost's configuration file using the `[signer.tls_mode]` table as follows:

```toml
[pbs]
# ...
with_signer = true

[signer]
port = 20000
# ...

[signer.tls_mode]
type = "certificate"
path = "path/to/your/cert/folder"
```

With `type = "certificate"`, an existing `cert.pem` and `key.pem` must be present at `path`; there is no default path and the files are not auto-generated.

### Rate limit

The Signer service implements a rate limit system of 3 failed authentications every 5 minutes. These values can be modified in the config file:

```toml
[signer]
# ...
jwt_auth_fail_limit = 3 # The amount of failed requests allowed
jwt_auth_fail_timeout_seconds = 300 # The time window in seconds
```

The rate limit is applied to the IP address of the client making the request. By default, the IP is extracted directly from the TCP connection. If you're running the Signer service behind a reverse proxy (e.g. Nginx), you can configure it to extract the IP from a custom HTTP header instead. There are two options:

- `unique`: Provides an HTTP header that contains the IP. This header is expected to appear only once in the request. This is common when using `X-Real-IP`, `True-Client-IP`, etc. If a request has multiple values for this header, it will be considered invalid and rejected.
- `rightmost`: Provides an HTTP header that contains a comma-separated list of IPs. The nth rightmost IP in the list is used. If the header appears multiple times, all occurrences are concatenated in order and the rightmost counting spans the combined list. This is common when using `X-Forwarded-For`.

Examples:

```toml
[signer.reverse_proxy]
type = "unique"
header = "X-Real-IP"
```

```toml
[signer.reverse_proxy]
type = "rightmost"
header = "X-Forwarded-For"
trusted_count = 1
```

:::note
`trusted_count` is the number of trusted proxies in front of the Signer service, but the last proxy won't add its address, so the number of skipped IPs is `trusted_count - 1`. See [MDN docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For#trusted_proxy_count) for more info.
:::

:::warning
Only enable `[signer.reverse_proxy]` when the signer is reachable exclusively through the trusted proxy: this configuration decides whose IP gets rate-limited, so a directly reachable signer or a wrong `trusted_count` lets a client spoof the header to bypass the limit or lock other clients out.
:::

## Custom module

We currently provide a test module that needs to be built locally. To build the module run:

```bash
just docker-build-test-modules
```

:::note
We use `just` as command runner. If you don't have it installed, either install it from https://github.com/casey/just or run the commands manually from the `justfile` at the root of the repo.
:::

This will create a Docker image called `test_da_commit` that periodically requests signatures from the validator.

The `cb-config.toml` file needs to be updated as follows:

```toml
[pbs]
port = 18550

[[relays]]
# Replace this with your relay's own URL, in the form scheme://<relay-pubkey>@<host>
url = "https://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@relay.example.com"

[signer]
port = 20000

[signer.local.loader]
format = "lighthouse"
keys_path = "/path/to/keys"
secrets_path = "/path/to/secrets"

[metrics]
enabled = true

[[modules]]
id = "DA_COMMIT"
type = "commit"
docker_image = "test_da_commit"
signing_id = "0x6a33a23ef26a4836979edff86c493a69b26ccf0b4a16491a815a13787657431b"
sleep_secs = 5
```

The `[[modules]]` section at a minimum needs to specify the module `id`, `type` and `docker_image`. For modules with type `commit`, which will be used to access the Signer service and request signatures for preconfs, you will also need to specify the module's unique `signing_id` (see [the proposer commitment documentation](../developing/prop-commit-signing.md)). You can also pass environment variables to the module with `env` (a map of variable name to value) and `env_file` (path to an environment file for the module). Additional parameters needed for the business logic of the module will also be here.

To learn more about developing modules, see [Commit modules](../developing/commit-modules.md).


## Vouch

[Vouch](https://github.com/attestantio/vouch) is a multi-node validator client built by [Attestant](https://www.attestant.io/). Vouch is particular in that it also integrates an MEV-Boost client to interact with relays. The Commit-Boost PBS service is compatible with the Vouch `blockrelay` since it implements the same Builder-API as relays. For example, depending on your setup and preference, you may want to fetch headers from a given relay using Commit-Boost vs using the built-in Vouch `blockrelay`.

### Configuration

Get familiar on how to set up Vouch [here](https://github.com/attestantio/vouch/blob/master/docs/getting_started.md).

You can set up Commit-Boost with Vouch in two ways.
For simplicity, assume that in Vouch `blockrelay.listen-address: 127.0.0.1:19550` and in Commit-Boost `pbs.port = 18550`.

#### Beacon Node to Vouch

In this setup, the BN Builder-API endpoint will be pointing to the Vouch `blockrelay` (e.g. for Lighthouse you will need the flag `--builder=http://127.0.0.1:19550`).

Modify the `blockrelay.config` file to add Commit-Boost to its `relays`:

```json
{
    "relays": {
        "http://127.0.0.1:18550": {}
    }
}
```

#### Beacon Node to Commit-Boost

In this setup, the BN Builder-API endpoint will be pointing to the PBS service (e.g. for Lighthouse you will need the flag `--builder=http://127.0.0.1:18550`).

This will bypass the `blockrelay` entirely so make sure all relays are properly configured in the `[[relays]]` section.

:::note
This approach could also work if you have a multi-beacon-node setup, where some BNs fetch directly via Commit-Boost while others go through the `blockrelay`.
:::

### Notes

- It's up to you to decide which relays will be connected via Commit-Boost (`[[relays]]` section in the `toml` config) and which via Vouch (additional entries in the `relays` field). Remember that any rate-limit will be shared across the two sidecars, if running on the same machine.
- You may occasionally see a `timeout` error during registrations, especially if you're running a large number of validators in the same instance. This can resolve itself as registrations will be cleared later in the epoch when relays are less busy processing other registrations. Alternatively you can also adjust the `builderclient.timeout` option in `.vouch.yml`.

## Hot reload

Commit-Boost can hot-reload `cb-config.toml` without restarting modules: send `POST /reload` to each module you want to reload.

On the signer, the `/reload` and `/revoke_jwt` endpoints require admin authentication. `CB_SIGNER_ADMIN_JWT` holds the admin *secret* (an HMAC key), not a ready-to-use token: mint a short-lived HS256 admin JWT from it (claims spec: [Signer API > Admin token](../developing/prop-commit-signing.md#admin-token)). Sending the raw secret as the Bearer token fails with `401`. Commit-Boost ships no CLI helper for minting this token today; a few lines of Python do it (deps: `pip install pyjwt "eth-hash[pycryptodome]"`):

```python
import os, time, jwt
from eth_hash.auto import keccak

secret = os.environ["CB_SIGNER_ADMIN_JWT"]
route = "/reload"
body = b"{}"  # the request body you will send

claims = {"admin": True, "route": route, "exp": int(time.time()) + 30}
if body:
    claims["payload_hash"] = "0x" + keccak(body).hex()
print(jwt.encode(claims, secret, algorithm="HS256"))
```

Then send the request with the minted token. The signer's `/reload` endpoint requires a JSON body with `Content-Type: application/json` even when no overrides are sent; send an empty JSON object (`{}`) at minimum, and mint the token over the exact body you send. In the case the module is running in a Docker container without the port exposed (like the signer), you can run the request inside the container (assuming the snippet above is saved as `mint_admin_jwt.py`). In the Docker setup the admin secret lives in `.cb.env`, so export it into your shell first:

```bash
export $(grep CB_SIGNER_ADMIN_JWT .cb.env)
TOKEN=$(python3 mint_admin_jwt.py)
docker compose -f cb.docker-compose.yml exec cb_signer curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{}' http://localhost:20000/reload
```

Passing the minted token on the command line is acceptable only because it expires in 30 seconds and is bound to the route and body; the admin secret itself must never appear on a command line.

### Automatic reload (PBS only)

In addition to the manual `/reload` endpoint, the PBS service watches the config file for changes and automatically reloads the configuration whenever the file is modified, with no restart or API call needed. If a reload fails (e.g. because of a misconfigured option), the previous configuration is kept: the watcher logs a warning and the `/reload` endpoint returns a 500 error.

:::caution Custom PBS binaries
Custom PBS binaries only get the file watcher if they pass the real config path to `PbsState::new`; see [Extending PBS](../developing/extending-pbs.md#entry-point). `POST /reload` works either way.
:::

### Signer service reload

When the signer receives a reload request it re-reads the configuration file and environment variables, rebuilding its internal state to match:

- New modules added to the config are registered with the signer.
- Removed modules are dropped from the signer's access list.
- JWT secrets and the admin secret are reset to their current values from the environment variables.
- Any runtime changes from previous `/revoke_jwt` or `/reload` calls are reverted.

The request body accepts 2 optional override parameters, applied on top of the config:

- `jwt_secrets`: a comma-separated list of `<MODULE_ID>=<JWT_SECRET>` pairs to override specific module secrets. Only modules present in the config can be overridden.
- `admin_secret`: a string to override the admin JWT secret.

With an empty JSON object body (`{}`), the signer state is simply synced to match the config.

#### Common patterns

**Add a new module without restarting:**
This works only if the module's JWT secret was already included in `CB_JWTS` (a comma-separated list of `<MODULE_ID>=<JWT_SECRET>` pairs) when the signer started: the reload re-reads `CB_JWTS` from the signer's own process environment, which is fixed at startup, and fails with a 500 (`internal error`; the signer log shows `JWT secret for module X is missing`) otherwise. For a module whose secret is not yet in `CB_JWTS`, there are two Docker paths: re-run `commit-boost init` and `docker compose up -d` with the new env file so every container is recreated with consistent fresh secrets, or hand-add the module's service to the compose file and append its secret to `CB_JWTS` in `.cb.env` before restarting the signer. Re-running `init` rotates every JWT secret, including the admin secret.
1. Add the `[[modules]]` entry to `cb-config.toml`.
2. Send `POST /reload` with an empty JSON object body (`{}`). The signer picks up the new module from config.
3. Start the new module container with the matching JWT secret.

**Rotate a JWT secret remotely:**
Send `POST /reload` with the new secret in the body. The module must already exist in the config. Scripted rotation works without SSH access to edit config files. Unless TLS is enabled (see [TLS](#tls)), the request sends the new secret in cleartext over the network. A secret passed on a curl command line also lands in shell history and the process list; read it from a file or stdin instead.

**Revoke a compromised module immediately:**
Send `POST /revoke_jwt` with the module ID. This removes the module from the signer's access list without touching the config. The next `/reload` will restore the module if it is still in the config, so remove it from config as well if the revocation should be permanent.

#### Footguns

- Body overrides are not persisted: if the signer crashes or restarts after a body-based secret rotation, it falls back to the config/environment values. The module container will still have the rotated secret and authentication will fail. To avoid this, update the environment variable to match after rotating via the body.
- Override validation is strict: if the body references a module ID that does not exist in the config, the entire reload request is rejected and no changes are applied. This prevents typos from silently failing.

### Notes

- The hot reload feature is available for the PBS service (both default and custom) and the Signer service.
- Changes to listening hosts and ports are not applied, since they require a server restart.
- If running in Docker containers, changes in `volumes` will not be applied, as it requires the container to be recreated. Be careful if changing a path to a local file as it may not be accessible from the container.
- Custom PBS services may override the default behavior of the hot reload feature to parse extra configuration fields. Check the [examples](https://github.com/Commit-Boost/commit-boost-client/blob/main/examples/status_api/src/main.rs) for more details.
