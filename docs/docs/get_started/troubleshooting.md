---
description: Common issues
---

# Troubleshooting

If you run into an issue or have a question, please reach out on [X (Twitter)](https://x.com/Commit_Boost). For security related items, please see [here](https://github.com/Commit-Boost/commit-boost-client/blob/main/SECURITY.md).

---

## Where to start

| If you see… | Likely culprit | Start in section |
|---|---|---|
| Container won't start / exits immediately | Docker (volume, port, image) or missing env vars | [Docker / networking](#docker--networking) |
| HTTP 401 from `POST /signer/*` | JWT auth failure (shared secret mismatch) | [Signer service > JWT auth failures](#jwt-auth-failures) |
| Signer logs a key loading error at startup | Key loading path, format mismatch, or permission error | [Signer service > Key loading](#key-loading) |
| Module log says `connection refused` reaching signer | Docker networking: wrong URL, port, or network | [Docker / networking > container-to-container connectivity](#container-to-container-connectivity) |
| `POST /reload` returns HTTP 500 or 400 | Reload failure: invalid config (500) or bad body override (400) | [Hot reload > Reload failures](#reload-failures) |
| `POST /reload` reverts a previous `POST /revoke_jwt` | Body override not persisted | [Hot reload > Body overrides and footguns](#body-overrides-and-footguns) |
| Module starts but fails all signature requests | Shared secret mismatch, module missing from the signer's config, or clock skew beyond ~5 minutes | [Signer service > JWT auth failures](#jwt-auth-failures) |
| Module container runs but PBS returns no headers | Relays unreachable or timing game expiring too early | [Cascading diagnostics > Scenario 3](#scenario-3-relay-timeout-causes-no-payload-cascade) |
| `docker compose` exits with `no such file` | Missing or misnamed config file or env file | [Docker / networking > Init failures](#init-failures) |

---

## Docker / networking

### Init failures

`commit-boost init --config cb-config.toml` produces `cb.docker-compose.yml` and, when the Signer service is enabled, `.cb.env`. If you see `no such file` when running Docker Compose:

1. Missing config file: verify `cb-config.toml` exists in the working directory and is TOML-valid.
2. Missing env file: if the Signer service is enabled, `.cb.env` is created alongside the compose file. Pass it with `--env-file ./.cb.env`.
3. Wrong path: the volume bindings in the compose file are relative to the working directory. If you moved the config file after `init`, update the `volumes` entry.

See the [configuration reference](./configuration.md) for a full field listing and [Docker setup](./running/docker.md#init) for init details.

### Container won't start / exits immediately

If a container exits immediately after `docker compose up`:

1. Port conflict: try a different `[pbs] port` or `[signer] port` in the config, or stop whatever is already using the port. A conflict on a published port shows up in the `docker compose up` output as a `port is already allocated` error from the Docker daemon.
2. Missing image: the config's `docker_image` field must point to a valid image. For local development images (e.g. `test_da_commit`), build them first with `just docker-build-test-modules`.
3. Volume mount failure: the config file, keys, and secrets paths must be accessible at runtime. If a path is wrong, the container will exit. A bad config mount logs `Unable to find config file`.
4. Missing environment variables: services that need `CB_CONFIG`, `CB_SIGNER_JWT`, or `CB_MODULE_ID` will fail to start if these aren't set. In the generated compose file, `CB_CONFIG` and `CB_MODULE_ID` are written inline into each service and only the JWT secret comes from `.cb.env` (via `--env-file`); native binaries set all of them on the command line.

Check `docker compose logs` for the specific error message.

### Container-to-container connectivity

Modules connect to the Signer service over an internal Docker bridge network. If a module logs `connection refused`:

1. Wrong URL: modules receive `CB_SIGNER_URL` as an env var. The default is `http://cb_signer:20000`. If you override this, verify the hostname matches the Signer container name (`cb_signer` by default) and the port matches `[signer] port`.
2. Network isolation: verify the module's compose service is on the `signer_network` (or whatever network the signer is on). The `init` command sets this up automatically; manual compose edits can break it.
3. Signer not healthy: the compose file sets `depends_on: cb_signer: condition: service_healthy`. If the signer fails its health check (e.g., because it can't load keys), dependent modules will never start. Check `docker compose logs cb_signer` first.

---

## Signer service

If the signer logs an error at startup or signature requests fail at runtime, the likely causes fall into three categories.

### JWT auth failures

A `401` response from any `POST /signer/*` endpoint means the request's JWT was rejected.

1. Shared secret mismatch (most common): each module authenticates with a JWT derived from a shared secret. The signer's `CB_JWTS` env var and the module's `CB_SIGNER_JWT` env var must carry the **same secret for the same module ID**. Common pitfalls:
   - Typo in the module ID or secret string.
   - The `.cb.env` file was regenerated (e.g., by re-running `init`) but the running containers still use the old env file.
   - A manual override was applied via [`POST /reload` body overrides](#body-overrides-and-footguns) but the environment variable was not updated; after a restart the override is lost.
2. Clock skew: the only time-based claim JWT validation checks is `exp` (expiration), with a 10-second leeway. Tokens are minted with a 5-minute expiration, so a token is rejected only when the signer's clock is ahead of the module's by more than the token lifetime plus the leeway, about 5 minutes 10 seconds. A signer clock running behind the module's never invalidates a token.
3. Admin endpoint auth failure: `POST /reload` and `POST /revoke_jwt` require the admin JWT secret (`CB_SIGNER_ADMIN_JWT` environment variable or `admin_secret` body override). If you get a 401 on these endpoints, check that the admin secret matches.

### Key loading

If the signer fails to start with errors about keys:

- The `[signer.local.loader] format` must match the actual keystore layout. See the [Signer configuration](./configuration.md#local-signer) for supported formats and their expected file structures.
- `keys_path` and `secrets_path` are relative to the container's filesystem, not the host. In Docker, these are volume-mounted from the host; verify the mount paths match what the loader expects.
- The signer process runs as a non-root user inside the container, so the mounted keys and secrets must be readable by the container user.
- If `[signer.local.store]` is configured, the proxy directory must exist and be writable. The signer will fail to start if it cannot create proxy key files.
- For Dirk, the remote signer must be reachable at startup. A timeout or connection error during the initial handshake will cause the signer to exit.

See the [Signer configuration](./configuration.md#signer-service) for a full reference and [Docker setup](./running/docker.md#example-with-pbs-signer-and-a-commit-module) for a working example.

### TLS

If you enable TLS and the signer fails to start:

- The directory set by `path` in `[signer.tls_mode]` (mounted at `/certs` inside the Docker container) is missing `cert.pem` or `key.pem`.
- The key file is not readable by the signer process (a non-root user inside the container).

See [Configuration > TLS](./configuration.md#tls) for the full certificate contract.

---

## Modules

### Signer connectivity

If a commit module logs errors when calling the signer:

1. Wrong JWT: the module's `CB_SIGNER_JWT` must match the signer's entry for that module ID. See [JWT auth failures](#jwt-auth-failures) above.
2. Wrong signer URL: verify `CB_SIGNER_URL` points to the correct host and port. In Docker, the host is the signer container name (`cb_signer` by default); with native binaries, it is the signer's host IP.
3. Signer not started: modules depend on the signer via Docker Compose `depends_on`. If the signer fails to start (e.g., key loading error), dependent modules will never leave the `created` state.
4. Proxy key errors: generating proxy keys does not require a proxy store; without one the signer only warns that proxies will not be persisted, and they are lost on restart. If `[signer.local.store]` is configured, the directory must be readable and writable or the signer fails at startup (e.g. `failed reading proxy dir: ...`).

### Module ID mismatch

If the signer responds with `401` `unauthorized` to a module's requests (or `404` `module id not found` on `POST /revoke_jwt`):

- The `[[modules]]` entry in `cb-config.toml` uses a different `id` than what the module was started with (`CB_MODULE_ID` env var). These must match exactly.
- After adding a new module to the config, send [`POST /reload`](#hot-reload) to the signer before starting the module container. Until then, the signer has no record of the new module and will reject its requests. `/reload` returns `500` with `JWT secret for module X is missing` if the secret was not in `CB_JWTS` at signer startup; update `.cb.env` and restart. Full mechanism: [Hot reload > Common patterns](./configuration.md#common-patterns).

---

## Hot reload

Commit-Boost supports hot-reloading the configuration without restarting containers. The mechanism is fully documented in the [configuration page](./configuration.md#hot-reload); this section covers what to do when it breaks.

### Reload failures

`500` means the reload was rejected and the previous configuration kept: usually invalid TOML in the changed config file (check `docker compose logs` for the parse error), sometimes a permission error re-reading it. `400` means a body override references a module ID that is not in the config file. Full rules: [Hot reload](./configuration.md#hot-reload).

### Body overrides and footguns

The `POST /reload` body overrides (`jwt_secrets`, `admin_secret`) live only in memory and are lost on restart, and a `/reload` re-adds any module revoked with `POST /revoke_jwt` that is still in the config. Full rules: [Signer service reload](./configuration.md#signer-service-reload).

### Hot reload and custom PBS

Custom PBS services may override the default reload behavior to parse extra configuration fields. If a custom PBS returns `500` on reload, check the module's documentation for custom reload handling. See the [custom module examples](https://github.com/Commit-Boost/commit-boost-client/blob/main/examples/status_api/src/main.rs) for details.

---

## Cascading diagnostics

Failures in one service often propagate to others. When debugging, check the upstream dependency first.

### Scenario 1: Signer fails to load keys, all modules fail

A signer that cannot read its keystore fails its health check, so Docker Compose never marks `cb_signer` as healthy and modules guarded by `depends_on: condition: service_healthy` never start. Anything that needs proposer commitments (proxy key generation, signature requests) then gets `connection refused`.

Start with the signer log. A key loading error at the top (e.g. `failed reading proxy dir: ...` or a keystore parse failure) means all downstream failures are consequences. Fix the key loading, then restart.

### Scenario 2: Config file becomes stale after a restart

Telltale pattern: everything worked until a restart, then all modules fail with 401. Cause: a body-override secret rotation was never persisted (see [Body overrides and footguns](#body-overrides-and-footguns)). Update `.cb.env` to the rotated secret and restart.

### Scenario 3: Relay timeout causes no-payload cascade

When a relay becomes slow or unresponsive, PBS times out waiting for that relay's header. If no relay returns a valid bid, PBS returns `204` (no content) to the CL, which falls back to the local execution payload, so there is no MEV reward. If the request itself fails (rather than simply yielding no bids), PBS instead returns `502` (`no payload from relays`).

Check the PBS logs for a specific relay repeatedly timing out: a `get_header` timeout logs `err="Timed Out"` with the relay id, and increments `cb_pbs_relay_status_code_total` with `http_status_code="555"` (the synthetic timeout code; see the [Metrics catalog](./running/metrics-catalog.md)). Remove or replace that relay in the `[[relays]]` config, then `POST /reload` the PBS.

---

## Expected healthy logs

If you started the modules correctly you should see the following logs.

### PBS

After the service started correctly you should see:
```text
2025-11-04T14:22:03.118512Z  INFO starting PBS service version="0.10.0-rc4" commit_hash="eeff25750c01f4adfc95fc08d69d541ace8e4087" addr=0.0.0.0:18550 chain=Hoodi
```

The v0.10.0 release commit self-reports version `0.10.0-rc4`; any other checkout prints its own commit hash and version.

To check that the setup is correct and you are connected to relays, you can manually trigger the `/status` endpoint, by running:

```bash
curl http://0.0.0.0:18550/eth/v1/builder/status -vvv

*   Trying 0.0.0.0:18550...
* Connected to 0.0.0.0 (127.0.0.1) port 18550 (#0)
> GET /eth/v1/builder/status HTTP/1.1
> Host: 0.0.0.0:18550
> User-Agent: curl/7.81.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-length: 0
< date: Tue, 04 Nov 2025 14:32:07 GMT
<
* Connection #0 to host 0.0.0.0 left intact
```

If you now check the logs, you should see:

```text
2025-11-04T14:32:07.634966Z  INFO : new request ua="curl/7.81.0" relay_check=true method=/eth/v1/builder/status req_id=62f1c0db-f277-49fa-91e7-a9a1c2b2a6d3
2025-11-04T14:32:07.642992Z  INFO : relay check successful method=/eth/v1/builder/status req_id=62f1c0db-f277-49fa-91e7-a9a1c2b2a6d3
2025-11-04T14:32:07.643104Z  INFO : Responded with 200 OK in 8 ms method=/eth/v1/builder/status req_id=62f1c0db-f277-49fa-91e7-a9a1c2b2a6d3
```

The leading `:` is the (deliberately unnamed) request span; the fields after the message are that
span's fields, so every line belonging to one request carries the same `req_id`.

If the sidecar is set up correctly, it will receive and process calls from the CL:

#### Register validator
This should happen periodically, depending on your validator setup.

```text
2025-11-04T14:28:37.976534Z  INFO : new request ua="Lighthouse/v5.2.1-9e12c21" num_registrations=500 method=/eth/v1/builder/validators req_id=296f662f-0e7a-4f15-be75-55b8ca19ffc0
2025-11-04T14:28:38.819591Z  INFO : register validator successful method=/eth/v1/builder/validators req_id=296f662f-0e7a-4f15-be75-55b8ca19ffc0
```

#### Get header
This will only happen if some of your validators have a proposal slot coming up.

```text
2025-11-04T14:30:24.135376Z  INFO : new request ua="Lighthouse/v5.2.1-9e12c21" ms_into_slot=135 method=/eth/v1/builder/header/{slot}/{parent_hash}/{pubkey} req_id=74126c5f-69e6-4961-86a6-6c2597bf15f5 slot=1671102 parent_hash=0x641c99d6e4f14bf6d268eb2a8c0dc51c7030ab24e384c0e679f2a6b438d298ea validator=0x84fc20b09496341f24abfcb6f407e916ecc317497c5b1bba4970e50e96cf5e731b88e51753064c30cb221453bd71aebf
2025-11-04T14:30:25.089477Z  INFO : received header value_eth="0.001399518501462470" block_hash=0x0139686e8d251f010153875270256fce6f298d7b3f3f9129179fb86297dffad3 method=/eth/v1/builder/header/{slot}/{parent_hash}/{pubkey} req_id=74126c5f-69e6-4961-86a6-6c2597bf15f5 slot=1671102 parent_hash=0x641c99d6e4f14bf6d268eb2a8c0dc51c7030ab24e384c0e679f2a6b438d298ea validator=0x84fc20b09496341f24abfcb6f407e916ecc317497c5b1bba4970e50e96cf5e731b88e51753064c30cb221453bd71aebf
```

If no relay returns a usable bid you will see `no header available for slot` instead, and PBS answers the beacon node with a `204`.

#### Submit block
This will only happen if you received a header in the previous call, and if the header is higher than the locally built block.

```text
2025-11-04T14:30:26.409075Z  INFO : new request ua="Lighthouse/v5.2.1-9e12c21" ms_into_slot=2409 method=/eth/v1/builder/blinded_blocks req_id=6eb9a04d-6f79-4295-823f-c054582b3599 slot=1671102 block_hash=0x0139686e8d251f010153875270256fce6f298d7b3f3f9129179fb86297dffad3 block_number=1640231 parent_hash=0x641c99d6e4f14bf6d268eb2a8c0dc51c7030ab24e384c0e679f2a6b438d298ea
2025-11-04T14:30:27.910974Z  INFO : received unblinded block (v1) method=/eth/v1/builder/blinded_blocks req_id=6eb9a04d-6f79-4295-823f-c054582b3599 slot=1671102 block_hash=0x0139686e8d251f010153875270256fce6f298d7b3f3f9129179fb86297dffad3 block_number=1640231 parent_hash=0x641c99d6e4f14bf6d268eb2a8c0dc51c7030ab24e384c0e679f2a6b438d298ea
```

A beacon node calling the v2 route (`POST /eth/v2/builder/blinded_blocks`) logs `received unblinded block (v2)` instead.
