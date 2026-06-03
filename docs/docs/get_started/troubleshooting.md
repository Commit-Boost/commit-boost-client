---
description: Common issues
---

# Troubleshooting

If you find any or have any question, please reach out on [X (Twitter)](https://x.com/Commit_Boost). If there are any security related items, please see [here](https://github.com/Commit-Boost/commit-boost-client/blob/main/SECURITY.md).

---

## Symptom → service decision matrix

Real failures often cascade across service boundaries. Before diving into a specific section, use this table to identify the most likely culprit from the observable symptom.

| If you see… | Likely culprit | Start in section |
|---|---|---|
| Container won't start / exits immediately | Docker (volume, port, image) or missing env vars | [Docker / networking](#docker--networking) |
| HTTP 401 from `POST /signer/*` | JWT auth failure — shared secret mismatch | [Signer Service > JWT auth failures](#jwt-auth-failures) |
| Signer log says `cannot load keys` or `invalid keystore` | Key loading path, format mismatch, or permission error | [Signer Service > Key loading](#key-loading) |
| Module log says `connection refused` reaching signer | Docker networking: wrong URL, port, or network | [Docker / networking > container-to-container connectivity](#container-to-container-connectivity) |
| `POST /reload` returns HTTP 500 | Reload failure — invalid config or body override | [Hot reload > Reload failures](#reload-failures) |
| `POST /reload` reverts a previous `POST /revoke_jwt` | Body override not persisted | [Hot reload > Body overrides and footguns](#body-overrides-and-footguns) |
| Module starts but fails all signature requests | JWT expiration too short for long-running operations | [Signer Service > JWT auth failures](#jwt-auth-failures) |
| Module container runs but PBS returns no headers | Relays unreachable or timing game expiring too early | [PBS](#pbs) |
| `docker compose` exits with `no such file` | Missing or misnamed config file or env file | [Docker / networking > Init failures](#init-failures) |

---

## Docker / networking

### Init failures

`commit-boost init --config cb-config.toml` produces `cb.docker-compose.yml`, and `.cb.env`. If you see `no such file` when running Docker Compose:

1. **Missing config file** — verify `cb-config.toml` exists in the working directory and is TOML-valid.
2. **Missing env file** — if the Signer Service is enabled, `.cb.env` is created alongside the compose file. Pass it with `--env-file ./.cb.env`.
3. **Wrong path** — the volume bindings in the compose file are relative to the working directory. If you moved the config file after `init`, update the `volumes` entry.

See the [configuration reference](./configuration.md) for a full field listing and [Docker setup](./running/docker.md#init) for init details.

### Container won't start / exits immediately

If a container exits immediately after `docker compose up`:

1. **Port conflict** — try a different `[pbs] port` or `[signer] port` in the config, or stop whatever is already using the port. The `docker compose logs` output will show a `bind: address already in use` error.
2. **Missing image** — the config's `docker_image` field must point to a valid image. For local development images (e.g. `test_da_commit`), build them first with `just docker-build-test-modules`.
3. **Volume mount failure** — the config file, keys, and secrets paths must be accessible at runtime. If a path is wrong, the container will exit. Check logs for `file not found`.
4. **Missing environment variables** — services that need `CB_CONFIG`, `CB_SIGNER_JWT`, or `CB_MODULE_ID` will fail to start if these aren't set. Docker containers get these from `.cb.env` (via `--env-file`); native binaries set them on the command line.

Check `docker compose logs` for the specific error message.

### Container-to-container connectivity

Modules connect to the Signer Service over an internal Docker bridge network. If a module logs `connection refused`:

1. **Wrong URL** — modules receive `CB_SIGNER_URL` as an env var. The default is `http://cb_signer:20000`. If you override this, verify the hostname matches the Signer container name (`cb_signer` by default) and the port matches `[signer] port`.
2. **Network isolation** — verify the module's compose service is on the `signer_network` (or whatever network the signer is on). The `init` command sets this up automatically; manual compose edits can break it.
3. **Signer not healthy** — the compose file sets `depends_on: cb_signer: condition: service_healthy`. If the signer fails its health check (e.g., because it can't load keys), dependent modules will never start. Check `docker compose logs cb_signer` first.

---

## Signer Service

If the signer logs an error at startup or signature requests fail at runtime, the likely causes fall into three categories.

### JWT auth failures

A `401` response from any `POST /signer/*` endpoint means the request's JWT was rejected.

1. **Shared secret mismatch (most common)** — each module authenticates with a JWT derived from a shared secret. The signer's `CB_JWTS` env var (or `[signer]` config) and the module's `CB_SIGNER_JWT` env var must carry the **same secret for the same module ID**. Common pitfalls:
   - Typo in the module ID or secret string.
   - The `.cb.env` file was regenerated (e.g., by re-running `init`) but the running containers still use the old env file.
   - A manual override was applied via [`POST /reload` body overrides](#body-overrides-and-footguns) but the environment variable was not updated — after a restart the override is lost.
2. **Clock skew** — JWT validation checks the `iat` (issued-at) and `exp` (expiration) claims. If the signer's system clock differs from the module's clock, the JWT may appear invalid.
3. **Admin endpoint auth failure** — `POST /signer/reload` and `POST /signer/revoke_jwt` require the admin JWT secret (`CB_SIGNER_ADMIN_JWT` environment variable or `admin_secret` body override). If you get a 401 on these endpoints, check that the admin secret matches.

### Key loading

If the signer fails to start with errors about keys:

- **Wrong format** — the `[signer.local.loader] format` must match the actual keystore layout. See the [Signer configuration](./configuration.md#local-signer) for supported formats and their expected file structures.
- **Wrong path** — `keys_path` and `secrets_path` are relative to the container's filesystem, not the host. In Docker, these are volume-mounted from the host; verify the mount paths match what the loader expects.
- **Permission denied** — the signer process runs as a non-root user inside the container. Ensure the mounted keys and secrets are readable by the container user.
- **Proxy store path missing** — if `[signer.local.store]` is configured, the proxy directory must exist and be writable. The signer will fail to start if it cannot create proxy key files.
- **Remote signer unavailable** — for Web3Signer or Dirk, the signer must be reachable at startup. A timeout or connection error during the initial handshake will cause the signer to exit.

See the [Signer configuration](./configuration.md#signer-service) for a full reference and [Docker setup](./running/docker.md#example-with-pbs-signer-and-a-signer-service) for a working example.

### TLS

If you enable TLS and the signer fails to start:

1. **Missing certificate files** — the TLS directory (default `./certs`) must contain `cert.pem` and `key.pem`. See the [TLS section](./configuration.md#tls) for details.
2. **Self-signed certificate** — recommended for testing only. Production setups should use a well-known CA.
3. **Certificate permissions** — the key file must be readable by the signer process (non-root user inside the container).

---

## Modules

### Signer connectivity

If a commit module logs errors when calling the signer:

1. **Wrong JWT** — the module's `CB_SIGNER_JWT` must match the signer's entry for that module ID. See [JWT auth failures](#jwt-auth-failures) above.
2. **Wrong signer URL** — verify `CB_SIGNER_URL` points to the correct host and port. In Docker, the host is the signer container name (`cb_signer` by default); with native binaries, it is the signer's host IP.
3. **Signer not started** — modules depend on the signer via Docker Compose `depends_on`. If the signer fails to start (e.g., key loading error), dependent modules will never leave the `created` state.
4. **Proxy key generation fails** — if using proxy keys, the signer must have the proxy store configured and writable. Check the signer logs for `cannot write proxy key`.

### Module ID mismatch

If the signer responds with `unknown module`:

- The `[[modules]]` entry in `cb-config.toml` uses a different `id` than what the module was started with (`CB_MODULE_ID` env var). These must match exactly.
- After adding a new module to the config, you must send [`POST /reload`](#hot-reload) to the signer before starting the module container. Until then, the signer has no record of the new module and will reject its requests.

---

## Hot reload

Commit-Boost supports hot-reloading the configuration without restarting containers. The mechanism is fully documented in the [configuration page](./configuration.md#hot-reload); this section covers what to do when it breaks.

### Reload failures

If `POST /reload` returns `500`:

1. **Invalid TOML** — the config file changed on disk since the service started. If the new content has syntax errors, the reload is rejected and the previous configuration is kept. Check `docker compose logs` for the parse error.
2. **Body override references a non-existent module** — the body fields `jwt_secrets` and `admin_secret` (the "body overrides") accept optional overrides applied on top of the config. If the body references a module ID that does not exist in the config file, the entire reload is rejected.
3. **Permission denied** — the service may not be able to re-read the config file if its permissions changed after startup (e.g., file was moved or ownership changed).

### Body overrides and footguns

The request body for `POST /reload` accepts two optional fields — collectively called **body overrides** — that are applied on top of the config at runtime but **never persisted to disk**:

- `jwt_secrets`: a comma-separated list of `<MODULE_ID>=<JWT_SECRET>` pairs to override specific module secrets.
- `admin_secret`: a string to override the admin JWT secret.

Because these are in-memory only, they are lost on container restart. If you rotate a JWT secret via a body override, the environment variable (`CB_JWTS` or the module's `CB_SIGNER_JWT`) still holds the old value. After any restart the signer will fall back to the old secret and authentication will fail until you update the environment variable to match.

Similarly, if you revoke a module with `POST /revoke_jwt` but leave it in the config, the next `POST /reload` (without a body override) re-adds the module from the config. Always remove revoked modules from `[[modules]]` in the config to make the revocation permanent.

See the [Hot Reload section in the configuration page](./configuration.md#footguns) for the full list of footguns.

### Hot reload and custom PBS

Custom PBS services may override the default reload behaviour to parse extra configuration fields. If a custom PBS returns `500` on reload, check the module's documentation for custom reload handling. See the [custom module examples](https://github.com/Commit-Boost/commit-boost-client/blob/main/examples/status_api/src/main.rs) for details.

---

## Cascading diagnostics

Failures in one service often propagate to others. When debugging, always check the **upstream dependency first**:

### Scenario 1: Signer fails to load keys → all modules fail

```
Signer can't read keystore
    ↓
Signer health check fails
    ↓
Docker Compose never marks cb_signer as healthy
    ↓
Modules (depends_on: condition: service_healthy) never start
    ↓
Modules that need proposer commitments (proxy key generation, signature requests) get connection refused
```

**Diagnosis:** Start with the signer log. A `cannot load keys` or `invalid keystore` error at the top means all downstream failures are consequences. Fix the key loading, then restart.

### Scenario 2: Config file becomes stale after a restart

```
Admin rotates JWT secrets via POST /reload body overrides
    (overrides are in-memory only)
    ↓
Container crashes or is restarted
    ↓
Signer starts with the old secrets from .cb.env / config file
    ↓
Modules still hold the rotated JWT → 401 on every request
```

**Diagnosis:** Look for a pattern where everything worked before a restart, then all modules fail with 401. The fix is to update the environment variable (`.cb.env` or the shell env) to match the rotated secret, then restart cleanly.

### Scenario 3: Relay timeout causes no-payload cascade

```
One relay becomes slow or unresponsive
    ↓
PBS times out waiting for that relay's header
    ↓
PBS returns 502 (NoResponse) to the CL
    ↓
CL falls back to local execution payload → no MEV reward
```

**Diagnosis:** Check the PBS logs for relay timeout errors (status code `555` or `TIMEOUT_ERROR_CODE_STR`) on a specific relay. Remove or replace that relay in the `[[relays]]` config, then `POST /reload` the PBS.

---

If you started the modules correctly you should see the following logs.

## PBS
After the module started correctly you should see:
```bash
2024-09-16T19:27:16.004643Z  INFO Starting PBS service address=0.0.0.0:18550 events_subs=0
```

To check that the setup is correct and you are connected to relays, you can trigger manually the `/status` endpoint, by running:

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
< date: Mon, 16 Sep 2024 19:32:07 GMT
<
* Connection #0 to host 0.0.0.0 left intact
```

if now you check the logs, you should see:

```bash
2024-09-16T19:32:07.634966Z  INFO status{req_id=62f1c0db-f277-49fa-91e7-a9a1c2b2a6d3}: ua="curl/7.81.0" relay_check=true
2024-09-16T19:32:07.642992Z  INFO status{req_id=62f1c0db-f277-49fa-91e7-a9a1c2b2a6d3}: relay check successful
```

If the sidecar is setup correctly, it will receive and process calls from the CL:
#### Register validator
This should happen periodically, depending on your validator setup.

```bash
2024-09-16T19:28:37.976534Z  INFO register_validators{req_id=296f662f-0e7a-4f15-be75-55b8ca19ffc0}: ua="Lighthouse/v5.2.1-9e12c21" num_registrations=500
2024-09-16T19:28:38.819591Z  INFO register_validators{req_id=296f662f-0e7a-4f15-be75-55b8ca19ffc0}: register validator successful
```

#### Get header
This will only happen if some of your validators have a proposal slot coming up.

```bash
2024-09-16T19:30:24.135376Z  INFO get_header{req_id=74126c5f-69e6-4961-86a6-6c2597bf15f5 slot=2551052}: ua="Lighthouse/v5.2.1-9e12c21" parent_hash=0x641c99d6e4f14bf6d268eb2a8c0dc51c7030ab24e384c0e679f2a6b438d298ea validator_pubkey=0x84fc20b09496341f24abfcb6f407e916ecc317497c5b1bba4970e50e96cf5e731b88e51753064c30cb221453bd71aebf ms_into_slot=135
2024-09-16T19:30:25.089477Z  INFO get_header{req_id=74126c5f-69e6-4961-86a6-6c2597bf15f5 slot=2551052}: received header block_hash=0x0139686e8d251f010153875270256fce6f298d7b3f3f9129179fb86297dffad3 value_eth="0.001399518501462470"
```

#### Submit block
This will only happen if you received a header in the previous call, and if the header is higher than the locally built block.

```bash
2024-09-16T14:38:01.409075Z  INFO submit_blinded_block{req_id=6eb9a04d-6f79-4295-823f-c054582b3599 slot=2549590}: ua="Lighthouse/v5.2.1-9e12c21" slot_uuid=16186e06-0cd0-47bc-9758-daa1b66eff5c ms_into_slot=1409 block_hash=0xfa135ae6f2bfb32b0a47368f93d69e0a2b3f8b855d917ec61d78e78779edaae6
2024-09-16T14:38:02.910974Z  INFO submit_blinded_block{req_id=6eb9a04d-6f79-4295-823f-c054582b3599 slot=2549590}: received unblinded block
```
