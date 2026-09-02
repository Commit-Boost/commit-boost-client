---
description: Mux (multiplexer) configuration and key loader types
---

# Mux key loaders

The PBS multiplexer (or *mux*) lets you route different validators to different relay sets or timing game configurations. Instead of a single `[[relays]]` list for all your validators, you declare one or more `[[mux]]` entries that match specific validator pubkeys to custom relay and timing settings.

A mux covers cases like a Lido or SSV node operator who sends some validators to an operator-specific relay while the rest use the global relay set, or per-group timing games: `timeout_get_header_ms` and `late_in_slot_time_ms` can be set per-mux, overriding the PBS defaults for those validators. The mux key loaders (File, URL, Registry) populate a mux's validator set from a file, an HTTP endpoint, or an on-chain registry, so you don't have to list hundreds or thousands of pubkeys by hand.

Mux entries are an optional addition to the `[[relays]]` section. A mux affects only `get_header` requests: validator registrations and `submit_blinded_block` always go to all configured relays, global and mux alike.

---

## Mux entry matching

At startup the sidecar resolves every mux (running its loader, if any) and builds one pubkey-to-mux lookup, so entry order in the config does not matter and the mux pubkey sets must be disjoint:

| Condition | Behavior |
|---|---|
| Pubkey belongs to exactly one mux | That mux's relays and timing config are used for `get_header`; registrations and `submit_blinded_block` still go to all relays |
| Pubkey appears in more than one mux | Startup error: `duplicate validator pubkey in muxes` |
| Pubkey doesn't belong to any mux | Falls through to global `[[relays]]` |
| A mux has no pubkeys (empty set) | Startup error: each mux must have at least one pubkey |
| A mux has no relays | Startup error: each mux must have at least one relay |

```toml
# Global relays, used for validators not matching any mux
[[relays]]
id = "global-relay"
url = "..."

# A mux entry; its pubkeys must not appear in any other mux
[[mux]]
id = "timing-sensitive"
validator_pubkeys = [
    "0x80c7f782b2467c5898c5516a8b6595d75623960b4afc4f71ee07d40985d20e117ba35e7cd352a3e75fb85a8668a3b745",
]

# A relay used by this mux
[[mux.relays]]
id = "fast-relay"
url = "..."

# Another relay used by this mux
[[mux.relays]]
id = "robust-relay"
url = "..."

# ...
# Multiple muxes can be defined repeating this pattern
```

The pubkey set for a mux can come from two sources combined:
1. **Inline `validator_pubkeys`**: a list of hex-prefixed BLS pubkeys in the config file itself.
2. **A loader plugin**: loads additional keys from a file, URL, or on-chain registry. Keys from the loader are merged into the mux's pubkey set *before* the disjointness check runs, so a key pulled in by a loader can collide with one you listed inline in another mux.

---

## Key loaders

Key loaders are how you populate a mux with validator pubkeys without listing them manually. They are configured via the `loader` field inside a `[[mux]]` entry.

### File loader

Loads pubkeys from a flat JSON file on disk.

The file is a JSON array of hex-prefixed BLS public key strings.

```json
[
    "0x8160998addda06f2956e5d1945461f33dbc140486e972b96f341ebf2bdb553a0e3feb127451f5332dd9e33469d37ca67",
    "0x87b5dc7f78b68a7b5e7f2e8b9c2115f968332cbf6fc2caaaaa2c9dc219a58206b72c924805f2278c58b55790a2c3bf17",
    "0x89e2f50fe5cd07ed2ff0a01340b2f717aa65cced6d89a79fdecc1e924be5f4bbe75c11598bb9a53d307bb39b8223bc52"
]
```

Relative paths resolve against the sidecar's working directory, not the config file's location; absolute paths are recommended for binary deployments.

```toml
[[mux]]
id = "my-mux"
loader = "./path/to/keys.json"

[[mux.relays]]
id = "my-relay"
url = "..."
```

The path can be overridden at runtime via `CB_MUX_PATH_{id}` where `{id}` is the mux identifier, verbatim. For a mux with `id = "lido-mux"`, the variable is `CB_MUX_PATH_lido-mux`.

```bash
env CB_MUX_PATH_lido-mux="/path/to/override.json" commit-boost pbs
```

Hyphenated mux ids cannot be set with bash `export` (a hyphen is not valid in a shell identifier); use `env` as above, a compose `environment:` entry, or an underscore-only mux id.

---

### URL loader

Loads pubkeys from an HTTP(S) endpoint returning the same JSON array format as the File loader.

```toml
[[mux]]
id = "url-mux"
loader = { url = "https://keys.example.com/validators.json" }

[[mux.relays]]
id = "my-relay"
url = "..."
```

HTTPS is recommended; plain HTTP works but triggers a warning at startup.

The loader makes a one-shot GET request with no retry logic. The timeout is controlled by `http_timeout_seconds` in the `[pbs]` section (default: 10s). The response body is read (up to a 10 MiB limit) and parsed as JSON; larger responses fail the load.

---

### Registry loader

Loads validator pubkeys from an on-chain or network registry.

Three registries are currently supported:

| Registry | `registry` value | Key source | Authentication |
|---|---|---|---|
| Lido | `"lido"` | On-chain contract via RPC | RPC URL (from `[pbs]` config) |
| SSV | `"ssv"` | SSV node API or public API | SSV API URLs (from `[pbs]` config) |
| Stader | `"stader"` | On-chain contract via RPC | RPC URL (from `[pbs]` config) |

Registry entries must be unique within their registry type (one Lido entry per node operator ID, one SSV entry per node operator ID, one Stader entry per pool and node operator ID); a Lido and an SSV entry may share a node operator ID, since the registries are independent.

#### Lido registry

Reads validator pubkeys from Lido's on-chain `NodeOperatorsRegistry` or `CSModule registry`, depending on the module type. The sidecar connects to the configured RPC endpoint and calls the contract's `getSigningKeys` method with pagination.

`rpc_url` must be set in the `[pbs]` configuration.

```toml
[pbs]
port = 18550
rpc_url = "https://ethereum-rpc.publicnode.com"

[[mux]]
id = "lido-mux"
loader = { registry = "lido", node_operator_id = 8, lido_module_id = 1 }

[[mux.relays]]
id = "lido-relay"
url = "..."
```

**Fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `registry` | string | Yes | Must be `"lido"` |
| `node_operator_id` | integer | Yes | Lido node operator ID |
| `lido_module_id` | integer | No (default: `1`) | Lido staking module ID |
| `enable_refreshing` | boolean | No (default: `false`) | Whether to periodically refresh keys at runtime (see below) |

**Chain support:**

| Chain | `lido_module_id` | Module type | Contract type |
|---|---|---|---|
| Mainnet | 1 | Curated (NodeOperatorsRegistry) | `NodeOperatorsRegistry` |
| Mainnet | 2 | SimpleDVT | `NodeOperatorsRegistry` |
| Mainnet | 3 | Community Staking (CSM) | `CSModule` |
| Holesky | 1 | Curated (NodeOperatorsRegistry) | `NodeOperatorsRegistry` |
| Holesky | 2 | SimpleDVT | `NodeOperatorsRegistry` |
| Holesky | 3 | Sandbox | `NodeOperatorsRegistry` |
| Holesky | 4 | Community Staking (CSM) | `CSModule` |
| Hoodi | 1 | Curated (NodeOperatorsRegistry) | `NodeOperatorsRegistry` |
| Hoodi | 2 | SimpleDVT | `NodeOperatorsRegistry` |
| Hoodi | 3 | Sandbox | `NodeOperatorsRegistry` |
| Hoodi | 4 | Community Staking (CSM) | `CSModule` |
| Sepolia | 1 | | `NodeOperatorsRegistry` |

The sidecar picks the right contract automatically based on chain and module id.

When `enable_refreshing = true`, the sidecar periodically re-fetches keys from the on-chain registry at runtime. New validators that register with the node operator are picked up automatically without a restart, and validators removed from the registry are dropped from the mux (falling back to the global relays) on the same refresh cycle. The refresh interval is controlled by `mux_registry_refresh_interval_seconds` in the `[pbs]` configuration (default: `384` seconds, i.e. one epoch; must be greater than 0), and applies to all registry muxes with refreshing enabled.

---

#### SSV registry

Loads validator pubkeys from the SSV network. The sidecar first tries to fetch keys from your local SSV node API. If that fails, it falls back to the public SSV API.

No `[pbs]` settings are required: `ssv_node_api_url` and `ssv_public_api_url` are optional and default to `http://localhost:16000/v1/` (node API) and `https://api.ssv.network/api/v4/` (public API). Set them only to point at a different node or API server.

```toml
[pbs]
port = 18550
ssv_node_api_url = "http://localhost:16000/v1/"
ssv_public_api_url = "https://api.ssv.network/api/v4/"

[[mux]]
id = "ssv-mux"
loader = { registry = "ssv", node_operator_id = 200 }

[[mux.relays]]
id = "ssv-relay"
url = "..."
```

**Fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `registry` | string | Yes | Must be `"ssv"` |
| `node_operator_id` | integer | Yes | SSV node operator ID |
| `enable_refreshing` | boolean | No (default: `false`) | Whether to periodically refresh keys at runtime |

The loader tries two API sources in order:

1. **SSV node API** (preferred): `GET {ssv_node_api_url}validators` with a JSON body `{"operators": [node_operator_id]}`. Response contains a `data` array of validators with hex-encoded `public_key` fields.
2. **Public API** (fallback): `GET {ssv_public_api_url}{chain}/validators/in_operator/{node_operator_id}?perPage=100&page={page}` with pagination. Response contains a `validators` array and `pagination` object.

If the node API call fails (timeout, connection error, etc.), the sidecar logs a warning and falls back to the public API.

The public-API fallback supports Mainnet, Holesky, and Hoodi only; the node API path is chain-agnostic, so on other chains the loader works only while your local SSV node API is reachable.

---

#### Stader registry

Reads validator pubkeys from Stader's on-chain node registry. The sidecar connects to the configured RPC endpoint and queries the registry contract for the pool you specify.

`rpc_url` must be set in the `[pbs]` configuration, and `stader_pool` must be set in the mux config.

```toml
[pbs]
port = 18550
rpc_url = "https://ethereum-rpc.publicnode.com"

[[mux]]
id = "stader-mux"
loader = { registry = "stader", node_operator_id = 200, stader_pool = "permissioned" }

[[mux.relays]]
id = "stader-relay"
url = "..."
```

**Fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `registry` | string | Yes | Must be `"stader"` |
| `node_operator_id` | integer | Yes | Stader node operator ID |
| `stader_pool` | string | Yes | Stader staking pool: `"permissioned"` or `"permissionless"` |
| `enable_refreshing` | boolean | No (default: `false`) | Whether to periodically refresh keys at runtime |

Stader is supported on Mainnet only.

---

## Reference config

For a complete working example with multiple mux entries (File loader, Lido registry, SSV registry, and Stader registry), see:

- [`examples/configs/pbs_mux.toml`](https://github.com/Commit-Boost/commit-boost-client/blob/main/examples/configs/pbs_mux.toml)

---

## See also

- [Configuration reference](./configuration.md): full config field listing
- [Signer API](../developing/prop-commit-signing.md#api-quickstart): signing API quickstart and authentication
