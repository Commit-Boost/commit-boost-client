---
description: Mux (multiplexer) configuration and key loader types
---

# Mux key loaders

The PBS multiplexer (AKA *mux*) lets you route different validators to different relay sets or timing game configurations. Instead of a single `[[relays]]` list for all your validators, you declare one or more `[[mux]]` entries that match specific validator pubkeys to custom relay and timing settings.

Use a mux when you need:

- **Different relay sets for different validators** — for example, Lido or SSV node operators who send some validators to an operator-specific relay while the rest use the global relay set.
- **Per-group timing game parameters** — `timeout_get_header_ms` and `late_in_slot_time_ms` can be set per-mux, overriding the PBS defaults for those validators.
- **Dynamic key loading from on-chain or external sources** — the mux key loaders (File, URL, Registry) populate the mux's validator set automatically, so you don't have to list hundreds or thousands of pubkeys by hand.

Mux entries are an optional addition to the `[[relays]]` section. If you don't need per-validator routing, you can ignore this page entirely.

---

## Mux entry matching

Each `[[mux]]` entry declares a set of validator pubkeys. The mux system enforces that these sets are **disjoint** — a validator pubkey should appear in at most one mux entry. If a pubkey is duplicated across mux entries, the sidecar will refuse to start.

Matching uses **first-match semantics**: when the PBS receives a request for a validator, it checks each mux entry in the order they appear in the config file. The first mux whose pubkey set contains the validator's key wins. Validators that don't match any mux entry fall through to the global `[[relays]]` configuration.

```toml
# Global relays — used for validators not matching any mux
[[relays]]
id = "global-relay"
url = "..."

# First mux entry — checked first
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

### Matching rules summary

| Condition | Behaviour |
|---|---|
| Pubkey matches a mux entry | That mux's relays and timing config are used |
| Pubkey appears in multiple mux entries | Validation error — sidecar fails to start |
| Pubkey doesn't match any entry | Falls through to global `[[relays]]` |
| A mux has no pubkeys (empty set) | Validation error — each mux must have at least one pubkey |

The pubkey set for a mux can come from two sources combined:
1. **Inline `validator_pubkeys`** — a list of hex-prefixed BLS pubkeys in the config file itself.
2. **A loader plugin** — loads additional keys from a file, URL, or on-chain registry. Keys from the loader are merged into the mux's pubkey set.

---

## Key loaders

Key loaders are how you populate a mux with validator pubkeys without listing them manually. They are configured via the `loader` field inside a `[[mux]]` entry.

### File loader

Loads pubkeys from a flat JSON file on disk.

**Schema:** A JSON array of hex-prefixed BLS public key strings.

```json
[
    "0x8160998addda06f2956e5d1945461f33dbc140486e972b96f341ebf2bdb553a0e3feb127451f5332dd9e33469d37ca67",
    "0x87b5dc7f78b68a7b5e7f2e8b9c2115f968332cbf6fc2caaaaa2c9dc219a58206b72c924805f2278c58b55790a2c3bf17",
    "0x89e2f50fe5cd07ed2ff0a01340b2f717aa65cced6d89a79fdecc1e924be5f4bbe75c11598bb9a53d307bb39b8223bc52"
]
```

**Config:** Specify the path relative to the config file, or as an absolute path.

```toml
[[mux]]
id = "my-mux"
loader = "./path/to/keys.json"

[[mux.relays]]
id = "my-relay"
url = "..."
```

**Environment variable override:** The path can be overridden at runtime via `CB_MUX_PATH_{id}` where `{id}` is the mux identifier. For a mux with `id = "lido-mux"`, the variable would be `CB_MUX_PATH_lido-mux`. This is useful when you want to keep the config file the same across deployments but point to different key files.

```bash
export CB_MUX_PATH_lido-mux="/path/to/override.json"
```

---

### URL loader

Loads the same JSON schema from an HTTP(S) endpoint. The endpoint must return a JSON array of hex-prefixed BLS public keys (identical format to the File loader).

```toml
[[mux]]
id = "url-mux"
loader = { url = "https://keys.example.com/validators.json" }

[[mux.relays]]
id = "my-relay"
url = "..."
```

**Security:** HTTPS is recommended. HTTP URLs work but trigger a warning at startup.

**Request behaviour:**
- One-shot GET request — no retry logic.
- Timeout is controlled by `default_pbs.http_timeout_seconds` (default: 10s).
- The response body is read in full and parsed as JSON.

---

### Registry loader

Loads validator pubkeys from an on-chain or network registry. This resolves pubkeys automatically from a data source that stays in sync as validators are added or removed.

Two registries are currently supported:

| Registry | `registry` value | Key source | Authentication |
|---|---|---|---|
| Lido | `"lido"` | On-chain contract via RPC | RPC URL (from `[pbs]` config) |
| SSV | `"ssv"` | SSV node API or public API | SSV API URLs (from `[pbs]` config) |

#### Lido registry

Reads validator pubkeys from Lido's on-chain `NodeOperatorsRegistry` or `CSModule registry`, depending on the module type. The sidecar connects to the configured RPC endpoint and calls the contract's `getSigningKeys` method with pagination.

**Requirements:** `rpc_url` must be set in the `[pbs]` configuration.

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
| Sepolia | 1 | — | `NodeOperatorsRegistry` |

Module ids 1 and 2 use the `NodeOperatorsRegistry` contract. Module id 3 (Mainnet) and module id 4 (Holesky / Hoodi) use the `CSModule` (Community Staking Module) contract, which has a different ABI. The sidecar detects the module type automatically based on chain and module id.

**Dynamic refreshing:** When `enable_refreshing = true`, the sidecar periodically re-fetches keys from the on-chain registry at runtime. New validators that register with the node operator are picked up automatically without a restart. This is useful for growing node operator deployments where you don't want to restart the sidecar every time a new validator is added.

---

#### SSV registry

Loads validator pubkeys from the SSV network. The sidecar first tries to fetch keys from your local SSV node API. If that fails, it falls back to the public SSV API.

**Requirements:** `ssv_node_api_url` and `ssv_public_api_url` must be set in the `[pbs]` configuration.

```toml
[pbs]
port = 18550
ssv_node_api_url = "http://localhost:3030/"
ssv_public_api_url = "https://api.ssv.network/"

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

**API sources (fallback chain):**

1. **SSV node API** (preferred): `GET {ssv_node_api_url}validators` with a JSON body `{"operators": [node_operator_id]}`. Response contains a `data` array of validators with hex-encoded `public_key` fields.
2. **Public API** (fallback): `GET {ssv_public_api_url}{chain}/validators/in_operator/{node_operator_id}?perPage=100&page={page}` with pagination. Response contains a `validators` array and `pagination` object.

If the node API call fails (timeout, connection error, etc.), the sidecar logs a warning and falls back to the public API.

**Chains supported:** Mainnet, Holesky, and Hoodi.

---

## Reference config

For a complete working example with multiple mux entries — File loader, Lido registry, and SSV registry — see:

- [`examples/configs/pbs_mux.toml`](https://github.com/Commit-Boost/commit-boost-client/blob/main/examples/configs/pbs_mux.toml)

---

## See also

- [Configuration reference](./configuration.md) — full config field listing
- [Signer API](../developing/prop-commit-signing.md#api-quickstart) — signing API quickstart and authentication
