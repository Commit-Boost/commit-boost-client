# Project Context

## Domain Glossary

**Commit-Boost** — A modular sidecar for Ethereum validators. Runs alongside the beacon node, standardizing the last mile of communication between validators and third-party protocols (MEV-Boost relays, preconfirmation services, inclusion list services, etc.).

**Proposer-Builder Separation (PBS)** — The Ethereum protocol split where validators propose blocks but builders construct them. Commit-Boost acts as middleware between the beacon node's Builder API calls and external relays/builders.

**PBS Service** — The core service (`cb-pbs` crate) that implements the [Builder API](https://ethereum.github.io/builder-specs/). Receives `get_header`, `submit_block`, `register_validator`, and `get_status` calls from the beacon node, fans them out to configured relays, selects the best bid, and returns it.

**Signer Service** — A separate HTTP service (`cb-signer` crate) that holds validator consensus keys and creates signatures. Modules request signatures (BLS or ECDSA, via consensus keys or proxy keys) using JWT-authenticated HTTP calls. The signer *never* exposes private keys to modules.

**Commit Module** — A plugin (Docker container) that implements a specific proposer commitment protocol (e.g., preconfirmations, inclusion lists). Communicates with the Signer via the Signer Client (`SignerClient` in `cb-common`). Loaded as a separate process; configured in the main TOML config under `[modules]`.

**Builder API Module** — Like a commit module but plugs into the PBS request pipeline. Can add custom routes and override the default MEV-Boost behavior via the `BuilderApi` trait.

**Mux (Multiplexer)** — A configuration construct that routes different validator pubkeys to different sets of relays with different timing/config overrides. A "pubkey → mux" mapping. Supports loading pubkeys from: static file, HTTP endpoint, or Registry (Lido/SSV operator registries, with optional auto-refresh).

**Relay** — An external MEV-Boost relay that receives builder API calls. Defined by `scheme://pubkey@host` URL format. Supports timing games (delayed header requests), custom headers, GET params, and retry limits.

**Consensus Signer** — A BLS keypair loaded into the Signer (from keystore, Dirk, or other loader). Used to sign consensus-layer messages (e.g., preconfirmation commitments).

**Proxy Key** — A derived key (BLS or ECDSA) that a commit module generates via the Signer. The Signer creates a proxy delegation from a consensus key, allowing the module to sign messages without holding the consensus key. Proxy delegations can be persisted via a Proxy Store.

**Proxy Store** — Persistence for proxy key delegations. Ensures proxy keys survive restarts. Supports ERC-2335 keystore format or raw file.

**Dirk** — A remote signer backend (Attestant's Dirk). The Signer can delegate to Dirk for consensus signing, while still generating proxy keys locally. Note: ECDSA proxy signing is not supported with Dirk.

**Timing Games** — A relay-specific setting where the PBS service delays `get_header` requests until a specific time in the slot, then polls at a configured frequency. Used to give late builders an advantage.

**Registry Mux** — A mux whose pubkey list comes from a live operator registry (Lido CSM, Lido curated module, SSV network). The pubkey list auto-refreshes at a configurable interval.

**Fork-Versioned Response** — The pattern used for `get_header` and `submit_block` responses. Responses are wrapped in `ForkVersionedResponse<T>` (from lighthouse) which carries a fork version discriminator. The PBS service multiplexes across Electra and Fulu fork request/response shapes.

**Builder API Version** — `V1` for the standard Builder API, `V2` for the extended API (supports execution requests). Routes are nested under `/eth/v1/builder/` and `/eth/v2/builder/`.

## Architecture Map

```
┌─────────────────────────────────────────────────────────────────┐
│                      commit-boost binary                        │
│  Subcommands: pbs | signer | init                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────┐    ┌──────────────────────┐          │
│  │     PBS Service       │    │    Signer Service     │          │
│  │   (cb-pbs crate)      │    │   (cb-signer crate)   │          │
│  │                       │    │                       │          │
│  │  Routes:              │    │  Routes:              │          │
│  │  GET  get_header ─────│───▶│  POST request_sig_bls │          │
│  │  GET  get_status      │    │  POST request_sig_*   │          │
│  │  POST register_val    │    │  GET  get_pubkeys     │          │
│  │  POST submit_block    │    │  POST generate_proxy  │          │
│  │  POST reload          │    │  POST reload          │          │
│  │                       │    │  POST revoke_module   │          │
│  │  State:               │    │  GET  status          │          │
│  │  ┌─────────────────┐  │    │                       │          │
│  │  │ PbsState<S>     │  │    │  State:               │          │
│  │  │ config: PbsModCfg│ │    │  ┌───────────────┐    │          │
│  │  │ mux_lookup: K→V │  │    │  │ SigningState  │    │          │
│  │  │ relays: vec     │  │    │  │ manager: Mgr  │    │          │
│  │  │ data: S (ext)   │  │    │  │ jwts: K→V     │    │          │
│  │  └─────────────────┘  │    │  │ admin_secret  │    │          │
│  │                       │    │  └───────────────┘    │          │
│  │  BuilderApi trait:    │    │                       │          │
│  │  ┌─────────────────┐  │    │  SigningManager enum: │          │
│  │  │ get_header      │  │    │  ┌── LocalManager     │          │
│  │  │ get_status      │  │    │  └── DirkManager      │          │
│  │  │ submit_block    │  │    │                       │          │
│  │  │ register_val    │  │    │  LocalManager:        │          │
│  │  │ reload          │  │    │  ┌── consensus keys   │          │
│  │  │ extra_routes()  │  │    │  └── proxy keys       │          │
│  │  └─────────────────┘  │    │                       │          │
│  │                       │    │  Proxy store:         │          │
│  │  Fan-out to N relays  │    │  ┌── ERC2335 keystore │          │
│  │  Best bid selection   │    │  └── raw file         │          │
│  └───────────────────────┘    └───────────────────────┘          │
│           │                            │                         │
│           │ SignerClient               │ JWT auth middleware     │
│           │ (cb-common)                │ rate limiter            │
│           ▼                            ▼                         │
│  ┌────────────────────────────────────────────────────────┐     │
│  │                    cb-common crate                       │     │
│  │  ┌──────────┬──────────┬──────────┬──────────────────┐  │     │
│  │  │ config/  │ pbs/     │ commit/  │ signer/           │  │     │
│  │  │ Config   │ types    │ client   │ schemes (BLS/ECD) │  │     │
│  │  │ Mux      │ relay    │ request  │ loader            │  │     │
│  │  │ Module   │ builder  │ response │ store (ERC2335)   │  │     │
│  │  │ Signer   │ constants│ error    │ types             │  │     │
│  │  ├──────────┼──────────┼──────────┼──────────────────┤  │     │
│  │  │ interop/ │ types    │ utils    │ signature         │  │     │
│  │  │ lido/ssv │ Chain    │ JWT      │ verify_signed_msg │  │     │
│  │  └──────────┴──────────┴──────────┴──────────────────┘  │     │
│  └────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘

External:
  Beacon Node ──Builder API──▶ PBS Service
  PBS Service ──Builder API──▶ Relays (MEV-Boost)
  PBS Service ──Commit API───▶ Commit Modules (sidecars)
  Commit Modules ──Signer API─▶ Signer Service
  Signer Service ──gRPC──────▶ Dirk (optional remote signer)
```

## Crate Responsibilities

| Crate | Purpose | Key Public API |
|-------|---------|---------------|
| `cb-common` | Shared types, config, PBS types, signer types, commit client, interop | `Chain`, `PbsConfig`, `RelayClient`, `SignerClient`, `ModuleId`, `Jwt`, `get_header`, `submit_block` |
| `cb-pbs` | PBS service: routes, MEV-Boost relay fan-out, state management | `PbsService`, `PbsState`, `BuilderApi` trait, `DefaultBuilderApi` |
| `cb-signer` | Signer service: key management, signing endpoints, JWT auth | `SigningService`, `SigningManager`, `LocalSigningManager`, `DirkManager` |
| `cb-metrics` | Prometheus metrics provider | `MetricsProvider` |
| `cb-cli` | Docker compose init helper | `handle_docker_init` |

## Data Flow: get_header Request

```
Beacon Node
  │ GET /eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}
  ▼
create_app_router (routes/router.rs)
  │ Match GET_HEADER_PATH → handle_get_header
  ▼
handle_get_header (routes/get_header.rs)
  │ Extract GetHeaderParams, req headers
  │ Look up state.mux_config_and_relays(pubkey)
  │   → returns (PbsConfig, &[RelayClient], Option<mux_id>)
  ▼
mev_boost::get_header (mev_boost/get_header.rs)
  │ For each relay:
  │   If timing_games: delay then poll at frequency
  │   If not: immediate request
  │   Track best bid by value
  │   Optional extra validation: check EL block validity
  │ Return best GetHeaderResponse or None (204)
  ▼
Response to Beacon Node
```

## Key Configuration Flow

```
config.example.toml / CB_CONFIG env
  │
  ├── [chain] → Chain (Mainnet/Holesky/Sepolia/Hoodi/Custom)
  ├── [[relays]] → Vec<RelayConfig> → Vec<RelayClient>
  ├── [pbs] → StaticPbsConfig → PbsConfig
  ├── [[mux]] → PbsMuxes → HashMap<BlsPublicKey, RuntimeMuxConfig>
  ├── [[modules]] → Vec<StaticModuleConfig> → module Docker containers
  └── [signer] → SignerConfig → StartSignerConfig
```

## Relationships

- **PBS Service → Signer Service**: Uses `SignerClient` (from `cb-common`) to request signatures. Only when `with_signer = true` in PBS config.
- **Commit Module → Signer Service**: Each module gets its own JWT. Calls signer endpoints for consensus/proxy BLS/ECDSA signatures.
- **PBS Service → Relays**: Fans out Builder API calls. One HTTP client per relay. Timing games per relay. Mux routing per validator pubkey.
- **Signer Service → Dirk**: Delegates consensus signing to Dirk gRPC backend. Proxy key generation still local.
- **PBS Mux → Registry**: Lido CSM/module or SSV operator registries queried for validator pubkey lists. Auto-refresh for dynamic sets.

## Flagged Ambiguities

- **Module vs sidecar vs plugin**: The codebase uses "module" for the signer auth system (`ModuleId`, `ModuleSigningConfig`), but the PBS service also refers to "modules" (builder API plugins like preconfirmations). These are different concepts sharing one term.
- **PBS Config reload**: The PBS service watches the config file and hot-reloads on change. The signer also supports reload via admin API. These are independent mechanisms.
- **Custom chain support**: `Chain::Custom` allows any chain with genesis params. Some interop features (SSV) only support Mainnet/Holesky/Hoodi.

## Example Dialogue

**"How does a validator use Commit-Boost with MEV-Boost?"**
→ Configure relays in `[[relays]]`, set `[pbs]` options, run `commit-boost pbs`. Beacon node points Builder API at Commit-Boost. Commit-Boost fans out to relays, returns best bid. Optional: add timing games per relay.

**"How do I add a preconfirmation module?"**
→ Add `[[modules]]` entry with `type = "commit"`, `id`, `docker_image`, and `signing_id`. The module container gets `MODULE_JWT` and `SIGNER_URL` env vars. It calls `SignerClient` to request consensus/proxy signatures. Add `jwt_secret` to JWT secrets file.

**"What is a mux and when do I need it?"**
→ A mux routes specific validator pubkeys to specific relay sets with custom timeouts. Use when different validators under the same node operator need different relay configurations, or when integrating with SSV/Lido operator registries for automatic pubkey discovery.
