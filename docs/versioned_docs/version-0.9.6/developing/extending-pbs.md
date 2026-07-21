---
sidebar_position: 2
---

# Extending PBS

The PBS binary that ships with Commit-Boost can be extended with custom logic. This is **not** a config-level module declaration like commit modules — instead you replace the PBS binary entirely by implementing the `DefaultBuilderApi` trait.

## Before you extend PBS

| You want to... | Use... |
|---|---|
| Request signatures from the proposer's validator keys (BLS/ECDSA) | [Commit Module](./commit-modules.md) — runs as a sidecar alongside PBS |
| Add custom constraints to `get_header`, `submit_block`, or other BuilderAPI methods | Extend PBS — replace the `DefaultBuilderApi` with your own implementation |
| Run custom logic that triggers on each slot but does not modify relay interaction | Commit Module — cheaper to maintain and deploy independently |
| Add new HTTP routes alongside the standard BuilderAPI | Extend PBS — implement `extra_routes()` on your custom `BuilderApi` |

**Rule of thumb:** if you need to change how relay responses are filtered, validated, or transformed, extend PBS. If you want to request signatures or run slot-triggered logic independently, write a Commit Module.

## How it works

The PBS binary ships with the [`DefaultBuilderApi`](https://github.com/Commit-Boost/commit-boost-client/blob/main/crates/pbs/src/api.rs) struct, which implements [`BuilderApi<S>`](https://github.com/Commit-Boost/commit-boost-client/blob/main/crates/pbs/src/api.rs) with default (MEV-Boost-compatible) behavior for each method.

The trait covers:

- `get_header` — fetch the best header from relays
- `get_status` — check relay health
- `submit_block` — publish blinded blocks
- `register_validator` — register validators with relays
- `reload` — hot-reload configuration
- `extra_routes` — add custom HTTP endpoints

By implementing `BuilderApi<S>` on your own struct, you can override any of these methods while reusing the default MEV-Boost logic by calling the corresponding free functions (`crate::get_header`, etc.) from within your override.

### Reference example

See [`examples/status_api/`](https://github.com/Commit-Boost/commit-boost-client/tree/main/examples/status_api) for a complete working example that:

1. Defines a custom `ExtraConfig` struct with additional TOML fields (`inc_amount`).
2. Creates a custom `BuilderApiState` (`MyBuilderState`) to hold runtime state.
3. Implements `BuilderApi<MyBuilderState>` that overrides `get_status` with custom logging and a counter, and adds a `/check` route via `extra_routes()`.
4. Loads config with `load_pbs_custom_config::<ExtraConfig>()` and starts the service with `PbsService::run::<_, MyBuilderApi>(state)`.

## Building and running a custom PBS binary

### Dependencies

Add the `commit-boost` crate to your `Cargo.toml`:

```toml
commit-boost = { git = "https://github.com/Commit-Boost/commit-boost-client", version = "..." }
```

### Entry point

Your `main.rs` should:

1. Define your extra config (if any):

```rust
#[derive(Debug, Deserialize)]
struct ExtraConfig {
    inc_amount: u64,
}
```

2. Define your state (if any):

```rust
#[derive(Clone)]
struct MyBuilderState { /* ... */ }
impl BuilderApiState for MyBuilderState {}
```

3. Implement `BuilderApi<MyBuilderState>`:

```rust
struct MyBuilderApi;

#[async_trait]
impl BuilderApi<MyBuilderState> for MyBuilderApi {
    // Override methods here
}
```

4. Load config and run:

```rust
let (pbs_config, extra) = load_pbs_custom_config::<ExtraConfig>().await?;
let state = PbsState::new(pbs_config, config_path).with_data(MyBuilderState::from_config(extra));
PbsService::run::<MyBuilderState, MyBuilderApi>(state).await
```

### Running

Compile and run your binary. Set the same environment variables as the default PBS (see [Running with binary](../get_started/running/binary.md)). Your custom PBS handles the same BuilderAPI endpoints plus any extra routes you added.

## Cross-reference

For system context on how PBS fits into the Commit-Boost architecture, see [Architecture Overview](../architecture/overview.md).
