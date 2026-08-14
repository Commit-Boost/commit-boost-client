---
sidebar_label: "Metrics catalog"
---

# Metrics catalog

Every metric emitted by the Commit-Boost PBS and Signer services, together with the runtime-registered build-info metric from the shared telemetry crate. Useful when building dashboards or writing alerting rules. For scrape and port setup, see [Metrics](./metrics.md).

---

## PBS metrics

PBS metrics use a custom Prometheus registry with namespace prefix `cb_pbs_`. The registry is created via `Registry::new_custom(Some("cb_pbs"), None)` in `crates/pbs/src/metrics.rs`. All wire names shown below include this prefix.

| Metric name (wire) | Type | Labels | Description |
|---|---|---|---|
| `cb_pbs_relay_status_code_total` | Counter | `http_status_code`, `endpoint`, `relay_id` | HTTP status code received by relay. Incremented after each relay HTTP response; `http_status_code` may be `"555"` (the value of `TIMEOUT_ERROR_CODE_STR`) for timeouts, or `"556"` (the value of `TRANSPORT_ERROR_CODE`) for WebSocket transport failures on the `get_header` bids stream (unreleased, from v0.11). Endpoint values: `get_header`, `register_validator`, `submit_blinded_block`, `status`. |
| `cb_pbs_relay_latency` | Histogram | `endpoint`, `relay_id` | HTTP latency (duration in seconds) by relay. Records duration of relay HTTP requests. Endpoint values: `get_header`, `register_validator`, `submit_blinded_block`, `status`. |
| `cb_pbs_relay_last_slot` | Gauge | `relay_id` | Latest slot for which a relay delivered a header. Only updated in the `get_header` handler. Set to the current slot on each successful header from that relay. |
| `cb_pbs_relay_header_value` | Gauge | `relay_id` | Header value in gwei delivered by a relay. Converted from raw wei (÷ 1e9) in the `get_header` handler. |
| `cb_pbs_beacon_node_status_code_total` | Counter | `http_status_code`, `endpoint` | HTTP status code returned to the beacon node. Tracks what status codes the PBS returns for beacon node-facing requests. Endpoint values: `get_header`, `register_validator`, `submit_blinded_block`, `status`, `reload`. Error status codes (`502` for `NoResponse`/`NoPayload`, `500` for `Internal`) are set via `PbsClientError`. The handlers also record `406` directly when the request's `Accept` header offers no supported encoding (unreleased, from v0.11 content negotiation), `204` when no bid is available on `get_header`, and `202` for accepted v2 `submit_blinded_block` requests. |
| `cb_pbs_pbs_submit_block_v2_unsupported_total` | Counter | `relay_id` | (unreleased, from v0.11) Count of v2 `submit_blinded_block` requests a relay could not serve because it returned 404 on the v2 endpoint. A non-zero value means the relay does not support `submitBlindedBlockV2` and those blocks were not submitted via that relay. The double `pbs` in the wire name comes from the registry prefix plus the metric name `pbs_submit_block_v2_unsupported_total`. |

---

## Signer metrics

Signer metrics use a custom Prometheus registry with namespace prefix `cb_signer_`. The registry is created via `Registry::new_custom(Some("cb_signer"), None)` in `crates/signer/src/metrics.rs`. Wire names include this prefix.

| Metric name (wire) | Type | Labels | Description |
|---|---|---|---|
| `cb_signer_signer_status_code_total` | Counter | `http_status_code`, `endpoint` | HTTP status code returned by signer endpoints. Incremented as responses are sent. Endpoint values: `get_pubkeys`, `generate_proxy_key`, `request_signature_bls`, `request_signature_proxy_bls`, `request_signature_proxy_ecdsa`, and `unknown endpoint` (emitted for the admin routes `/reload` and `/revoke_jwt`, which are matched by the router but not mapped to a named tag). |

---

## Build-info metric (all services)

When each service starts its metrics HTTP server (via the `MetricsProvider` from the `cb-metrics` crate), a runtime-registered gauge is added to its registry:

| Metric name (wire) | Type | Labels | Description |
|---|---|---|---|
| `info` | Gauge | `version`, `commit`, `network` | Always `1`. Carries build metadata as Prometheus const labels. The `version` label is the crate version (`CARGO_PKG_VERSION`), `commit` is the Git hash at build time (`GIT_HASH`), and `network` is the chain name (e.g. `Mainnet`, `Holesky`, `Sepolia`, `Hoodi`, or `Custom` for custom chain specs). |

This metric appears under the service's own registry prefix: the PBS instance exposes it as `cb_pbs_info{version="...",commit="...",network="..."}` and the Signer exposes it as `cb_signer_info{version="...",commit="...",network="..."}`.

---

## Custom module metrics

Commit modules can register their own metrics via the `prometheus` crate. The module's metrics HTTP server port comes from `CB_METRICS_PORT` (see [Running > Binary](./binary.md#common)). To expose custom metrics:

1. Create a custom `Registry` (optionally with a namespace prefix).
2. Register your metrics on that registry.
3. Call `MetricsProvider::load_and_run(chain, registry)` to serve the registry on the module's `/metrics` endpoint. Alternatively, construct a `ModuleMetricsConfig` and pass it to `MetricsProvider::new()`, then spawn `provider.run()` yourself.

All module metrics are served on a separate port and are **not** aggregated into the PBS or Signer registries. To collect them, add the module's metrics port as an additional scrape target in your Prometheus configuration.
