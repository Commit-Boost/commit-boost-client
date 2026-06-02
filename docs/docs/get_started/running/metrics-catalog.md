---
sidebar_label: "Metrics catalog"
---

# Metrics catalog

This page lists every metric emitted by the Commit-Boost PBS and Signer services together with the runtime-registered build-info metric from the shared telemetry crate. Use this as a reference when building dashboards or writing alerting rules.

---

## PBS metrics

PBS metrics use a custom Prometheus registry with namespace prefix `cb_pbs_`. The registry is created via `Registry::new_custom(Some("cb_pbs"), None)` in `crates/pbs/src/metrics.rs`. All wire names shown below include this prefix.

| Metric name (wire) | Type | Labels | Description |
|---|---|---|---|
| `cb_pbs_relay_status_code_total` | Counter | `http_status_code`, `endpoint`, `relay_id` | HTTP status code received by relay. Incremented after each relay HTTP response; `http_status_code` may be `"555"` (the value of `TIMEOUT_ERROR_CODE_STR`) for timeouts. Endpoint values: `get_header`, `register_validator`, `submit_blinded_block`, `status`. |
| `cb_pbs_relay_latency` | Histogram | `endpoint`, `relay_id` | HTTP latency (duration in seconds) by relay. Records duration of relay HTTP requests. Endpoint values: `get_header`, `register_validator`, `submit_blinded_block`, `status`. |
| `cb_pbs_relay_last_slot` | Gauge | `relay_id` | Latest slot for which a relay delivered a header. Only updated in the `get_header` handler. Set to the current slot on each successful header from that relay. |
| `cb_pbs_relay_header_value` | Gauge | `relay_id` | Header value in gwei delivered by a relay. Converted from raw wei (÷ 1e9) in the `get_header` handler. |
| `cb_pbs_beacon_node_status_code_total` | Counter | `http_status_code`, `endpoint` | HTTP status code returned to the beacon node. Tracks what status codes the PBS returns for beacon node-facing requests. Endpoint values: `get_header`, `register_validator`, `submit_blinded_block`, `status`, `reload`. Error status codes (`502` for `NoResponse`/`NoPayload`, `500` for `Internal`) are set via `PbsClientError`. |

---

## Signer metrics

Signer metrics use a custom Prometheus registry with namespace prefix `cb_signer_`. The registry is created via `Registry::new_custom(Some("cb_signer"), None)` in `crates/signer/src/metrics.rs`. Wire names include this prefix.

| Metric name (wire) | Type | Labels | Description |
|---|---|---|---|
| `cb_signer_signer_status_code_total` | Counter | `http_status_code`, `endpoint` | HTTP status code returned by signer endpoints. Incremented as responses are sent. Endpoint values: `get_pubkeys`, `generate_proxy_key`, `request_signature_bls`, `request_signature_proxy_bls`, `request_signature_proxy_ecdsa`. |

---

## Build-info metric (all services)

When each service starts its metrics HTTP server (via the `MetricsProvider` from the `cb-metrics` crate), a runtime-registered gauge is added to its registry:

| Metric name (wire) | Type | Labels | Description |
|---|---|---|---|
| `info` | Gauge | `version`, `commit`, `network` | Always `1`. Carries build metadata as Prometheus const labels. The `version` label is the crate version (`CARGO_PKG_VERSION`), `commit` is the Git hash at build time (`GIT_HASH`), and `network` is the chain name (e.g. `mainnet`, `holesky`, `ephemery`). |

This metric appears under the service's own registry prefix — for example, the PBS instance exposes it as `cb_pbs_info{version="...",commit="...",network="..."}` and the Signer exposes it as `cb_signer_info{version="...",commit="...",network="..."}`.

---

## Custom module metrics

Commit-Modules can register their own metrics via the `prometheus` crate. Each module receives a `ModuleMetricsConfig` at init time which includes the `server_port` for its metrics HTTP server. To expose custom metrics:

1. Create a custom `Registry` (optionally with a namespace prefix).
2. Register your metrics on that registry.
3. Pass the registry to `MetricsProvider::new()` or `MetricsProvider::load_and_run()` to serve them on the module's `/metrics` endpoint.

All module metrics are served on a separate port and are **not** aggregated into the PBS or Signer registries. To collect them, add the module's metrics port as an additional scrape target in your Prometheus configuration.
