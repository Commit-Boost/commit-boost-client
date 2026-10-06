---
sidebar_label: "Metrics catalog"
---

# Metrics catalog

Every metric emitted by the Commit-Boost PBS and Signer services, together with the runtime-registered build-info metric from the shared telemetry crate. Useful when building dashboards or writing alerting rules. For scrape and port setup, see [Metrics](./metrics.md).

---

## PBS metrics

PBS metrics use a custom Prometheus registry with namespace prefix `cb_pbs_`. The registry is created via `Registry::new_custom(Some("cb_pbs"), None)` in `crates/pbs/src/metrics.rs`. All wire names shown below include this prefix. (unreleased, from v0.12.0-rc1) ePBS requests to a builder outside your config are labeled `relay_id="dial"`.

| Metric name (wire) | Type | Labels | Description |
|---|---|---|---|
| `cb_pbs_relay_status_code_total` | Counter | `http_status_code`, `endpoint`, `relay_id` | HTTP status code received by relay. Incremented once per relay response. Two synthetic codes stand in for outcomes that never reach a status line: `"555"` when no response arrived (over HTTP a timeout, DNS or connection failure; on a stream, the bid window ran out before the handshake completed), and `"556"` for a bid-stream transport failure (connect failed, the stream broke before a bid, or the handshake was answered with a `2xx` other than `204`). (unreleased, from v0.12.0-rc1) A `204` answer to the handshake records `204`. Endpoint values: `get_header`, `get_header_stream`, `register_validator`, `submit_blinded_block`, `status`, and (unreleased, from v0.12.0-rc1) `get_execution_payload_bid`, `get_execution_payload_bid_stream`, `submit_builder_preferences`, `submit_signed_beacon_block`. |
| `cb_pbs_relay_latency` | Histogram | `endpoint`, `relay_id` | HTTP latency (duration in seconds) by relay. Records the duration of relay HTTP requests. Endpoint values: `get_header`, `get_header_stream`, `register_validator`, `submit_blinded_block`, `status`, and (unreleased, from v0.12.0-rc1) `get_execution_payload_bid`, `get_execution_payload_bid_stream`, `submit_builder_preferences`, `submit_signed_beacon_block`. Under the two stream endpoints the observation is the time from opening the websocket to the first bid update, not a round trip, and a window that received no bid records nothing. |
| `cb_pbs_relay_last_slot` | Gauge | `relay_id` | Latest slot for which a relay delivered a bid. Set to the current slot on each successful `get_header` bid and (unreleased, from v0.12.0-rc1) each ePBS bid served from that relay. |
| `cb_pbs_relay_header_value` | Gauge | `relay_id` | Value in gwei of the bid a relay delivered: for `get_header`, the bid's value converted from wei (÷ 1e9). (unreleased, from v0.12.0-rc1) For a streaming relay, the better of its HTTP and stream bids. For ePBS, the returned bid's `value`, without its execution payment. |
| `cb_pbs_relay_stream_connect_latency` | Histogram | `endpoint` (unreleased, from v0.12.0-rc1), `relay_id` | Websocket handshake latency in seconds, for a relay with `get_header = "stream"`. Observed once per successful handshake; a handshake that fails, runs out the bid window, or is answered `204` records nothing here. Custom buckets from 5 ms to 1 s. Endpoint values: `get_header_stream`, `get_execution_payload_bid_stream`. |
| `cb_pbs_relay_stream_updates` | Histogram | `endpoint` (unreleased, from v0.12.0-rc1), `relay_id` | Bid updates accepted on arrival per stream: on `get_header_stream`, every frame whose message type and fork byte can be read; on `get_execution_payload_bid_stream`, every bid that decodes. Observed once per stream that connected, including streams that received nothing; a handshake that fails, times out or is answered `204` records nothing. Buckets: `0, 1, 2, 3, 5, 10, 20, 50, 100`. Endpoint values: `get_header_stream`, `get_execution_payload_bid_stream`. |
| `cb_pbs_relay_stream_invalid_frames_total` | Counter | `endpoint` (unreleased, from v0.12.0-rc1), `relay_id` | Websocket frames whose message type or fork byte cannot be read; on the ePBS stream, also bids that fail to decode. Incremented only for windows that saw at least one, so the series is absent while zero. Endpoint values: `get_header_stream`, `get_execution_payload_bid_stream`. |
| `cb_pbs_relay_stream_fallback_total` | Counter | `endpoint` (unreleased, from v0.12.0-rc1), `relay_id` | (unreleased, from v0.12.0-rc1; in v0.11.0, handshake failures retried over HTTP) Bid streams that failed while the relay's HTTP request ran alongside: a connection or handshake that failed or timed out, a stream that broke before a bid, or, on `get_header_stream`, a window in which every held bid was invalid. A `204` answer to the handshake is no bid and does not count. Counts every failed stream, whether or not the HTTP request returned a bid; the HTTP result is recorded under `endpoint="get_header"` (or `get_execution_payload_bid`). Endpoint values: `get_header_stream`, `get_execution_payload_bid_stream`. |
| `cb_pbs_beacon_node_status_code_total` | Counter | `http_status_code`, `endpoint` | HTTP status code returned to the beacon node. Tracks what status codes the PBS returns for beacon node-facing requests. Endpoint values: `get_header`, `register_validator`, `submit_blinded_block`, `status`, `reload`, and (unreleased, from v0.12.0-rc1) `get_execution_payload_bid`, `submit_builder_preferences`, `submit_signed_beacon_block`. Error status codes (`502` for `NoResponse`/`NoPayload`, `500` for `Internal`) are set via `PbsClientError`. The handlers also record `406` directly when the request's `Accept` header offers no supported encoding, `204` when no bid is available on `get_header`, and `202` for accepted v2 `submit_blinded_block` requests. (unreleased, from v0.12.0-rc1) The ePBS endpoints record `200` for a bid, `204` for none, `202` for accepted preferences and for every signed block it forwards, `400` for a request Commit-Boost refuses, a builder's own `400` or `401`, `406` for a bid request whose `Accept` offers no supported encoding, `415` for an unsupported `Content-Type`, and `500` when no builder accepts the preferences. |
| `cb_pbs_pbs_submit_block_v2_unsupported_total` | Counter | `relay_id` | Count of v2 `submit_blinded_block` requests a relay could not serve because it returned 404 on the v2 endpoint. A non-zero value means the relay does not support `submitBlindedBlockV2` and those blocks were not submitted via that relay. The double `pbs` in the wire name comes from the registry prefix plus the metric name `pbs_submit_block_v2_unsupported_total`. |

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
