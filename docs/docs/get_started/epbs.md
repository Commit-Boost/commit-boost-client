---
description: Run Commit-Boost for ePBS proposals after the Gloas fork
---

# ePBS

:::info Unreleased
ePBS support is not in a Commit-Boost release yet; it ships from v0.12.0-rc1.
:::

From the Gloas fork, a proposer commits to a builder's signed execution payload bid instead of a blinded header, and the winning builder publishes the payload itself. Commit-Boost serves the builder-API endpoints the beacon node calls for this and forwards each call to builders, relays, or MPBC operators.

## What changes at the fork

Normal PBS paths are unaffected. From the Gloas fork, apart from the `status` endpoint, the beacon node calls three new endpoints on Commit-Boost:

| Endpoint | What the beacon node sends | What Commit-Boost does |
|---|---|---|
| `POST /eth/v1/builder/execution_payload_bid/{slot}/{parent_hash}/{parent_root}/{proposer_pubkey}` | A bid request for the proposal slot | Asks the [addressed](#routing-by-auth-data) builder for its bid |
| `POST /eth/v1/builder/builder_preferences/{proposer_pubkey}` | The proposer's `max_execution_payment` for one builder, ahead of the slot | Forwards it to the addressed builder |
| `POST /eth/v1/builder/beacon_blocks` | The signed beacon block that commits to the winning bid | Forwards it to every builder in `[[relays]]` and `[[mux.relays]]` |

With ePBS the beacon node validates each bid and weighs it against your builder config (`min_bid`, `builder_boost_factor`) and its local block, so Commit-Boost adds no redundant verification on the hot path.

The ePBS bid endpoint does not use these PBS options, which will be deprecated after the hard fork:

- `skip_sigverify`, `min_bid_eth` and `extra_validation_enabled`: the beacon node checks the bid against the on-chain builder registry and applies the `min_bid` from its builder config.
- `timeout_get_header_ms`, `late_in_slot_time_ms`, their `[[mux]]` overrides and the timing-games options: the beacon node's deadline bounds the request (see [Timing](#timing)).

For a builder whose relay entry sets `get_header = "stream"`, Commit-Boost reads its bids from a [stream](#bid-streaming).

## How a bid request reaches a builder

From the fork, each validator key has a builder config: a list of entries, each a `url` and an `auth_data`. For every entry the beacon node sends a bid request to the entry's `url`, carrying its `auth_data` in a `SignedBuilderRequestAuth` that the validator signs. `auth_data` tells a builder that a request was meant for it, so a request signed for one builder is rejected by another. Unless the proposer and builder agree on another value, it is the builder's hostname.

To go through Commit-Boost, every entry's `url` is Commit-Boost's own URL, and its `auth_data` is the hostname of the builder it stands for. Commit-Boost reads the `auth_data` of each request, finds the relay entry with that hostname and forwards the request there. If no relay entry has it, Commit-Boost dials the builder the `auth_data` names ([builders outside your config](#builders-outside-your-config)). Builder preferences are routed the same way. The signed block goes to every builder in your config, since Commit-Boost does not track which bid won.

## Setup

### 1. Add the builders to Commit-Boost

List each builder as a relay entry, as for PBS: in `[[relays]]`, or in the `[[mux.relays]]` of the mux that lists the proposer's key. A key can still reach a builder you do not list, unless you set `[pbs] dial_unconfigured_builders = false` (see [Builders outside your config](#builders-outside-your-config)).

### 2. Point each validator key at Commit-Boost {#validator-builder-config}

Write each key's builder config through its validator client's keymanager API, which must implement the builder config endpoint ([keymanager-APIs #88](https://github.com/ethereum/keymanager-APIs/pull/88)). Add one entry per builder: `url` is Commit-Boost's URL, and `auth_data` is the hex of the builder's hostname. A key without builder config gets no bids through Commit-Boost ([builders outside your config](#builders-outside-your-config)).

With the relay entry `url = "https://0xa1ce...@builder-a.example.com"`, Commit-Boost listening at `http://cb.example.com:18550`, the keymanager API at `$KEYMANAGER_URL`, its token in `$TOKEN` and the validator key in `$PUBKEY`:

```bash
curl -X POST "$KEYMANAGER_URL/eth/v1/validator/$PUBKEY/builder_config" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "builders": [
      {
        "url": "http://cb.example.com:18550",
        "auth_data": "0x6275696c6465722d612e6578616d706c652e636f6d",
        "builder_pubkeys": []
      }
    ]
  }'
```

`echo 0x$(printf builder-a.example.com | xxd -p | tr -d '\n')` prints the `auth_data` hex.

The call is `POST /eth/v1/validator/{pubkey}/builder_config`, authenticated with the keymanager API's bearer token. The body replaces the key's config in full, and the validator client answers `202` once it is stored. Besides `url` and `auth_data`, an entry or the top level can set:

- `min_bid` and `builder_boost_factor` are optional. At the top level they apply to p2p bids and to every entry that does not set its own, so a top-level `min_bid` above your builders' bids sends every proposal to a p2p bid or a local block, unless an entry sets a lower one of its own.
- `max_execution_payment`, when an entry omits it, gets the validator client's default, which differs between clients and can be `0`, so no execution payment counts. Lodestar accepts a nonzero value only when started with `--allowDangerousTrustedPayments`.
- `builder_pubkeys` limits which builder keys' bids the beacon node accepts; leave it empty to accept any. Don't copy the pubkey from the relay URL: that is the relay's key, not the builder's bid-signing key.

## Routing by auth data

Commit-Boost sends a bid or preferences request to the first builder whose URL hostname equals the request's `auth_data`, byte for byte. That is the [builder specs](https://github.com/ethereum/builder-specs/blob/main/specs/gloas/validator.md#default-auth-data) default auth data: the lowercase ASCII hostname (punycode for an internationalized name), without scheme, port or path, with an IPv6 address compressed and in brackets, such as `[::1]`. Builders on one host share it, so only the first is asked. Commit-Boost looks first among the relays serving the proposer's key (those of its `[[mux]]`, otherwise `[[relays]]`), then among `[[relays]]` in config order, so a key in a mux still reaches a `[[relays]]` builder through that entry, with its headers, path and port. A builder listed only in another mux's `[[mux.relays]]` is not used for this key: it is dialed like a builder outside your config.

`auth_data` can also be an `http` or `https` URL agreed with a builder. It then matches the first builder whose `url` has the same scheme, host and port; the path and the pubkey in the relay URL do not count, so builders on one origin share it. Any other value agreed with a builder does not route through Commit-Boost. When no builder matches, Commit-Boost [dials the builder](#builders-outside-your-config) the `auth_data` names, and answers `400` when the `auth_data` is neither in that hostname form nor an `http(s)` URL.

Either form may end in `?` and form-encoded parameters for the builder, such as `builder-a.example.com?ofac=1`. Commit-Boost routes on the part before `?`. The parameters reach the builder inside the signed auth, so set them only for a builder that accepts them; one that does not answers `400`.

## Builders outside your config {#builders-outside-your-config}

A key's builder config may name a builder you have not added as a relay entry. Commit-Boost dials that builder anyway: a hostname at `https://<hostname>` on the default port, and a URL at its scheme, host and port. It answers `400` instead when the host does not resolve, or resolves to any address that is not public unicast, such as a loopback, private, link-local or `100.64.0.0/10` address, so a builder on your own network has to be a relay entry. These requests connect directly, ignoring `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`, follow no redirects and do not carry your relay `headers`. A builder reached this way gets the signed block over gossip, unless it is also a relay entry in `[[relays]]` or a mux. Neither `[[relays]]` nor a mux's relays limit which builders a key can reach this way, and anyone who can reach Commit-Boost's port can make it dial a public host, so keep that port private. Commit-Boost looks up at most 32 of these hosts at once and answers further requests as if the builder had not responded, as it does when a lookup runs out of the request's time.

To turn dialing off, set `dial_unconfigured_builders = false` in `[pbs]`. Commit-Boost then answers `400` instead of dialing.

On a validator client whose builder URL is Commit-Boost, a key without builder config sends Commit-Boost's own hostname as its `auth_data`, so it gets no bids: unless a relay entry has that hostname, which then gets the request, Commit-Boost answers `400` without dialing. A client that sends Commit-Boost's full URL instead also gets `400`. Commit-Boost never dials for a request that came from another Commit-Boost, so chained Commit-Boosts route only through relay entries.

## Timing

The builder specs require each bid request to carry `Date-Milliseconds` and `X-Timeout-Ms`, which together say how long the beacon node will wait for a bid. Commit-Boost subtracts `[pbs] proposer_deadline_buffer_ms` (default `20`) from the time remaining and sends the result to the builder as its `X-Timeout-Ms`, so the builder knows how long it has to answer. For a builder outside your config, the time its lookup took is subtracted too.

The buffer is the time Commit-Boost's answer needs to reach the beacon node, which discards answers that arrive after its deadline. Commit-Boost's own share is a few milliseconds, so the default suits a beacon node on the same host. When Commit-Boost and the beacon node run on different hosts, raise it by the time a response takes to travel from Commit-Boost to the beacon node, plus any difference between the two hosts' clocks, since Commit-Boost reads the beacon node's `Date-Milliseconds` against its own clock. It must be above `0` and under one slot, `12000` on mainnet. If no time is left, Commit-Boost does not ask the builder. With `0`, Commit-Boost refuses to start or reload: the builder gets the whole deadline, so a bid it sends at the deadline reaches the beacon node late.

Builder preferences use `timeout_register_validator_ms`, and the signed block `timeout_get_payload_ms`.

## Bid streaming

A builder answers an HTTP bid request once, so a better bid it makes after answering never reaches the beacon node. Over a websocket stream it can keep sending bids until just before the beacon node's deadline.

Ask the builder whether it serves the ePBS bid stream, at `ws(s)://<relay host>/eth/v1/builder/execution_payload_bid_stream/{slot}/{parent_hash}/{parent_root}/{proposer_pubkey}`. If it does, set `get_header = "stream"` on its relay entry. Before the fork the same setting reads the builder's `get_header` bids from its [PBS stream](./configuration.md#bid-streaming), so for a builder that serves only one of the two, Commit-Boost logs a failed stream on each request to the other and asks over HTTP instead. The handshake carries the relay entry's `headers`, so a builder that requires an [API key](./configuration.md#relay-api-keys) gets it.

For each bid request to a streaming builder, Commit-Boost opens the stream and returns the latest streamed bid that decodes. Only a stream that fails to connect, because of a connection error or a handshake answered with anything but the upgrade, `204` included, is retried over HTTP with the time left. A handshake still unanswered at the deadline, or a stream that breaks before a bid, is no bid. A builder [outside your config](#builders-outside-your-config) is always asked over HTTP. If a builder has two relay entries, one on `"stream"` and one on `"http"`, only the first that matches the key's auth data serves ePBS bids.

Streaming makes bid requests slower. Commit-Boost replies to the beacon node once the stream has ended: when the builder closes it, when it fails, or at the beacon node's deadline less `proposer_deadline_buffer_ms`. After a retry over HTTP, it replies once that request answers. A bid request to an HTTP builder is answered as soon as the builder responds. `timeout_get_header_ms` does not shorten the wait. If the beacon node reports bid requests timing out on streaming builders, raise `proposer_deadline_buffer_ms`.

The stream connects directly, ignoring `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`, while the HTTP fallback uses them. If your host reaches builders only through a proxy, keep them on `"http"`.

## Metrics

With [metrics](./running/metrics.md) enabled, the ePBS endpoints use the `endpoint` labels `get_execution_payload_bid`, `submit_builder_preferences` and `submit_signed_beacon_block`, and a [streaming](#bid-streaming) builder's stream uses `get_execution_payload_bid_stream`, with its own `cb_pbs_relay_epbs_stream_*` series ([Metrics > Bid stream](./running/metrics.md#bid-stream)).

| Question | Series |
|---|---|
| What did Commit-Boost answer the beacon node? | `cb_pbs_beacon_node_status_code_total`: `200` or `204` for a bid request, `202` for preferences, `202` for the signed block whatever the builders answer, `4xx` for a rejected request, `500` when no builder accepted the preferences or on an internal error |
| What did each builder answer? | `cb_pbs_relay_status_code_total`, by `relay_id`: the builder's HTTP status, or `555` when no response arrived (timeout, DNS or connection failure; on the bid stream, only the deadline). Requests to builders outside your config count under `relay_id="dial"`; a dial Commit-Boost [refuses](#builders-outside-your-config), or whose lookup fails, times out or finds no free slot, sends no request and is not counted |
| How fast are builders? | `cb_pbs_relay_latency`, by `relay_id` |
| Is a builder's bid stream working? | `cb_pbs_relay_status_code_total{endpoint="get_execution_payload_bid_stream"}`: `200` when the stream supplied a bid, `204` when it had none, `555` when the deadline ran out before the handshake completed, `556` when the connection failed, the handshake was answered with a success code instead of the upgrade, or the stream dropped before a bid, or the builder's own refusal code such as `404` |
| What are builders bidding? | `cb_pbs_relay_header_value` (the bid's `value` in Gwei, without the execution payment) and `cb_pbs_relay_last_slot`, by `relay_id`, from each bid a builder serves |

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Bid requests get `400` "auth.message.data does not match any configured builder" | The auth data is neither a lowercase hostname without a port nor an `http(s)` URL, names the host the request was sent to (a key without builder config), the request came from another Commit-Boost and matches none of this one's relay entries, or `dial_unconfigured_builders` is `false` | Correct the `auth_data` in the key's [builder config](#validator-builder-config), or add the builder as a relay entry for the key on the Commit-Boost the request reaches |
| Bid requests get `400` "the addressed builder's host does not resolve or resolves to a disallowed address" | The auth data names a builder outside your config whose host does not resolve or resolves to an [internal address](#builders-outside-your-config) | Add the builder as a relay entry for the key, or write or correct the key's [builder config](#validator-builder-config) |
| A builder answers bid requests with `400` (`cb_pbs_relay_status_code_total{endpoint="get_execution_payload_bid",http_status_code="400"}`) | The builder compares auth data byte for byte and expects something other than what the key sends, such as its hostname without `?` parameters | Send the auth data the builder expects: its hostname or its URL, the forms Commit-Boost [routes by](#routing-by-auth-data), with `?` parameters only if it accepts them |
| Bid requests to a streaming builder log "stream failed" with "rejected with 404", and `cb_pbs_relay_epbs_stream_fallback_total` rises | The builder does not serve the ePBS bid stream. Commit-Boost asks it over HTTP instead | Set `get_header = "http"` on its relay entry |
| Commit-Boost does not start or reload, or `commit-boost init` fails, with "proposer_deadline_buffer_ms must be greater than 0 and less than one slot" | `proposer_deadline_buffer_ms` is `0`, or one slot or more | Set it above `0` and under one slot, or remove it to use the default `20` |
| Bid requests to a streaming builder log "stream failed" with "websocket timed out" or a connection error | Commit-Boost could not open the stream, for example because your network allows only proxied connections, which the stream does not use. A connection error with time left is retried over HTTP; a handshake that times out is no bid | Set `get_header = "http"` on its relay entry, or allow direct connections to it |
| Commit-Boost returns `200` but the beacon node builds locally | The beacon node rejected the bid, or valued its local block higher after `builder_boost_factor` | Compare the bid with the key's `min_bid` and `builder_boost_factor` |
