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
| `POST /eth/v1/builder/beacon_blocks` | The signed beacon block that commits to the winning bid | Forwards it to every builder in `[[relays]]` and `[[mux.relays]]`; only the winning builder accepts it |

With ePBS the beacon node validates each bid and weighs it against your builder config (`min_bid`, `builder_boost_factor`) and its local block, so Commit-Boost adds no redundant verification on the hot path.

The ePBS bid endpoint does not use these PBS options, which will be deprecated after the hard fork:

- `skip_sigverify`, `min_bid_eth` and `extra_validation_enabled`: the beacon node checks the bid against the on-chain builder registry and applies the `min_bid` from its builder config.
- `timeout_get_header_ms`, `late_in_slot_time_ms`, their `[[mux]]` overrides and the timing-games options: the beacon node's deadline bounds the request (see [Timing](#timing)).

For a builder whose relay entry sets `get_header = "stream"`, Commit-Boost also reads its bids from a [stream](#bid-streaming).

## How a bid request reaches a builder

From the fork, each validator key has a builder config: a list of entries, each a `url` and an `auth_data`. For every entry the beacon node sends a bid request to the entry's `url`, carrying its `auth_data` in a `SignedBuilderRequestAuth` that the validator signs. `auth_data` tells a builder that a request was meant for it, so a request signed for one builder is rejected by another. Unless the proposer and builder agree on another value, it is the builder's hostname.

To go through Commit-Boost, every entry's `url` is Commit-Boost's own URL, and its `auth_data` is the hostname of the builder it stands for. Commit-Boost reads the `auth_data` of each request, finds the relay entry with that hostname and forwards the request there. If no relay entry has it, Commit-Boost dials the builder the `auth_data` names ([builders outside your config](#builders-outside-your-config)). Builder preferences are routed the same way. The signed block goes to every builder in your config, since only the one whose bid won accepts it.

## Setup

### 1. Add the builders to Commit-Boost

List each builder as a relay entry, as for PBS: in `[[relays]]`, or in the `[[mux.relays]]` of the mux that lists the proposer's key. ePBS adds one option, `[pbs] proposer_deadline_buffer_ms` (default `50`): the time kept back from the beacon node's deadline (see [Timing](#timing)). It must be above `0` and under one slot, `12000` on mainnet.

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

Commit-Boost sends a bid or preferences request to the first builder serving the proposer's key (the relays of its `[[mux]]`, otherwise `[[relays]]`) whose URL hostname equals the request's `auth_data`, byte for byte. That is the [builder specs](https://github.com/ethereum/builder-specs/blob/main/specs/gloas/validator.md#default-auth-data) default auth data: the lowercase hostname, without scheme, port or path, with an IPv6 address in brackets, such as `[::1]`. Builders on one host share it, so only the first is asked.

`auth_data` can also be an `http` or `https` URL, a form some builders agree out of band. It then matches the first builder whose `url` has the same scheme, host and port; the path and the pubkey in the relay URL do not count. Any other value agreed with a builder does not route through Commit-Boost. When no builder matches, Commit-Boost [dials the builder](#builders-outside-your-config) the `auth_data` names, and answers `400` when the `auth_data` is neither a hostname nor an `http(s)` URL.

Either form may end in `?` and form-encoded parameters for the builder, such as `builder-a.example.com?ofac=1`. Commit-Boost routes on the part before `?`. The parameters reach the builder inside the signed auth, so set them only for a builder that accepts them; one that does not answers `400`.

## Builders outside your config {#builders-outside-your-config}

A key's builder config may name a builder you have not added as a relay entry. Commit-Boost dials that builder anyway: a hostname at `https://<hostname>` on the default port, and a URL at its scheme, host and port. It answers `400` instead when the host does not resolve, or resolves to any address that is not public unicast, such as a loopback, private, link-local or `100.64.0.0/10` address, so a builder on your own network has to be a relay entry. These requests connect directly, ignoring `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`, follow no redirects and do not carry your relay `headers`. A builder reached this way gets the signed block over gossip, not from Commit-Boost. Neither `[[relays]]` nor a mux's relays limit which builders a key can reach this way, and anyone who can reach Commit-Boost's port can make it dial a public host, so keep that port private. Commit-Boost looks up at most 32 of these hosts at once and answers further requests as if the builder had not responded.

A key without builder config sends Commit-Boost's own hostname as its `auth_data`, so it gets no bids. Commit-Boost answers `400` when that hostname resolves to a loopback or private address, as it usually does, and otherwise dials `https://<hostname>` on port 443, where Commit-Boost itself does not listen. Commit-Boost never dials for a request that came from another Commit-Boost, so chained Commit-Boosts route only through relay entries.

## Timing

The builder specs require each bid request to carry `Date-Milliseconds` and `X-Timeout-Ms`, which together say how long the beacon node will wait for a bid. Commit-Boost subtracts your `proposer_deadline_buffer_ms` from the time remaining and sends the result to the builder as its `X-Timeout-Ms`, so the builder knows how long it has to answer.

Think of `proposer_deadline_buffer_ms` as the slack you keep from the beacon node's remaining time: enough for the bid to get back from Commit-Boost to the beacon node and for the beacon node to process it. If no time is left, Commit-Boost does not ask the builder. With `0`, Commit-Boost refuses to start or reload: the builder gets the whole deadline, so a bid it sends at the deadline reaches the beacon node late.

Builder preferences use `timeout_register_validator_ms`, and the signed block `timeout_get_payload_ms`.

## Bid streaming

A builder answers an HTTP bid request once, so a better bid it makes after answering never reaches the beacon node. Over a websocket stream it can keep sending bids until just before the beacon node's deadline.

Ask the builder whether it serves the ePBS bid stream, at `ws(s)://<relay host>/eth/v1/builder/execution_payload_bid_stream/{slot}/{parent_hash}/{parent_root}/{proposer_pubkey}`. If it does, set `get_header = "stream"` on its relay entry. Before the fork the same setting reads the builder's `get_header` bids from its [PBS stream](./configuration.md#bid-streaming), so for a builder that serves only one of the two, Commit-Boost logs a failed stream on each request to the other and uses the HTTP bid. The handshake carries the relay entry's `headers`, so a builder that requires an [API key](./configuration.md#relay-api-keys) gets it.

For each bid request to a streaming builder, Commit-Boost sends the usual HTTP request and opens the stream at the same time. It returns the HTTP bid or the latest streamed bid that decodes, whichever has the higher `value + execution_payment`, and the streamed bid on a tie. Commit-Boost does not apply the key's `max_execution_payment` to this choice; the beacon node applies it afterwards. If the stream fails, the HTTP bid still reaches the beacon node. A builder [outside your config](#builders-outside-your-config) is always asked over HTTP.

Streaming makes bid requests slower. Commit-Boost replies to the beacon node once the builder's HTTP response is in and the stream has ended: when the builder closes it, when it fails, or at the beacon node's deadline less `proposer_deadline_buffer_ms`. An HTTP builder is answered as soon as it responds. `timeout_get_header_ms` does not shorten the wait. If the beacon node reports bid requests timing out on streaming builders, raise `proposer_deadline_buffer_ms`.

The stream [connects directly](./configuration.md#connection), without your proxy settings, while the HTTP request uses them. If your host reaches builders only through a proxy, keep them on `"http"`.

## Metrics

With [metrics](./running/metrics.md) enabled, the ePBS endpoints use the `endpoint` labels `get_execution_payload_bid`, `submit_builder_preferences` and `submit_signed_beacon_block`, and a [streaming](#bid-streaming) builder's stream uses `get_execution_payload_bid_stream`.

| Question | Series |
|---|---|
| What did Commit-Boost answer the beacon node? | `cb_pbs_beacon_node_status_code_total`: `200` or `204` for a bid request, `202` for preferences, `202` for the signed block whatever the builders answer, `4xx` for a rejected request, `500` when no builder accepted the preferences |
| What did each builder answer? | `cb_pbs_relay_status_code_total`, by `relay_id`: the builder's HTTP status, or `555` when no response arrived (timeout, DNS or connection failure). Requests to builders outside your config count under `relay_id="dial"`, except one Commit-Boost [refuses to dial](#builders-outside-your-config), which gets no request |
| How fast are builders? | `cb_pbs_relay_latency`, by `relay_id` |
| Is a builder's bid stream working? | `cb_pbs_relay_status_code_total{endpoint="get_execution_payload_bid_stream"}`: `200` when the stream supplied a bid, `204` when it had none, any other code a failed stream: `555` the deadline ran out before the handshake completed, `556` a connection that failed or dropped before a bid, or the builder's own refusal such as `404`. When Commit-Boost returns a streaming builder's bid, it also logs `selected bid`, with `transport` set to `stream` or `http` for where that bid came from |
| What are builders bidding? | `cb_pbs_relay_header_value` (the bid's `value` in Gwei, without the execution payment) and `cb_pbs_relay_last_slot`, by `relay_id`, from the bid Commit-Boost returns for each builder; with a streaming builder, whichever of its two bids it chose |

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Bid requests get `400` "auth.message.data does not match any configured builder" | The auth data is neither a hostname nor an `http(s)` URL, or the request came from another Commit-Boost and matches none of this one's relay entries | Correct the `auth_data` in the key's [builder config](#validator-builder-config), or add the builder as a relay entry on the Commit-Boost the request reaches |
| Bid requests get `400` "the addressed builder's host does not resolve or resolves to a disallowed address" | The auth data names a builder outside your config whose host does not resolve or resolves to an [internal address](#builders-outside-your-config). A key without builder config sends Commit-Boost's own hostname, which usually does | Add the builder as a relay entry for the key, or write or correct the key's [builder config](#validator-builder-config) |
| A builder answers bid requests with `400` (`cb_pbs_relay_status_code_total{endpoint="get_execution_payload_bid",http_status_code="400"}`) | The builder compares auth data byte for byte and expects something other than what the key sends, such as its hostname without `?` parameters | Send the auth data the builder expects: its hostname or its URL, the forms Commit-Boost [routes by](#routing-by-auth-data), with `?` parameters only if it accepts them |
| Bid requests to a streaming builder log "stream failed" with "rejected with 404", and `cb_pbs_relay_stream_fallback_total{endpoint="get_execution_payload_bid_stream"}` rises | The builder does not serve the ePBS bid stream. Its HTTP bid still reaches the beacon node | Set `get_header = "http"` on its relay entry |
| Commit-Boost does not start or reload, or `commit-boost init` fails, with "proposer_deadline_buffer_ms must be greater than 0 and less than one slot" | `proposer_deadline_buffer_ms` is `0`, or one slot or more | Set it above `0` and under one slot, or remove it to use the default `50` |
| Bid requests to a streaming builder log "stream failed" with "websocket timed out" or a connection error | Commit-Boost could not open the stream before the deadline, for example because your network allows only proxied connections, which the stream does not use. The HTTP bid still reaches the beacon node | Keep the builder on `get_header = "http"`, or allow direct connections to it |
| Commit-Boost returns `200` but the beacon node builds locally | The beacon node rejected the bid, or valued its local block higher after `builder_boost_factor` | Compare the bid with the key's `min_bid` and `builder_boost_factor` |
| The signed block gets `415` | The beacon node sends it as JSON | Configure the beacon node to send SSZ |
| Commit-Boost logs "no builder accepted the signed beacon block" | The winning bid came from a builder outside your config, which gets the block over gossip, or your builders did not accept it. The beacon node gossips the block either way | If the bid came from a configured builder, check its answer in `cb_pbs_relay_status_code_total{endpoint="submit_signed_beacon_block"}` |
