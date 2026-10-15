---
description: Run Commit-Boost for ePBS proposals after the Gloas fork
---

# ePBS

:::info From v0.12.0-rc1
ePBS support starts in v0.12.0-rc1, a pre-release. The `:latest` image doesn't have it yet, so use `ghcr.io/commit-boost/commit-boost:v0.12.0-rc1` or a newer tag. With `commit-boost init`, set it as `docker_image` in `[pbs]`.
:::

From the Gloas fork, a proposer commits to a builder's signed execution payload bid instead of a blinded header, and the winning builder publishes the payload itself. Commit-Boost serves the [builder-API endpoints](https://ethereum.github.io/builder-specs/?urls.primaryName=dev) the beacon node calls for this and forwards each call to builders, relays, or MPBC operators.

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

After the Gloas fork, each validator key has a builder config: a list of entries, each a `url` and an `auth_data`. For every entry the beacon node sends a bid request to the entry's `url`, carrying its `auth_data` in a `SignedBuilderRequestAuth` that the validator signs. `auth_data` tells a builder that a request was meant for it, so a request signed for one builder is rejected by another. Unless the proposer and builder agree on another value, it is the builder's hostname.

To go through Commit-Boost, set an entry's `url` to Commit-Boost's own URL, and set its `auth_data` to the hostname of the builder to ask. Commit-Boost reads the `auth_data` of each request, finds the relay entry with that hostname and forwards the request there. If no relay entry has it, Commit-Boost dials the builder at that hostname ([builders outside your config](#builders-outside-your-config)). Builder preferences are routed the same way. The signed block goes to every builder in your config, since Commit-Boost does not track which bid won.

For example, this validator client config on Hoodi asks Ultra Sound through Commit-Boost and directly, and Flashbots directly. It is in Lighthouse's `builder_definitions.yml` format (see [step 3](#validator-builder-config) for each client's config format). The example assumes `http://cb.example.com:18550` is Commit-Boost's URL reachable by the beacon node (see [step 2](#commit-boost-url)).

```yml title="builder_definitions.yml"
builders:
  # Ultra Sound through Commit-Boost
  - enabled: true
    url: "http://cb.example.com:18550"
    auth_data: "0x72656c61792d686f6f64692e756c747261736f756e642e6d6f6e6579"   # relay-hoodi.ultrasound.money
    max_execution_payment: 18446744073709551615   # the maximum allowed value
  # Ultra Sound directly
  - enabled: true
    url: "https://0xb1559beef7b5ba3127485bbbb090362d9f497ba64e177ee2c8e7db74746306efad687f2cf8574e38d70067d40ef136dc@relay-hoodi.ultrasound.money"
    auth_data: "0x72656c61792d686f6f64692e756c747261736f756e642e6d6f6e6579"   # relay-hoodi.ultrasound.money
    max_execution_payment: 18446744073709551615   # the maximum allowed value
  # Flashbots directly
  - enabled: true
    url: "https://0xafa4c6985aa049fb79dd37010438cfebeb0f2bd42b115b89dd678dab0670c1de38da0c4e9138c9290a398ecd9a0b3110@boost-relay-hoodi.flashbots.net"
    auth_data: "0x626f6f73742d72656c61792d686f6f64692e666c617368626f74732e6e6574"   # boost-relay-hoodi.flashbots.net
    max_execution_payment: 18446744073709551615   # the maximum allowed value
```

## Setup

These steps are for a network where the Gloas fork is active. Before the fork, Commit-Boost serves PBS as [Configuration](./configuration.md) describes.

### 1. Run Commit-Boost with your builders {#run-commit-boost}

A minimal `cb-config.toml`:

```toml
chain = "Hoodi"

[pbs]
port = 18550

[[relays]]
id = "builder-a"
# Replace this with your relay's own URL, in the form scheme://<relay-pubkey>@<host>
url = "https://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@builder-a.example.com"
# Uncomment only for a builder that serves the ePBS bid stream
# get_header = "stream"
```

Each `[[relays]]` table is a relay entry. It can point at a relay or at a builder; this page calls either a builder. The `example.com` URLs on this page are placeholders. [The EthStaker relay list](https://github.com/ethstaker/ethstaker-guides/blob/main/MEV-relay-list.md) has real relay URLs for each network, and for Hoodi so does [the Hoodi network's README](https://github.com/eth-clients/hoodi).

See [`examples/configs/epbs.toml`](https://github.com/Commit-Boost/commit-boost-client/blob/main/examples/configs/epbs.toml) for a fuller example config for Hoodi.

Some notes:
- On a devnet, `chain` takes the [custom form](./configuration.md#custom-chains).
- Commit-Boost doesn't read the Gloas fork from `chain`. It serves the PBS and ePBS endpoints side by side, and the beacon node calls the ones its fork uses.
- If you run the image without `commit-boost init`, set `host = "0.0.0.0"` in `[pbs]` before you start it ([step 2](#commit-boost-url)).
- Commit-Boost doesn't check ePBS bids against the BLS public key in a relay entry's `url`, but the URL must carry it.
- A key can still reach a builder you do not list, unless you set `[pbs] dial_unconfigured_builders = false` ([Builders outside your config](#builders-outside-your-config)).
- Commit-Boost needs at least one top-level `[[relays]]` entry (a relay entry only in a `[[mux]]` doesn't count), and by default it exits at startup unless one relay answers a status check. See [`relay_check`](./configuration.md#pbs-safety-and-tuning-options).

Start Commit-Boost with [Docker](./running/docker.md) or as a [binary](./running/binary.md).

### 2. Find Commit-Boost's URL for the beacon node {#commit-boost-url}

The beacon node sends the bid requests, so the URL to write in each key's builder config is Commit-Boost's address as the beacon node reaches it:

| Setup | URL | What to set |
|---|---|---|
| Docker via `commit-boost init`, beacon node in a container on the same Docker network | `http://cb_pbs:18550` | Nothing |
| Docker via `commit-boost init`, beacon node on the host | `http://127.0.0.1:18550` | Nothing |
| Docker without `commit-boost init`, such as your own `docker run` or compose file, beacon node in a container on the same Docker network | `http://<Commit-Boost container name>:18550` | `host = "0.0.0.0"` in `[pbs]` ([Without `commit-boost init`](./running/docker.md#without-commit-boost-init)) |
| Binary, or Commit-Boost on another machine | `http://<the address in host>:18550`, or with `0.0.0.0` any IPv4 address of the Commit-Boost host | `host` in `[pbs]`, an IPv4 address, `127.0.0.1` by default. Set it to an address the beacon node reaches, or `0.0.0.0` for every interface. The binary binds it, and under Docker the port is published on it ([Networking](./running/docker.md#networking)). [`CB_PBS_ENDPOINT`](./running/binary.md#pbs-service) overrides `host` and `port` for the binary |

Check it from where the beacon node runs, with your URL in place of `http://cb.example.com:18550`. If the beacon node's container has no curl, run it in Commit-Boost's own container with `docker exec`, since the Commit-Boost image has curl:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://cb.example.com:18550/eth/v1/builder/status
```

It prints `200`, or `502` when no relay answers ([`relay_check`](./configuration.md#pbs-safety-and-tuning-options)).

Keep the port private, since anyone who reaches it can make Commit-Boost dial a public host ([Builders outside your config](#builders-outside-your-config)).

Changing `host` or `port` needs a restart, after rerunning `commit-boost init` if you use it. Relay entries [reload](./configuration.md#automatic-reload-pbs-only) without one.

### 3. Point each validator key at Commit-Boost {#validator-builder-config}

The validator client holds each key's builder config, in its settings file or through its [keymanager API](#validator-builder-config-api). For each relay entry in `cb-config.toml`, add a builder config entry. Its `url` is your [step 2](#commit-boost-url) URL, and its `auth_data` is the hex of the relay entry's hostname alone, without the scheme, the key before the `@` or a port, so `https://0xa1ce...@builder-a.example.com:8080` gives `builder-a.example.com`. Note that a single validator key is limited to at most 64 entries.

Always remember to set `auth_data`. If a `url` points to Commit-Boost without specifying the `auth_data`, the validator client will derives it from Commit-Boost's own URL, and Commit-Boost will `400` since it won't know which builder to call.

To get the hex of a hostname:

```bash
printf '0x%s\n' "$(printf '%s' builder-a.example.com | od -An -tx1 | tr -d ' \n')"
```

It prints `0x6275696c6465722d612e6578616d706c652e636f6d`.

In your validator client, you can configure a key to connect to a builder directly as well as through Commit-Boost. If you do, give both entries the same `min_bid`, `builder_boost_factor` and `max_execution_payment`, so that the beacon node, which applies them per entry ([What changes at the fork](#what-changes-at-the-fork)), values a bid the same way on either route. A builder also keeps only one `max_execution_payment` per key and slot, so if two entries to the same builder differ, it depends on the builder's implementation which one is used.

:::note Check your client's docs
Clients are still changing how they configure ePBS builders. Each section below was tested on a specific client release, so check your client's own docs before you use another version: [Lodestar's proposer config](https://chainsafe.github.io/lodestar/run/validator-management/proposer-config/), [Lighthouse's Gloas builder configuration](https://lighthouse-book.sigmaprime.io/gloas_builder_config.html), and for Prysm, whose builder docs don't cover ePBS yet, its [release notes](https://github.com/OffchainLabs/prysm/releases).
:::

Each client example demonstrates, for redundancy, how to configure the validator client to have your beacon node request from builders directly and through Commit-Boost in parallel. A URL may keep the key before the `@` as relay lists give it. The validator client doesn't use the key and leaves it out of the default `auth_data`.

The commands use environment variables such as `$JWT_SECRET_PATH` for your own paths, endpoints and secrets; set them for your setup. Import your validator keys as each client's own docs describe.

#### Lodestar {#lodestar}

These steps are for Lodestar v1.50.0 ([Lodestar's docs](https://chainsafe.github.io/lodestar/run/validator-management/proposer-config/)).

The beacon node needs no builder flag, since it reads the builder config from the validator client. A `--builder` or `--builder.urls` left on it adds nothing to that config.

Start the beacon node:

```bash
lodestar beacon \
  --network hoodi \
  --dataDir "$BN_DATA_DIR" \
  --execution.urls "$EXECUTION_ENDPOINT" \
  --jwtSecret "$JWT_SECRET_PATH" \
  --checkpointSyncUrl "$CHECKPOINT_SYNC_URL"
```

Write the settings file:

```yml title="proposer-settings.yaml"
default_config:
  builder:
    selection: "maxprofit"
    boost_factor: "100"
    min_bid: "10000000"
    max_execution_payment: "18446744073709551615"
    builders:
      - url: "https://builder-a.example.com"
        auth_data: "0x6275696c6465722d612e6578616d706c652e636f6d"
      - url: "http://cb.example.com:18550"
        auth_data: "0x6275696c6465722d612e6578616d706c652e636f6d"
```

`default_config` can also set `fee_recipient`.

Start the validator client with the file, and restart it to load each change:

```bash
lodestar validator \
  --network hoodi \
  --dataDir "$VC_DATA_DIR" \
  --beaconNodes "$BEACON_NODE_URL" \
  --importKeystores "$KEYSTORES_DIR" \
  --importKeystoresPassword "$KEYSTORE_PASSWORD_FILE" \
  --suggestedFeeRecipient "$FEE_RECIPIENT" \
  --proposerSettingsFile proposer-settings.yaml \
  --allowDangerousTrustedPayments
```

:::warning
- `--builder`, `--builder.selection` and `--builder.boostFactor` on the validator client override the file's `selection` and `boost_factor`. With `--builder`, the validator client uses the `default` selection and a boost factor of 90 whatever the file sets, so leave them off the validator client.
- Without `selection: "maxprofit"` in the file, the validator client also uses the `default` selection and a boost factor of 90, and ignores the file's `boost_factor`.
- The validator client refuses to start:
  - with builders in both the file and `--builder.urls`: "Cannot configure both --builder.urls and builders in the proposer settings file";
  - with `selection: builderonly`: "Builder selection builderonly is no longer supported, use builderalways instead";
  - with a `max_execution_payment` above `0` and no `--allowDangerousTrustedPayments`: "Configuring a builder max execution payment above 0 requires --allowDangerousTrustedPayments";
  - with builder configs already written through the keymanager API: "Cannot accept --proposerSettingsFile since it conflicts with proposer configs previously persisted via the keymanager api". Lodestar keeps those configs in `<dataDir>/proposerConfigs`, so use either the settings file or the keymanager API, not both.
:::

After the restart, the validator client logs `Builder config` with the builders, boost factor and minimum bid it loaded. To check a proposal, find the beacon node's `Selected builder block` line, which it logs at info level for each proposal that uses a builder's bid (`Selected local block` otherwise). Its `bidSource` is the `url` of the entry the bid came from, so `http://cb.example.com:18550` means the bid came through Commit-Boost.

#### Lighthouse {#lighthouse}

These steps are for Lighthouse v8.3.0-rc.0 ([Lighthouse's docs](https://lighthouse-book.sigmaprime.io/gloas_builder_config.html)).

The beacon node needs no builder flag, since it reads the builder config from the validator client. If `--builder` is set, no bids will be route through Commit-Boost.

Start the beacon node:

```bash
lighthouse bn \
  --network hoodi \
  --datadir "$BN_DATA_DIR" \
  --execution-endpoint "$EXECUTION_ENDPOINT" \
  --execution-jwt "$JWT_SECRET_PATH" \
  --checkpoint-sync-url "$CHECKPOINT_SYNC_URL" \
  --http
```

Write `builder_definitions.yml`:

```yml title="builder_definitions.yml"
min_bid: 10000000
builder_boost_factor: 100
builders:
  - enabled: true
    url: "https://builder-a.example.com"
    auth_data: "0x6275696c6465722d612e6578616d706c652e636f6d"
    max_execution_payment: 18446744073709551615
  - enabled: true
    url: "http://cb.example.com:18550"
    auth_data: "0x6275696c6465722d612e6578616d706c652e636f6d"
    max_execution_payment: 18446744073709551615
```

The file lives in the validator client's validators directory, the one `--validators-dir` names (`$VC_DATA_DIR/validators` below), and the validator client reads it when it starts. It doesn't need `--builder-proposals` for the file's builders.

```bash
lighthouse vc \
  --network hoodi \
  --datadir "$VC_DATA_DIR" \
  --validators-dir "$VC_DATA_DIR/validators" \
  --beacon-nodes "$BEACON_NODE_URL" \
  --suggested-fee-recipient "$FEE_RECIPIENT"
```

:::warning
- An entry without `enabled` or `max_execution_payment` stops the validator client with "Unable to open or create builder definitions", followed by "missing field `enabled`" or "missing field `max_execution_payment`".
- Without a fee recipient, from `--suggested-fee-recipient` or per key, it stops with "The following validators are missing a `suggested_fee_recipient`".
- With `--gas-limit` but no `--builder-proposals`, it refuses to start: "the following required arguments were not provided: --builder-proposals". Set both or neither.
:::

At debug level, the validator client logs `Resolved builder config for block production` for each proposal, with the number of builders the key has, so `builders: 0` on a key you gave builders means its builder config isn't loaded. To check a proposal, find the validator client's `Builder bid won` line, which it logs at info level when an external bid wins. The line doesn't show which entry the bid came from, so compare it with Commit-Boost's `received header` for the same slot ([Execution payload bid](./troubleshooting.md#execution-payload-bid)).

#### Prysm {#prysm}

These steps are for Prysm v7.2.1 ([release notes](https://github.com/OffchainLabs/prysm/releases/tag/v7.2.1)).

The beacon node needs no builder flag, since it reads the builder config from the validator client. A `--http-mev-relay` left set isn't used for ePBS bid requests.

Start the beacon node:

```bash
beacon-chain \
  --hoodi \
  --datadir "$BN_DATA_DIR" \
  --execution-endpoint "$EXECUTION_ENDPOINT" \
  --jwt-secret "$JWT_SECRET_PATH" \
  --checkpoint-sync-url "$CHECKPOINT_SYNC_URL" \
  --genesis-beacon-api-url "$CHECKPOINT_SYNC_URL" \
  --suggested-fee-recipient "$FEE_RECIPIENT" \
  --accept-terms-of-use
```

Write the settings file:

```json title="proposer-settings.json"
{
  "version": 2,
  "default_config": {
    "fee_recipient": "0x<your fee recipient>",
    "builder": {
      "min_bid": "10000000",
      "builder_boost_factor": "100",
      "max_execution_payment": "18446744073709551615",
      "builders": [
        { "url": "https://builder-a.example.com", "auth_data": "0x6275696c6465722d612e6578616d706c652e636f6d" },
        { "url": "http://cb.example.com:18550", "auth_data": "0x6275696c6465722d612e6578616d706c652e636f6d" }
      ]
    }
  }
}
```

Set `fee_recipient` to the fee recipient your validator client already uses (its `--suggested-fee-recipient`).

Start the validator client with the file, and restart it to load each change. It doesn't need `--enable-builder`. Left on, the flag has no effect after the Gloas fork, and Prysm logs that it is legacy. A `--http-mev-relay` left on the beacon node isn't used for ePBS bid requests.

```bash
validator \
  --hoodi \
  --wallet-dir "$WALLET_DIR" \
  --wallet-password-file "$WALLET_PASSWORD_FILE" \
  --beacon-rpc-provider "$BEACON_RPC_PROVIDER" \
  --suggested-fee-recipient "$FEE_RECIPIENT" \
  --proposer-settings-file proposer-settings.json \
  --accept-terms-of-use
```

:::warning
- With a `fee_recipient` other than the validator client's `--suggested-fee-recipient`, the beacon node discards every bid that comes through Commit-Boost, logging "discarded: fee recipient does not match proposer preferences".
- An unknown field or an invalid `fee_recipient` stops the validator client, with "json: unknown field" or "default fee recipient is not a valid Ethereum address".
- An entry with a missing or invalid `url` is dropped with the warning "Removed 1 invalid or duplicate builder entries".
- At every restart, a per-key `proposer_config` section replaces the per-key settings written through the keymanager API.
:::

After the restart, the validator client logs `Proposer settings loaded from file` with the file's path, but no line lists the builders it loaded. At debug level it logs `Submitted builder preferences` with the number of keys each time it sends them, and Commit-Boost logs `builder preferences submitted` for each ([Check it worked](#check-it-worked)). To check a proposal, find the beacon node's `Chose payload bid` line at info level. `source=builder-api` there means the bid came from one of the file's entries. At debug level, its `Builder bids` line lists each bid with the `url` of its entry, so a bid through Commit-Boost shows `http://cb.example.com:18550`.

#### Through the keymanager API {#validator-builder-config-api}

To write a key's builder config through the validator client's [keymanager API](https://ethereum.github.io/keymanager-APIs/?urls.primaryName=dev#/Builder%20Config) instead, with the API at `$KEYMANAGER_URL`, its token in `$TOKEN` and the validator key in `$PUBKEY`:

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

The body replaces the key's config in full, and the validator client answers `202`. Each client's docs say where to find its keymanager API token. Lodestar doesn't accept a settings file and keymanager writes together ([Lodestar](#lodestar)).

`builder_pubkeys` limits which builders' bids the beacon node accepts, and an empty list accepts any. Don't copy the pubkey from a relay entry's URL into it, since that is the relay's key, not a builder's bid-signing key.

### 4. Check it worked {#check-it-worked}

Ahead of each key's proposal, Commit-Boost logs `builder preferences submitted` with the `relay_id` of the relay entry it reached. At the proposal it logs `received header` for the bid it returns. [Expected healthy logs](./troubleshooting.md#builder-preferences) shows both in full.

With [metrics](./running/metrics.md) enabled, `cb_pbs_beacon_node_status_code_total{endpoint="get_execution_payload_bid"}` counts Commit-Boost's answers to bid requests: `200` with a bid, `204` without ([Metrics](#metrics)).

## Routing by auth data

Commit-Boost sends a bid or preferences request to the first builder whose URL hostname equals the request's `auth_data`, byte for byte. That is the [builder specs](https://github.com/ethereum/builder-specs/blob/main/specs/gloas/validator.md#default-auth-data) default auth data: the lowercase ASCII hostname (punycode for an internationalized name), without scheme, port or path, with an IPv6 address compressed and in brackets, such as `[::1]`. Commit-Boost looks first among the relays serving the proposer's key (those of its `[[mux]]`, otherwise `[[relays]]`), then among `[[relays]]` in config order, so a key in a mux still reaches a `[[relays]]` builder through that entry, with its headers and port. Commit-Boost dials a builder listed only in another mux's `[[mux.relays]]` as it would a builder outside your config.

`auth_data` can also be an `http` or `https` URL agreed with a builder. It then matches the first builder whose `url` has the same scheme, host and port; the path and the pubkey in the relay URL do not count, so builders on one origin share it. Any other value agreed with a builder does not route through Commit-Boost. When no builder matches, Commit-Boost [dials the builder](#builders-outside-your-config) that the `auth_data` specifies, and responds `400` if the `auth_data` isn't in that hostname form no an `http(s)` URL.

## Builders outside your config {#builders-outside-your-config}

A key's builder config may address a builder you have not added as a relay entry. Commit-Boost dials that builder anyway: a hostname at `https://<hostname>` on the default port, and a URL at its scheme, host and port. It answers `400` instead when the host does not resolve, or resolves to any address that is not public unicast, such as a loopback, private, link-local or `100.64.0.0/10` address, so a builder on your own network has to be a relay entry. These requests connect directly, ignoring `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`, follow no redirects and do not carry your relay `headers`.

A dial only routes bid and builder preferences requests, to their builder-specs paths, with the signed auth or preferences the beacon node sent. Commit-Boost does not check the auth signature before dialing. A builder reached this way gets the signed block over gossip, unless it is also a relay entry in `[[relays]]` or a mux. Neither `[[relays]]` nor a mux's relays limit which builders a key can reach this way. Commit-Boost looks up at most 32 of these hosts at once and answers further requests as if the builder had not responded, as it does when a lookup runs out of the request's time.

To turn dialing off, set `dial_unconfigured_builders = false` in `[pbs]`. Commit-Boost then answers `400` instead of dialing.

On a validator client whose builder URL is Commit-Boost, a key without builder config sends Commit-Boost's own hostname as its `auth_data`, so it gets no bids: unless a relay entry has that hostname, which then gets the request, Commit-Boost answers `400` without dialing. A client that sends Commit-Boost's full URL instead also gets `400`. Commit-Boost never dials for a request that came from another Commit-Boost, so chained Commit-Boosts route only through relay entries.

## Timing

The builder specs require each bid request to carry `Date-Milliseconds` and `X-Timeout-Ms`, which together say how long the beacon node will wait for a bid. Commit-Boost subtracts `[pbs] proposer_deadline_buffer_ms` (default `20`) from the time remaining and sends the result to the builder as its `X-Timeout-Ms`, so the builder knows how long it has to answer.

The buffer is the time Commit-Boost's answer needs to reach the beacon node, which discards responses that arrive after its deadline. Commit-Boost's own share is a few milliseconds, so the default suits a beacon node on the same host. When Commit-Boost and the beacon node run on different hosts, raise it by the time a response takes to travel from Commit-Boost to the beacon node, plus any difference between the two hosts' clocks, since Commit-Boost reads the beacon node's `Date-Milliseconds` against its own clock. It must be above `0` and under one slot.

Builder preferences use `timeout_register_validator_ms`, and the signed block `timeout_get_payload_ms`.

## Bid streaming

A builder answers an HTTP bid request once, so a better bid it makes after answering never reaches the beacon node. Over a websocket stream it can keep sending bids until just before the beacon node's deadline.

Compatible builders serve the ePBS bid stream, at `ws(s)://<relay host>/eth/v1/builder/execution_payload_bid_stream/{slot}/{parent_hash}/{parent_root}/{proposer_pubkey}`. Set `get_header = "stream"` on its relay entry, just as for [PBS streaming](./configuration.md#bid-streaming).

For each bid request to a streaming builder, Commit-Boost opens the stream and returns the latest streamed bid that decodes. A stream that fails to connect, because of a connection error or a handshake answered with anything but the upgrade, `204` included, is retried over HTTP with the time left. A handshake still unanswered at the deadline, or a stream that breaks before a bid, is no bid. That includes a builder that does not serve the stream, if its refusal comes after the deadline.

:::warning
Set `"stream"` only on builders that serve it. A builder [outside your config](#builders-outside-your-config) is always asked over HTTP.
:::

A streaming builder's bid reaches the beacon node later than an HTTP builder's, because Commit-Boost keeps the stream open to return the builder's latest bid. It replies once the stream has ended: when the builder closes it, when it fails, or at the beacon node's deadline minus `proposer_deadline_buffer_ms`. After a retry over HTTP, it replies once that request answers. A bid request to an HTTP builder is answered as soon as the builder responds. `timeout_get_header_ms` does not shorten the wait. If the beacon node reports bid requests timing out on streaming builders, raise `proposer_deadline_buffer_ms`.

The stream follows the PBS stream's [connection rules](./configuration.md#connection), which differ from the HTTP request's for proxies and TLS. If your host reaches a builder only through a proxy, or its certificate comes from a private CA, keep it on `"http"`.

## Metrics

With [metrics](./running/metrics.md) enabled, the ePBS endpoints use the `endpoint` labels `get_execution_payload_bid`, `submit_builder_preferences` and `submit_signed_beacon_block`, and a [streaming](#bid-streaming) builder's stream uses `get_execution_payload_bid_stream`, with its own `cb_pbs_relay_epbs_stream_*` series ([Metrics > Bid stream](./running/metrics.md#bid-stream)).

| Question | Series |
|---|---|
| What did Commit-Boost answer the beacon node? | `cb_pbs_beacon_node_status_code_total`: `200` or `204` for a bid request, `202` for preferences, `202` for the signed block whatever the builders answer, `4xx` for a rejected request, `500` when no builder accepted the preferences or on an internal error |
| What did each builder answer? | `cb_pbs_relay_status_code_total`, by `relay_id`: the builder's HTTP status, or `555` when no response arrived (timeout, DNS or connection failure; on the bid stream, only the deadline). Requests to builders outside your config count under `relay_id="dial"`; a dial Commit-Boost [refuses](#builders-outside-your-config), or whose lookup fails, times out or finds no free slot, sends no request and is not counted |
| How fast are builders? | `cb_pbs_relay_latency`, by `relay_id` |
| Is a builder's bid stream working? | `cb_pbs_relay_status_code_total{endpoint="get_execution_payload_bid_stream"}`: `200` when the stream supplied a bid, `204` when it had none, `555` when the deadline ran out before the handshake completed, `556` when the connection failed, the handshake was answered with a success code instead of the upgrade, or the stream dropped before a bid, or the builder's own refusal code such as `404` |
| What are builders bidding? | `cb_pbs_relay_header_value` (the bid's `value` in Gwei, without the execution payment) and `cb_pbs_relay_last_slot`, by `relay_id`, from each bid a builder serves. Builders outside your config share these two series under `relay_id="dial"` |
