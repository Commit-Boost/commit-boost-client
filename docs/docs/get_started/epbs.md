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

- `skip_sigverify` and `extra_validation_enabled`: the beacon node checks the bid against the on-chain builder registry.
- `timeout_get_header_ms`, `late_in_slot_time_ms`, their `[[mux]]` overrides and the timing-games options: the beacon node's deadline bounds the request (see [Timing](#timing)).

Commit-Boost does not apply `min_bid_eth` to ePBS bids either. The beacon node applies the `min_bid` in each key's builder config, which [`commit-boost builder-config`](#builder-config-command) writes from `min_bid_eth`.

A `get_header = "stream"` relay is asked for ePBS bids over plain HTTP.

## How a bid request reaches a builder

From the fork, each validator key has a builder config: a list of entries, each a `url` and an `auth_data`. For every entry the beacon node sends a bid request to the entry's `url`, carrying its `auth_data` in a `SignedBuilderRequestAuth` that the validator signs. `auth_data` tells a builder that a request was meant for it, so a request signed for one builder is rejected by another. Unless the proposer and builder agree on another value, it is the builder's hostname.

To go through Commit-Boost, every entry's `url` is Commit-Boost's own URL, and its `auth_data` is the hostname of the builder it stands for. Commit-Boost reads the `auth_data` of each request, finds the relay entry with that hostname and forwards the request there. If no relay entry has it, Commit-Boost dials the builder the `auth_data` names ([builders outside your config](#builders-outside-your-config)). Builder preferences are routed the same way. The signed block goes to every builder in your config, since only the one whose bid won accepts it.

## Setup

### 1. Add the builders to Commit-Boost

List each builder as a relay entry, as for PBS: in `[[relays]]`, or in the `[[mux.relays]]` of the mux that lists the proposer's key. ePBS adds one option, `[pbs] proposer_deadline_buffer_ms` (default `50`): the time kept back from the beacon node's deadline (see [Timing](#timing)). It must be above `0` and under one slot, `12000` on mainnet.

### 2. Point each validator key at Commit-Boost {#validator-builder-config}

Write each key's builder config through its validator client's keymanager API, which must implement the builder config endpoint ([keymanager-APIs #88](https://github.com/ethereum/keymanager-APIs/pull/88)). Add one entry per builder: `url` is Commit-Boost's URL, and `auth_data` is the hex of the hostname in the builder's relay entry `url`. For a relay, that is the relay's own host, not a block builder behind it. A key without builder config gets no bids through Commit-Boost ([builders outside your config](#builders-outside-your-config)).

[`commit-boost builder-config`](#builder-config-command) writes this config for you from the Commit-Boost config. To write it by hand, with the relay entry `url = "https://0xa1ce...@builder-a.example.com"`, Commit-Boost listening at `http://cb.example.com:18550`, the keymanager API at `$KEYMANAGER_URL`, its token file at `$TOKEN_FILE` and the validator key in `$PUBKEY`:

```bash
printf 'Authorization: Bearer %s' "$(cat "$TOKEN_FILE")" | \
  curl -X POST "$KEYMANAGER_URL/eth/v1/validator/$PUBKEY/builder_config" \
  -H @- -H "Content-Type: application/json" \
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

The token goes to curl on stdin (`-H @-`, curl 7.55 or newer), so it never appears in a command line other users can read. `echo 0x$(printf builder-a.example.com | xxd -p | tr -d '\n')` prints the `auth_data` hex.

The call is `POST /eth/v1/validator/{pubkey}/builder_config`, authenticated with the keymanager API's bearer token. The body replaces the key's config in full, and the validator client answers `202` once it is stored. Besides `url` and `auth_data`, an entry or the top level can set:

- `min_bid` and `builder_boost_factor` are optional. At the top level they apply to p2p bids and to every entry that does not set its own, so a top-level `min_bid` above your builders' bids sends every proposal to a p2p bid or a local block, unless an entry sets a lower one of its own.
- `max_execution_payment`, when an entry omits it, gets the validator client's default, which differs between clients and can be `0`, so no execution payment counts. Lodestar accepts a nonzero value only when started with `--allowDangerousTrustedPayments`.
- `builder_pubkeys` limits which builder keys' bids the beacon node accepts; leave it empty to accept any. Don't copy the pubkey from the relay URL: that is the relay's key, not the builder's bid-signing key.

:::warning Proposer settings files
A validator client that loads a proposer settings file overrides or refuses keymanager writes. Prysm started with `--proposer-settings-file` or `--proposer-settings-url` reloads the file at every start, and a file with a `proposer_config` section replaces every key's per-key config, so builder config written through the API is lost at the next restart. Lodestar started with `--proposerSettingsFile` refuses every per-key write with `403`. Before writing builder config through the API, move off the file's per-key settings:

- Prysm: remove the flag, restart, check that your fee recipients survived, then write the builder config.
- Lodestar: save each key's fee recipient with `GET /eth/v1/validator/<pubkey>/feerecipient`, which works with the file set. Stop the validator client and replace `--proposerSettingsFile` with flags for the file's `default_config`, such as `--suggestedFeeRecipient`, `--graffiti`, `--defaultGasLimit` and `--builder.selection`: without them every key falls back to Lodestar's defaults, a zero-address fee recipient among them. Start it, POST each key's own settings from `proposer_config`, such as `{"ethaddress": "0x..."}` to `/eth/v1/validator/<pubkey>/feerecipient`, and read them back. Once a key is written through the API, Lodestar refuses to start with `--proposerSettingsFile` again.
:::

#### With `commit-boost builder-config` {#builder-config-command}

`commit-boost builder-config` works out each key's builder config from the Commit-Boost config, routed as Commit-Boost routes it: a key in a `[[mux]]` gets that mux's relays, and any other key gets `[[relays]]`. It finds each mux's keys as Commit-Boost does at startup, from `validator_pubkeys` and the mux's loader, so a URL or registry loader needs the network, and keys a registry adds later need another run. With a registry loader it also checks `rpc_url` as Commit-Boost does. It has two subcommands:

- `apply` writes the config to the validator clients you give it, through their keymanager APIs, so it runs where it can reach them.
- `print` writes the config as JSON and contacts no validator client, for your own tooling to send, or for `apply --from` to write where the validator client runs.

Which to use:

| Setup | Use |
|---|---|
| Commit-Boost and the validator client run as binaries on one host | [`apply`](#builder-config-apply) |
| `commit-boost init` Docker compose, with the validator client on the host | `apply` in [`docker run`](#builder-config-with-docker) |
| The validator client in another container or a packaged stack, such as eth-docker or Dappnode | [`print` piped into `apply --from -`](#builder-config-with-docker) in the client's network |
| Kubernetes | [`apply` in a sidecar](#builder-config-on-kubernetes) |
| Your own tooling already writes per-key settings, such as fee recipients, to locked-down validator clients | [`print`](#builder-config-print), and your tooling sends it |

:::tip From MEV-Boost
Your MEV-Boost relays are the builders on this page: each `-relays` URL becomes a `[[relays]]` `url`. `-min-bid` becomes `[pbs] min_bid_eth`, which `builder-config` writes as every key's `min_bid`, so it floors p2p bids too; set `[pbs] min_bid_p2p_eth` to give p2p bids their own floor.
:::

1. From v0.12.0-rc1, `builder-config` is a subcommand of `commit-boost`, in the binary and the Docker image.

2. In the Commit-Boost config, set the values `builder-config` writes, such as a mux's `min_bid_eth` and `builder_boost_factor`. Commit-Boost itself does not act on them, so a mux's `min_bid_eth` does not floor that mux's PBS bids; `[pbs] min_bid_eth` still does. The table at the end of this section lists where each value comes from:

   ```toml
   [[mux]]
   id = "epbs"
   validator_pubkeys = [
       "0x80c7f782b2467c5898c5516a8b6595d75623960b4afc4f71ee07d40985d20e117ba35e7cd352a3e75fb85a8668a3b745",
   ]
   # Drops bids below 0.01 ETH for these keys, p2p bids included
   min_bid_eth = 0.01
   builder_boost_factor = 100

   [[mux.relays]]
   id = "builder-a"
   url = "https://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@builder-a.example.com"

   [[mux.relays]]
   id = "builder-b"
   url = "https://0xa119589bb33ef52acbb8116832bec2b58fca590fe5c85eac5d3230b44d5bc09fe73ccd21f88eab31d6de16194d17782e@builder-b.example.com"
   ```

   On Lodestar, start its validator client with `--allowDangerousTrustedPayments`: it refuses any cap above `0` without that flag, and the default cap is unclamped. `[pbs] max_execution_payment_gwei = 0` avoids the flag, but then the beacon node counts none of a builder's execution payment. `print` notes this on stderr. In `apply`, a client that refuses gets one error naming the flag, and no further key with a cap above `0` is written to it.

3. Preview the config with `print`, then write it with `apply`, or send it with your own tooling. `--advertised-url` is Commit-Boost's URL as your beacon nodes reach it, starting with `http://` or `https://`. `--config` defaults to `CB_CONFIG`, as set inside Commit-Boost's container.

##### `print` {#builder-config-print}

```bash
commit-boost builder-config print --config cb-config.toml --advertised-url http://cb.example.com:18550
```

stdout carries only the JSON document; the mux key counts, the Lodestar note and the loaders' warnings go to stderr. It exits `0`, `1` if the document could not be written, or `2` on a config or loader error. For the config above it prints this (abridged):

```json
{
  "version": 1,
  "advertised_url": "http://cb.example.com:18550",
  "default": null,
  "muxes": {
    "epbs": {
      "config": {
        "min_bid": "10000000",
        "builder_boost_factor": "100",
        "builders": [
          {
            "url": "http://cb.example.com:18550",
            "auth_data": "0x6275696c6465722d612e6578616d706c652e636f6d",
            "builder_pubkeys": [],
            "max_execution_payment": "18446744073709551615",
            "min_bid": "10000000",
            "builder_boost_factor": "100"
          },
          ...
        ]
      },
      "keys": ["0x80c7f782b2467c5898c5516a8b6595d75623960b4afc4f71ee07d40985d20e117ba35e7cd352a3e75fb85a8668a3b745"],
      "fetched_keys": []
    }
  }
}
```

Each mux's `config` is the POST body for every key in its `keys`, which the Commit-Boost config names, and its `fetched_keys`, which only a URL or registry loader lists and which can change after the print. `default` is the `[[relays]]` body for every other key, or `null` without `[[relays]]`. Keys are lowercase 0x hex. `version` is `1`; refuse any other. To send the document with your own tooling:

- List the validator client's keys (`GET /eth/v1/keystores` and `GET /eth/v1/remotekeys`, where `404` means no remote keys), lowercase them, and write only those: some validator clients answer `202` for a key they do not hold.
- List every validator client before writing, then check each mux's `keys`: a key no client lists means a client is missing from your inventory, and a key two clients list is a slashing risk. A `fetched_keys` key no client lists is normal, such as an exited validator's. `apply` makes both checks.
- Give each key its mux's `config`, else `default`. With `default` `null`, leave other keys alone. Never `DELETE` a key's builder config: the key then falls back to the validator client's own builders. To take a key off Commit-Boost, POST `{"builders": []}` or its other builders.
- POST each body to `/eth/v1/validator/<pubkey>/builder_config` with `Content-Type: application/json`, and require `202`.
- On `404` for a key the client lists, stop: the client has no builder config endpoint. On `403`, stop: a [proposer settings file](#validator-builder-config) or a wrong token. On `400` naming `--allowDangerousTrustedPayments`, restart Lodestar with that flag. On `501` or `503`, retry later: Prysm answers these before Gloas is scheduled and while it is not ready.
- A POST replaces the key's whole config. To keep entries another tool wrote, GET it first and keep each entry whose `url`, parsed, differs from `advertised_url`, so that `http://cb:18550` and `http://cb:18550/` count as one; write at most 64 entries in all.
- Run one writer at a time per validator client, print again after a mux's loader gains keys, and read back a key after writing it.
- `print` exits `0` when a loader falls back, such as to the SSV public API, and says so only in a warning on stderr, so fail your job on any stderr line containing `WARN`.
- Add a builder to Commit-Boost's config before writing builder configs that name it, and remove it from the builder configs before removing it from Commit-Boost; otherwise Commit-Boost reports those keys as stale or dials them as builders outside your config.
- Pass the token on stdin or from a file only its owner can read, never on the command line.

`jq -r '.muxes[] | .config as $c | (.keys + .fetched_keys)[] | [., ($c | tojson)] | @tsv'` turns the document into one line per mux key: the key, a tab and its POST body.

##### `apply` {#builder-config-apply}

```bash
commit-boost builder-config apply --config cb-config.toml --advertised-url http://cb.example.com:18550 \
  --vc http://127.0.0.1:5062=$HOME/.lighthouse/hoodi/validators/api-token.txt
```

Each `--vc` is a validator client to write to: its keymanager API, starting with `http://` or `https://`, then `=` and the file holding its API token. Repeat `--vc` for each client. The shell does not expand `~` after `=`, so write `$HOME`. With `--from <file>`, or `--from -` for stdin, `apply` writes a document `print` wrote in place of the Commit-Boost config. The document must be as `print` wrote it, with `advertised_url` exactly `--advertised-url`, and `--from` wins over `--config` and `CB_CONFIG`.

Each validator client serves its keymanager API only when started with the flag below. By default:

| Client | Keymanager API | Token file |
|---|---|---|
| Lighthouse | `--http`, at `http://127.0.0.1:5062` | `validators/api-token.txt` in its data directory, such as `~/.lighthouse/hoodi/validators/api-token.txt`; `--http-token-path` moves it |
| Lodestar | `--keymanager`, at `http://127.0.0.1:5062` | `validator-db/api-token.txt` in its data directory; `--keymanager.tokenFile` moves it. Lodestar rewrites the file at every start, keeping the token |
| Prysm | `--rpc`, at `http://127.0.0.1:7500` | `~/.eth2validators/prysm-wallet-v2/auth-token` on Linux; `--keymanager-token-file` moves it. `apply` refuses a token file of more than one line, so regenerate an older two-line one with `validator web generate-auth-token` |

The token file is readable only by its owner, so run `apply` as the validator client's user, such as with `sudo -u <user>`, and write the token path in full, since `$HOME` expands to yours.

As of Nimbus 26.10.0, Nimbus stores builder config, but its beacon node does not request bids with it; its keys are written like any other's, so the output does not show this. Teku 26.9.1 and Grandine 3.0.0-rc.0 have no builder config endpoint.

`apply` asks each validator client given with `--vc` for the keys it holds, its keystores and remote-signer keys, and writes each key only to the client that holds it. It prints:

- `mux <id>: <n> keys` for each mux, before contacting a client;
- `accepted: <key> on <client> (mux <id>)` for each write, or `([[relays]])` for a key in no mux;
- `<client>: <n> keys listed, <n> written` for each client it wrote to, ending `, <n> not written` when some were not;
- a closing `done:` tally: keys written, keys a listed client did not get, errors and warnings, the loaders' warnings included.

`WARN:` lines go to stdout. `ERROR:` lines and the loaders' own warnings, such as a fallback to the SSV public API, go to stderr; `RUST_LOG` raises the loaders' log level, such as `RUST_LOG=info`. A failure on one client does not stop the others. A client that leaves 3 writes in a row unanswered, or answers `403` before any write succeeds, gets no further writes.

It exits:

- `0` when it prints no `ERROR:` line.
- `1` when it contacted the validator clients and printed an `ERROR:` line, such as for mux keys that no validator client given with `--vc` holds, or keys that two hold (a slashing risk). Those two errors list the keys.
- `2` when it stopped before contacting any validator client: a bad flag, which clap reports as `error:` and `apply` as `ERROR:`, an unreadable, empty or multi-line token file, a config error, a failed mux loader, or a `--from` document that does not match.

Keys that only a URL or registry loader lists, such as exited validators', are counted in one warning instead, since no client may hold them. When a client could not be listed, that warning and the error for mux keys no client lists both name it, since it may hold them.

A run over only some of the clients that hold a mux's keys, such as a sidecar in one validator client's pod or a canary on one client, fails on the keys the others hold. Pass `--partial` to such a run, and mux keys that no client given holds are counted in one warning, as is a client with no keys yet. A run's slashing check covers only the clients it is given, so also run `apply` over every client without `--partial`, from somewhere that reaches each keymanager API.

Each run rewrites every key's builder config in full, so running it again is safe, and a run over 500 keys takes under a second. Run it from a timer, such as every epoch, and after each validator client restart, so a key you import later is written without your noticing it was missing. Run it again after fixing an error, whenever you change the muxes, their keys, their builders or the values it reads, and whenever a validator client gains a key, which gets no bids through Commit-Boost until it is written. A Commit-Boost config reload does not reach the validator clients. A key you take out of a mux gets the `[[relays]]` config on the next run. Run one `apply` at a time: each run writes every key and the last write wins, so two overlapping runs with different configs can leave a mix of both while both exit `0`.

Run it from the directory you run Commit-Boost from, so a relative file `loader` path names the same file; a `mux <id>: <n> keys` count you do not expect means it read a different or stale keys file. It never contacts a relay, so it needs none of the relays' `headers` secrets. It sends each validator client's token with every request, so use an `https://` keymanager URL unless it reaches the client over loopback, as from the same host or a sidecar in its pod. For a keymanager API whose certificate comes from a private certificate authority, set `SSL_CERT_FILE` to a bundle that holds it and the public roots your URL and registry loaders need.

Each write replaces the key's whole builder config. To keep entries another tool wrote, add `--preserve-entries`: it keeps every stored entry whose `url` is not the advertised URL. After changing `--advertised-url`, the entries at the old URL stay. To remove them, run once without `--preserve-entries`, which also removes the other tools' entries, then write those again. A kept entry is written back with the values the validator client filled in for it, so it does not follow later changes to the key's top-level values or the client's settings. A key with no builder config of its own gets a copy of the client's global builders, the ones it uses for every key without its own config.

To read back what a client stored for a key:

```bash
printf 'Authorization: Bearer %s' "$(cat <token file>)" | \
  curl -H @- <keymanager URL>/eth/v1/validator/<pubkey>/builder_config
```

The written config sets every value, so your validator client's own builder defaults never apply to these keys. Left unset, each defaults to the most profitable choice:

- `builder_boost_factor` is `100`, so a builder's bid is weighed against the local block at its full value. This overrides a validator client default that favours the local block.
- `min_bid` is `0`, so the beacon node takes any bid that beats its local block.
- The cap is unclamped, `18446744073709551615`, so the beacon node counts a builder's whole execution payment toward its bid. That trusts each builder to pay what it promised, since the protocol does not enforce that payment. Set a cap in Gwei in `[pbs]` or on a relay entry to limit it.

Where each builder config value comes from:

| Builder config field | Source |
|---|---|
| entry `url` | `--advertised-url` |
| entry `auth_data` | The hostname of the relay's `url`. Builders on one host share one entry, so they need the same cap |
| entry `max_execution_payment` | The relay entry's `max_execution_payment_gwei`, in `[[mux.relays]]` or `[[relays]]`, else the `[pbs]` one, else unclamped. `"unclamped"` sets that explicitly |
| entry `min_bid` | For a mux key, the mux `min_bid_eth`; else `[pbs] min_bid_eth`, else `0`; rounded down to whole Gwei |
| entry `builder_boost_factor` | For a mux key, the mux `builder_boost_factor`; else `100` |
| top-level `min_bid`, `builder_boost_factor` | `[pbs]` `min_bid_p2p_eth` and `builder_boost_factor_p2p`, one setting for every key, else the entry values. They govern bids received over p2p |
| entry `builder_pubkeys` | Always empty, so any builder's bid is accepted |

#### With Docker {#builder-config-with-docker}

`builder-config` runs from the Commit-Boost image, `ghcr.io/commit-boost/commit-boost:<tag>`, whose entrypoint is `commit-boost`. Use the tag `cb_pbs` runs, which `docker inspect -f '{{.Config.Image}}' cb_pbs` prints.

With the validator client on the host, run `apply` from the directory that holds `cb.docker-compose.yml`, so the config and any keys file are the ones Commit-Boost uses:

```bash
docker run --rm --network host --user "$(sudo stat -c %u:%g <token file>)" \
  --mount type=bind,src="$PWD",dst=/cb,readonly -w /cb \
  --mount type=bind,src=<token file>,dst=/token,readonly \
  ghcr.io/commit-boost/commit-boost:<tag> builder-config apply --config cb-config.toml \
  --advertised-url http://127.0.0.1:18550 --vc http://127.0.0.1:5062=/token
```

- `--network host` lets it reach a validator client listening on the host's `127.0.0.1`; in a bridge network, `127.0.0.1` is the container itself, and `docker compose run` cannot change that.
- `--user` runs it as the token file's owner, the only user who can read it. `sudo` lets `stat` see the file inside the validator client's private data directory; without it `--user` is empty and `apply` cannot read the token.
- `--mount` refuses a source that does not exist, where `-v` would create an empty directory in its place.
- `-w /cb` makes the config's relative paths resolve in the mounted directory. An absolute `loader` path must exist inside the container too.
- `--advertised-url` is the URL your beacon node's builder flag uses: `http://127.0.0.1:<pbs.port>` for a beacon node on the host and the Commit-Boost that `commit-boost init` sets up. `http://cb_pbs:18550` works only inside the compose network.

With the validator client in another container, such as a packaged stack's, print inside `cb_pbs`, where the config and keys files already are, and apply in a container that joins the client's network:

```bash
docker exec cb_pbs commit-boost builder-config print --advertised-url <URL> \
  | docker run -i --rm --network container:<vc container> --user "$(docker exec <vc container> id -u)" \
      --mount type=volume,src=<volume holding the token>,dst=/vc,readonly \
      ghcr.io/commit-boost/commit-boost:<tag> builder-config apply --from - \
      --advertised-url <URL> --vc http://127.0.0.1:<keymanager port>=/vc/<token path>
```

Mount only the volume that holds the token, not the client's keystores. A packaged stack may name its Commit-Boost container something other than `cb_pbs`.

#### On Kubernetes {#builder-config-on-kubernetes}

A Kubernetes deployment usually serves a validator client's keymanager API only inside its pod, and the client often writes its own token. Run `apply` as a sidecar in the validator client's pod, from the Commit-Boost image:

- Point `--vc` at `http://127.0.0.1:<port>` and at the token file on the client's data volume, mounted read-only. The file is readable only by its owner, so set the sidecar's `securityContext.runAsUser` to the client's user. A token you supply from a Secret works too, but not mounted read-only at Lodestar's `--keymanager.tokenFile`, which Lodestar rewrites at every start.
- Do not make it an init container the validator client waits for: `apply` exits at once when the keymanager API is not listening, so the pod never starts. A native sidecar, an init container with `restartPolicy: Always`, works as long as it has no `startupProbe`, which would hold the client back the same way.
- The image's entrypoint is `commit-boost` and its default argument `pbs`. Give the sidecar a `command` that runs `commit-boost builder-config apply` in a loop and stays up between runs: with `args` alone it exits after one run and restarts in CrashLoopBackOff. The API can come up later than the sidecar, so retry until it exits `0`. Run it again after any failed run, when the Commit-Boost config or a keys file changes, and on a timer, such as every epoch, which also covers keys the client gains and a client that restarts with an empty store. A pass over 500 keys takes under a second. A shell loop running as PID 1 must trap `SIGTERM` and sleep with `sleep <n> & wait $!`, since the shell runs a trap only once its foreground command ends; otherwise the pod stays in Terminating until its grace period ends.
- A sidecar sees one validator client, so pass `--partial`. Its slashing check then covers only that client, so also run `apply` over every client without `--partial`, from somewhere that reaches each keymanager API, such as through `kubectl port-forward` with each pod's token.
- Mount the Commit-Boost config, and any keys file a mux loader names, from the same source as Commit-Boost's, at the paths Commit-Boost uses, and set any `CB_MUX_PATH_<id>` Commit-Boost's container sets on the sidecar too. The image works in `/`, so write `loader` paths as absolute paths. A ConfigMap cannot be mounted from another namespace, and a copy that drifts writes builders Commit-Boost does not route. Set `CB_CONFIG` on the sidecar, or pass `--config`. A URL or registry loader runs in the sidecar, so the pod needs egress to its URL or `rpc_url`.
- Or render with `print` in CI into a ConfigMap and run `apply --from <file> --partial` in the sidecar, so the pod needs no Commit-Boost config, keys file or loader access. Render again on every config change, and on a schedule for a registry loader's keys.

`--advertised-url` goes into every key's builder config as given, so use the address your beacon nodes resolve: a Service name such as `http://commit-boost.<namespace>.svc:18550`, or `http://localhost:18550` when Commit-Boost runs in each beacon node's pod. Every beacon node a validator client fails over to must resolve it. Commit-Boost replicas behind one Service share its URL, since Commit-Boost keeps no state between a bid request and its block. With `--preserve-entries`, `apply` keeps every stored entry whose parsed URL differs from `--advertised-url`, so keep one spelling of the Service name. If some beacon nodes reach Commit-Boost at a different address, run `apply` once for each address, with `--partial` and the validator clients whose beacon nodes use it. After the address changes, run once without `--preserve-entries`, or each key keeps an entry at the old address.

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

## Metrics

With [metrics](./running/metrics.md) enabled, the ePBS endpoints use the `endpoint` labels `get_execution_payload_bid`, `submit_builder_preferences` and `submit_signed_beacon_block`.

| Question | Series |
|---|---|
| What did Commit-Boost answer the beacon node? | `cb_pbs_beacon_node_status_code_total`: `200` or `204` for a bid request, `202` for preferences, `202` for the signed block whatever the builders answer, `4xx` for a rejected request, `500` when no builder accepted the preferences |
| What did each builder answer? | `cb_pbs_relay_status_code_total`, by `relay_id`: the builder's HTTP status, or `555` when no response arrived (timeout, DNS or connection failure). Requests to builders outside your config count under `relay_id="dial"`, except one Commit-Boost [refuses to dial](#builders-outside-your-config), which gets no request |
| How fast are builders? | `cb_pbs_relay_latency`, by `relay_id` |
| What are builders bidding? | `cb_pbs_relay_header_value` (the bid's `value` in Gwei, without the execution payment) and `cb_pbs_relay_last_slot`, by `relay_id`, from each bid a builder serves |

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Bid requests get `400` "auth.message.data does not match any configured builder" | The auth data is neither a hostname nor an `http(s)` URL, or the request came from another Commit-Boost and matches none of this one's relay entries | Correct the `auth_data` in the key's [builder config](#validator-builder-config), or add the builder as a relay entry on the Commit-Boost the request reaches |
| Bid requests get `400` "the addressed builder's host does not resolve or resolves to a disallowed address" | The auth data names a builder outside your config whose host does not resolve or resolves to an [internal address](#builders-outside-your-config) | Add the builder as a relay entry for the key, or write or correct the key's [builder config](#validator-builder-config) |
| A builder answers bid requests with `400` (`cb_pbs_relay_status_code_total{endpoint="get_execution_payload_bid",http_status_code="400"}`) | The builder compares auth data byte for byte and expects something other than what the key sends, such as its hostname without `?` parameters | Send the auth data the builder expects: its hostname or its URL, the forms Commit-Boost [routes by](#routing-by-auth-data), with `?` parameters only if it accepts them |
| Commit-Boost does not start or reload, or `commit-boost init` fails, with "proposer_deadline_buffer_ms must be greater than 0 and less than one slot" | `proposer_deadline_buffer_ms` is `0`, or one slot or more | Set it above `0` and under one slot, or remove it to use the default `50` |
| The signed block gets `415` | The beacon node sends it as JSON | Configure the beacon node to send SSZ |
| Commit-Boost logs "no builder accepted the signed beacon block" | The winning bid came from a builder outside your config, which gets the block over gossip, or your builders did not accept it. The beacon node gossips the block either way | If the bid came from a configured builder, check its answer in `cb_pbs_relay_status_code_total{endpoint="submit_signed_beacon_block"}` |
| Commit-Boost returns `200` but the beacon node builds locally | The beacon node rejected the bid, or valued its local block higher after `builder_boost_factor` | Compare the bid with the key's `min_bid` and `builder_boost_factor` |
| `builder-config` stops with "unknown keys in the Commit-Boost config" | A misspelled `[pbs]` or `[[mux]]` key, or a `[pbs]` key that a custom PBS module reads | Fix each misspelled key. For a custom module's keys, run `builder-config` on a copy of the config without them |
| `builder-config` exits `2` | It stopped before contacting a validator client. Its `ERROR:` line, or clap's `error:` line for a flag clap rejects, names the flag, token file, config or mux loader | Fix what the line names |
| `builder-config apply` fails with "key listing failed" and `Connection refused` | The validator client's keymanager API is off, or listens at another address | Start the client with its keymanager API flag ([the client table](#builder-config-apply)) and check the `--vc` URL |
| `builder-config apply` fails with "key listing failed" and `401` or `403` | The token does not match the validator client's | Point `--vc` at the client's current token file |
| `builder-config apply` fails with "no validator client lists a key" | Every validator client given with `--vc` was listed, and none holds a key | Point `--vc` at the keymanager APIs of the validator clients that hold your keys. With `--partial`, this is a warning |
| `builder-config apply` fails with "keys in a mux that no validator client lists" | No validator client given with `--vc` holds the keys the error lists, which are in a mux's `validator_pubkeys` or keys file. The error also names any client that could not be listed and may hold them | Fix that client's error, add a `--vc` for the client that holds the keys, pass `--partial` if another run covers those clients, or take the keys out of the mux |
| `builder-config apply` fails with "a slashing risk" | More than one validator client given with `--vc` holds the keys the error lists, and it names the clients; `apply` has still written each key's builder config to each that accepted it. Two clients with the same keys are usually a migration or a failover left running | Stop the duplicate validator client, or remove the keys from every client but one, then run `apply` again. `apply` refuses one client given twice, such as `localhost` and `127.0.0.1` on one port |
| `builder-config apply` reports "builder_config probe failed: 501" | Prysm answers `501` until Gloas is scheduled, and while it is not ready | Run `apply` again once the fork is scheduled |
| `builder-config apply` reports "no builder_config support" | The validator client has no builder config endpoint: an older release, or Teku or Grandine | Upgrade it, or leave it out of `--vc` |
| `builder-config apply` reports "writes in a row got no answer" | The validator client hung or dropped the connections, so `apply` stopped writing to it | Check the validator client, then run `apply` again |
| `builder-config apply` reports that a validator client "answered 403 before any write landed" | Lodestar runs with `--proposerSettingsFile`, which takes over its builder config | Move off the settings file ([proposer settings files](#validator-builder-config)), or leave the client out of `--vc` |
| `builder-config apply` reports that a validator client "refuses a max_execution_payment above 0" | Lodestar's validator client refuses a cap above 0 unless it runs with `--allowDangerousTrustedPayments`, and the default cap is unclamped. `apply` writes no further key with a cap above 0 to that client. A refused key keeps its old builder config; one that had none gets no bids through Commit-Boost | Restart the validator client with `--allowDangerousTrustedPayments`, then run `apply` again |
