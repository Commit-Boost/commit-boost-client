---
description: Configure Commit-Boost
---

# Configuration

Commit-Boost needs a configuration file detailing all the services that you want to run. Create a `cb-config.toml` and adjust it depending on which modules you plan to run.

For a full explanation of all the fields, check out [here](https://github.com/Commit-Boost/commit-boost-client/blob/main/config.example.toml).

For some additional examples on config presets, check out [here](https://github.com/Commit-Boost/commit-boost-client/tree/main/configs).

## Minimal PBS setup on Holesky
```toml
chain = "Holesky"

[pbs]
port = 18550

[[relays]]
url = ""

[metrics]
prometheus_config = "./docker/prometheus.yml"
```

You can find a list of MEV-Boost Holesky relays [here](https://www.coincashew.com/coins/overview-eth/mev-boost/mev-relay-list#holesky-testnet-relays).
After the sidecar is started, it will expose a port (`18550` in this example), that you need to point your CL to. This may be different depending on which CL you're running, check out [here](https://docs.flashbots.net/flashbots-mev-boost/getting-started/system-requirements#consensus-client-configuration-guides) for a list of configuration guides.

Note that in this setup, the signer module will not be started.

## Signer module

To start the signer module, you need to include its parameters in the config file:

```toml
[signer]
[signer.loader]
format = "Lighthouse"
keys_path = "/path/to/keys"
secrets_path = "/path/to.secrets"
```

We currently support Lighthouse, Prysm, Teku and Lodestar's keystores so it's easier to load the keys. We're working on adding support for additional keystores, including remote signers. These are the expected file structures for each format:

<details>
  <summary>Lighthouse</summary>

  #### File structure:
  ```
  ├── keys
  │   ├── <PUBLIC_KEY_1>
  │   │   └── voting-keystore.json
  │   └── <PUBLIC_KEY_2>
  │       └── voting-keystore.json
  └── secrets
      ├── <PUBLIC_KEY_1>
      └── <PUBLIC_KEY_2>
  ```

  #### Config:
  ```toml
  [signer]
  [signer.loader]
  format = "Lighthouse"
  keys_path = "keys"
  secrets_path = "secrets"
  ```
</details>

<details>
  <summary>Prysm</summary>

  #### File structure:
  ```
  ├── wallet
  │   └── direct
  │       └── accounts
  │           └──all-accounts.keystore.json
  └── secrets
      └── password.txt
  ```

  #### Config:
  ```toml
  [signer]
  [signer.loader]
  format = "Prysm"
  keys_path = "wallet/direct/accounts/all-accounts.keystore.json"
  secrets_path = "secrets/password.txt"
  ```
</details>

<details>
  <summary>Teku</summary>

  #### File structure:
  ```
  ├── keys
  │   ├── <PUBLIC_KEY_1>.json
  │   └── <PUBLIC_KEY_2>.json
  └── secrets
      ├── <PUBLIC_KEY_1>.txt
      └── <PUBLIC_KEY_2>.txt
  ```

  #### Config:
  ```toml
  [signer]
  [signer.loader]
  format = "Teku"
  keys_path = "keys"
  secrets_path = "secrets"
  ```
</details>

<details>
  <summary>Lodestar</summary>

  #### File structure:
  ```
  ├── keys
  │   ├── <PUBLIC_KEY_1>.json
  │   └── <PUBLIC_KEY_2>.json
  └── secrets
      └── password.txt
  ```

  #### Config:
  ```toml
  [signer]
  [signer.loader]
  format = "Lodestar"
  keys_path = "keys"
  secrets_path = "secrets/password.txt"
  ```

  :::note
  All keys have the same password stored in `secrets/password.txt`
  :::
</details>


## Custom module
We currently provide a test module that needs to be built locally. To build the module run:
```bash
bash scripts/build_local_modules.sh
```
This will create a Docker image called `test_da_commit` that periodically requests signatures from the validator, and a `test_builder_log` module that logs BuilderAPI events.

The `cb-config.toml` file needs to be updated as follows:
```toml
[pbs]
port = 18550

[[relays]]
url = ""

[signer]
[signer.loader]
format = "Lighthouse"
keys_path = "/path/to/keys"
secrets_path = "/path/to.secrets"

[metrics]
prometheus_config = "./docker/prometheus.yml"

[[modules]]
id = "DA_COMMIT"
type = "commit"
docker_image = "test_da_commit"
sleep_secs = 5

[[modules]]
id = "BUILDER_LOG"
type = "events"
docker_image = "test_builder_log"
```

A few things to note:
- We now added a `signer` section which will be used to create the Signer module.
- There is now a `[[modules]]` section which at a minimum needs to specify the module `id`, `type` and `docker_image`. Additional parameters needed for the business logic of the module will also be here,

To learn more about developing modules, check out [here](/category/developing).

## Vouch
[Vouch](https://github.com/attestantio/vouch) is a multi-node validator client built by [Attestant](https://www.attestant.io/). Vouch is particular in that it also integrates a MEV-Boost client to interact with relays. The Commit-Boost PBS module is compatible with the Vouch `blockrelay` since it implements the Builder-API, just like relays do. For example, depending on your setup and preference, you may want to fetch headers from a given relay using Commit-Boost vs using the built-in Vouch `blockrelay`.

### Configuration
Get familiar on how to set up Vouch [here](https://github.com/attestantio/vouch/blob/master/docs/getting_started.md).

You can setup Commit-Boost with Vouch in two ways.
For simplicity, assume that in Vouch `blockrelay.listen-address: 127.0.0.0:19550` and in Commit-Boost `pbs.port = 18550`.

#### Beacon Node to Vouch
In this setup, the BN Builder-API endpoint will be pointing to the Vouch `blockrelay` (e.g. for Lighthouse you will need the flag `--builder=http://127.0.0.0:19550`).

Modify the `blockrelay.config` file to add Commit-Boost:
```json
"relays": {
    "http://127.0.0.0:18550": {}
}
```

#### Beacon Node to Commit Boost
In this setup, the BN Builder-API endpoint will be pointing to the PBS module (e.g. for Lighthouse you will need the flag `--builder=http://127.0.0.0:18550`).

This will bypass the `blockrelay` entirely so make sure all relays are properly configured in the `[[relays]]` section.

**Note**: this approach could also work if you have a multi-beacon-node setup, where some BNs fetch directly via Commit-Boost while others go through the `blockrelay`.

### Notes
- It's up to you to decide which relays will be connected via Commit-Boost (`[[relays]]` section in the `toml` config) and which via Vouch (additional entries in the `relays` field). Remember that any rate-limit will be shared across the two sidecars, if running on the same machine.
- You may occasionally see a `timeout` error during registrations, especially if you're running a large number of validators in the same instance. This can resolve itself as registrations will be cleared later in the epoch when relays are less busy processing other registrations. Alternatively you can also adjust the `builderclient.timeout` option in `.vouch.yml`.
