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
- We now added a `signer` section which will be used to create the Signer module. To load keys in the module, we currently support the Lighthouse `validators_dir` keys and secrets. We're working on adding support for additional keystores, including remote signers.
- There is now a `[[modules]]` section which at a minimum needs to specify the module `id`, `type` and `docker_image`. Additional parameters needed for the business logic of the module will also be here,

To learn more about developing modules, check out [here](/category/developing).
