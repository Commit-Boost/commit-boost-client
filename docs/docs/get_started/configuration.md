---
sidebar_position: 2
---

# Configuration

After the Commit-Boost CLI is setup as detailed in the previous section, you will need to create a `cb-config.toml` file, detailing all the services that you want to run. 

## Minimal PBS setup on Holesky
```toml
chain = "Holesky"

[pbs]
port = 18550
# Add relays enpoints here
relays = []
relay_check = true

[metrics]
prometheus_config = "./docker/prometheus.yml"
use_grafana = true
```

You can find a list of MEV-Boost Holesky relays [here](https://www.coincashew.com/coins/overview-eth/mev-boost/mev-relay-list#holesky-testnet-relays).
For the full config parameters, check out [here](https://github.com/Commit-Boost/commit-boost-client/blob/main/config.example.toml#L4-L11) (more detailed docs incoming).
Note that in this setup, the signer module will not be started.

## Custom module
We currently provide a test module that needs to be built as a Docker image. To build the module run:
```bash
bash scripts/build_local_module.sh
```
This will create a Docker image called `test_da_commit` that periodically requests signatures from the validator. 

The `cb-config.toml` file needs to be updated as follows:
```toml
[pbs]
port = 18550
# Add relays enpoints here
relays = []
relay_check = true

[signer]
[signer.loader]
keys_path = "/path/to/keys"
secrets_path = "/path/to.secrets"

[[modules]]
id = "DA_COMMIT"
docker_image = "test_da_commit"
sleep_secs = 5

[metrics]
prometheus_config = "./docker/prometheus.yml"
use_grafana = true
```

A few things to note:
- We now added a `signer` section which will be used to create the Signer module. To load keys in the module, we currently support the Lighthouse `validators_dir` keys and secrets. We're working on adding support for additional keystores, including remote signers.
- There is now a `[[module]]` section which at a minimum needs to specify the module `id` and `docker_image`. Additional parameters needed for the business logic of the module will also be here,

To learn more about developing modules, check out [here](/category/developing).