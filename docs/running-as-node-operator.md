# Running as a Node Operator
## Overview
Commit Boost currently has a "container-centric" approach, i.e. services are mapped to containers which are spawned using docker-compose.

There are currently two modules that are provided by the core Commit-Boost:
- the Proposer-Builder Separation (PBS) module (implements the [BuilderAPI](https://ethereum.github.io/builder-specs/) for [MEV Boost](https://docs.flashbots.net/flashbots-mev-boost/architecture-overview/specifications))
- the signer module (implements the [Signer API](https://github.com/Commit-Boost/commit-boost-client/blob/main/api/signer-api.yml))

While in development you have to build them manually as Commit Boost will search for the images to run, eventually we'll provide images to pull from the Docker registry. You can do so by running [this script](https://github.com/Commit-Boost/commit-boost-client/blob/main/scripts/build_local_images.sh)
Commit Boost also supports "Commit Modules", which are modules that leverage the Signer API to request signatures from the proposer. You can find an example [here](https://github.com/Commit-Boost/commit-boost-client/blob/main/examples/da_commit). Commit Modules also need to be built as docker images and specified in the config file. You can build the local example by running [this script](https://github.com/Commit-Boost/commit-boost-client/blob/main/scripts/build_local_module.sh).

Note: because Commit Boost currently uses Docker underneath, if you require `sudo` to interact with Docker, you will need `sudo` to launch some Commit Boost commands.

## Config
The main config file is a .toml which specifies how modules should be built, and their configs. Full specifations are WIP. You can find an example here
## Build
You can compile the project using
```cargo build --release```
### Initialize 
Use this command to setup the Docker Compose file that will be used to run the services. For example:
```./target/release/commit-boost init --config config.example.toml```
This will create three files:
- `cb.docker-compose.yml` - used to start services
- `.cb.env` - with local env variables to be loaded at runtime
- `targets.json`  - used by prometheus to dynamically discover metrics servers
### Build docker containers
Firstly, ensure you have Docker Engine up and running and authenticate using:
```docker login```
Then give execute permissions to the `scripts/build_local_images.sh` and `scripts/build_local_modules.sh` files:
```chmod +x scripts/build_local_modules.sh scripts/build_local_images.sh```
Finally, run the scripts:
```
./scripts/build_local_modules.sh
./scripts/build_local_iamges.sh
```

### Start
Once the init is done, you can start Commit Boost with start. For example:
```./target/release/commit-boost start --docker cb.docker-compose.yml --env .cb.env```
### Stop
```./target/release/commit-boost stop --docker cb.docker-compose.yml --env .cb.env```
### Logs
To listen for logs:
```./target/release/commit-boost logs --docker cb.docker-compose.yml```
