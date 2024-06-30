# Commit-Boost

## Dependencies

- Docker

## Usage
### Overview
Commit Boost currently has a "container-centric" approach, i.e. services are mapped to containers which are spawned using docker compose.

There are currently two modules that are provided by commit boost:
- the pbs module (implements the [BuilderAPI](https://ethereum.github.io/builder-specs/) for [MEV Boost](https://docs.flashbots.net/flashbots-mev-boost/architecture-overview/specifications))
- the signer module (implements the [Signer API](api/signer-api.yml))

While in development you have to build them manually as Commit Boost will search for the images to run, eventually we'll provide images to pull from the Docker registry. You can do so by running [this script](scripts/build_local_images.sh).

Commit Boost also supports "Commit Modules", which are modules that leverage the Signer API to request signatures from the proposer. You can find an example [here](examples/da_commit). Commit Modules also need to be built as docker images and specified in the config file. You can build the local example by running [this script](scripts/build_local_module.sh).

Note: that because Commit Boost leverages Docker, if you require `sudo` to interact with Docker, so will Commit Boost.

### Config
The main config file is a `.toml` which specifies how modules should be built, and their configs. Full specifations are WIP. You can find an example [here](./config.example.toml)

### Running

#### Init
Use this command to setup the Docker Compose file that will be used to run the services. For example:
```shell
./target/debug/commit-boost init --config config.example.toml
```
This will create three files:
- `cb.docker-compose.yml`, used to start services
- `.cb.env`, with local env variables to be loaded at runtime
- `targets.json`, used by prometheus to dynamiccaly discover metrics servers

#### Start
Once the `init` is done, you can start Commit Boost with `start`. For example:
```shell
./target/debug/commit-boost start --docker cb.docker-compose.yml --env .cb.env
```

#### Stop
```shell
./target/debug/commit-boost stop --docker cb.docker-compose.yml --env .cb.env
```

### Logs
To listen to logs:
```shell
./target/debug/commit-boost stop --docker cb.docker-compose.yml --env .cb.env
```


TODO:
- how services are started with configs
- describe metrics


## Acknowledgements
- [MEV boost](https://github.com/flashbots/mev-boost)
- [Reth](https://github.com/paradigmxyz/reth)
- [Lighthouse](https://github.com/sigp/lighthouse)

## License
MIT + Apache-2.0
