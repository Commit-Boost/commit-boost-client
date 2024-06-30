# Commit-Boost

## Dependencies

- Docker Desktop v4.29 or later. We are using the `host` network driver on docker container instantiation, so our client needs to support the feature.

## Usage
Note: Ensure that the ports used by the docker-compose are set up in the config.toml are not already in use by other processes and are not blocked by a firewall

First, initialize the submodule with:
```bash
git submodule update --init --recursive
```

Then, build and run the grafana and prometheus docker containers with:
```bash
docker-compose build
docker-compose up -d
```

Finally, run the project with:
```bash
cargo run --bin commit-boost -- start config.example.toml
```


static config -> toml
runtime config in docker compose
create .env file

module contract
JWT
metrics
config file (with id)

pbs contract
JWT (optional)
metrics
config

signer image



## Acknowledgements
- [MEV boost](https://github.com/flashbots/mev-boost)
- [Reth](https://github.com/paradigmxyz/reth)
- [Lighthouse](https://github.com/sigp/lighthouse)

## License
MIT + Apache-2.0
