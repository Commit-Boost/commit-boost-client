---
sidebar_position: 3
---

# Running
Here are the commands currently supported by the CLI.

## Init

After creating the `cb-config.toml` file, you can now run the Commit-Boost sidecar. First run:
```bash
commit-boost init --config cb-config.toml
```
This will create three files:
- `cb.docker-compose.yml`, which contains the full setup of the Commit-Boost services
- `.cb.env`, with local env variables, including JWTs for modules
- `target.json`, which enables dynamic discovery of services for metrics scraping via Prometheus

## Start

To start Commit-Boost run:
```bash
commit-boost start --docker cb.docker-compose.yml --env .cb.env
```

This will start up the services including PBS, commit modules (if any), and metrics collection.

The MEV-Boost server will be exposed at `pbs.port` from the config, `18550` in our example. You'll need to point your CL/Validator client to this port to be able to source blocks from the builder market.

This will also start a Prometheus server on port `9090` and a Grafana instance on port `3000`. We're working to provide [built-in dashboards](https://github.com/Commit-Boost/commit-boost-client/issues/14) for the core services.


## Logs

To check logs, run:
```bash
commit-boost logs
```
This will currently show all logs from the different services via the Docker logs interface. We're working to add [persistent](https://github.com/Commit-Boost/commit-boost-client/issues/21) logging. 

## Stop

To stop all the services and cleanup, simply run:
```bash
commit-boost stop
```
This will wind down all services and clear internal networks and file mounts.