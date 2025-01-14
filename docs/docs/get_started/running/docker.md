---
description: Run Commit-Boost with Docker
---

# Docker
The Commit-Boost CLI will generate a dynamic `docker-compose.yml` file using the provided `.toml` config file. This is the recommended approach as Docker provides sandboxing of the containers from the rest of your system.

## Init

First run:
```bash
commit-boost-cli init --config cb-config.toml
```
This will create up to three files:
- `cb.docker-compose.yml` which contains the full setup of the Commit-Boost services.
- `.cb.env` with local env variables, including JWTs for modules, only created if the signer module is enabled.
- `target.json` which enables dynamic discovery of services for metrics scraping via Prometheus, only created if metrics are enabled.

## Start

To start Commit-Boost run:
```bash
commit-boost-cli start --docker cb.docker-compose.yml [--env .cb.env]
```

This will run `docker compose up` with the correct envs, and start up the services including PBS, commit modules (if any), and metrics collection (if enabled).

The MEV-Boost server will be exposed at `pbs.port` from the config, `18550` in our example. You'll need to point your CL/Validator client to this port to be able to source blocks from the builder market.

If enabled, this will also start a Prometheus server on port `9090` and a Grafana instance on port `3000`. In Grafana, you will also find some preset dashboards already connected.


## Logs

To check logs, run:
```bash
commit-boost-cli logs
```
This will currently show all logs from the different services via the Docker logs interface. Logs are also optionally saved to file, depending on your `[logs]` configuration.

## Stop

To stop all the services and cleanup, simply run:
```bash
commit-boost-cli stop
```
This will wind down all services and clear internal networks and file mounts.