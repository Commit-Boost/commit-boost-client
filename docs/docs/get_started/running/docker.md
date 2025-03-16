---
description: Run Commit-Boost with Docker
---

# Docker
The Commit-Boost CLI generates a dynamic `docker-compose.yml` file using the provided `.toml` config file. This is the recommended approach as Docker provides sandboxing of the containers from the rest of your system.

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
docker compose --env-file ".cb.env" -f ".cb.docker-compose.yml" up -d
```

This will run the all the configured services, including PBS, signer and modules (if any).

The MEV-Boost server will be exposed at `pbs.port` from the config, `18550` in our example. You'll need to point your CL/Validator client to this port to be able to source blocks from the builder market.

## Logs
To check the logs, run:
```bash
docker compose --env-file ".cb.env" -f ".cb.docker-compose.yml" logs -f
```
This will currently show all logs from the different services via the Docker logs interface. Logs are also optionally saved to file, depending on your `[logs]` configuration.

## Stop

To stop all the services and cleanup, simply run:
```bash
docker compose --env-file ".cb.env" -f ".cb.docker-compose.yml" down
```
This will wind down all services and clear internal networks and file mounts.