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

This will run all the configured services, including PBS, signer and modules (if any).

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


## Example with PBS Only

This section provides an example of a configuration where only the PBS service is run with its default configuration, and the Docker compose file produced by that configuration.

All of PBS's parameters are controlled via the [Commit-Boost TOML configuration file](../configuration.md); the service cannot currently be controlled with command-line arguments. Therefore it is crucial to ensure that you have a configuration file present with all of the settings you require *before* starting the service, as this file will be mounted within the Docker container as a volume in read-only mode.

Below is a simple configuration for running only the PBS service on the Hoodi network with two relays:

```
chain = "Hoodi"

[pbs]
docker_image = "ghcr.io/commit-boost/pbs:v0.8.0"
relay_check = true
wait_all_registrations = true

[[relays]]
id = "abc"
url = "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz"

[[relays]]
id = "def"
url = "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@def.xyz"
```

Note that there are many more parameters that Commit-Boost supports, but they are all omitted and thus will use their default options. For a full description of the default options within the config file, go to the [annotated configuration example](../../../../config.example.toml).

The relays here are placeholder for the sake of the example; for a list of actual relays, visit [the EthStaker relay list](https://github.com/eth-educators/ethstaker-guides/blob/main/MEV-relay-list.md).


### Commit-Boost CLI Output

Run `commit-boost-cli init --config cb-config.toml` with the above configuration, the CLI will produce the following Docker Compose file:

```
services:
  cb_pbs:
    healthcheck:
      test: curl -f http://localhost:18550/eth/v1/builder/status
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 5s
    image: ghcr.io/commit-boost/pbs:v0.8.0
    container_name: cb_pbs
    ports:
    - 127.0.0.1:18550:18550
    environment:
      CB_CONFIG: /cb-config.toml
      CB_PBS_ENDPOINT: 0.0.0.0:18550
    volumes:
    - ./cb-config.toml:/cb-config.toml:ro
```

This will run the PBS service in a container named `cb_pbs`.


### Configuration File Volume

The CLI creates a read-only volume binding for the config file, which the PBS service needs to run. The Docker compose file that it creates with the `init` command, `cb.docker-compose.yml`, will be placed into your current working directory when you run the CLI. The volume source will be specified as a *relative path* to that working directory, so it's ideal if the config file is directly within your working directory (or a subdirectory). If you need to specify an absolute path for the config file, you can adjust the `volumes` entry within the Docker compose file manually after its creation.

Since this is a volume, the PBS service container will reload the file from disk any time it's restarted. That means you can change the file any time after the Docker compose file is created to tweak PBS's parameters, but it also means the config file must stay in the same location; if you move it, the PBS container won't be able to mount it anymore and fail to start unless you manually adjust the volume's source location.


### Networking

The CLI will force the PBS service to bind to `0.0.0.0` within Docker's internal network so other Docker containers can access it, but it will only expose the API port (default `18550`) to `127.0.0.1` on your host machine. That way any processes running on the same machine can access it on that port. If you want to open the port for access across your entire network, not just your local machine, you can add the line:

```
host = "0.0.0.0"
```

to the `[pbs]` section in the configuration. This will cause the resulting `ports` entry in the Docker compose file to become:

```
    ports:
    - 0.0.0.0:18550:18550
```

though you will need to add an entry to your local machine's firewall software (if applicable) for other machines to access it.

Currently, the CLI will always export the PBS service's API port in one of these two ways. If you don't want to expose it at all, so it can only be accessed by other Docker containers running within Docker's internal network, you will need to manually remove the `ports` entry from the Docker compose file after it's been created:

```
    ports: []
```


## Example with PBS, Signer, and a Signer Module

In this scenario we will be running the PBS service, the Signer service, and a module (`DA_COMMIT`) that interacts with the Signer service's API.

All of both PBS's and the Signer's parameters are controlled via the [Commit-Boost TOML configuration file](../configuration.md); the services cannot currently be controlled with command-line arguments. Therefore it is crucial to ensure that you have a configuration file present with all of the settings you require *before* starting the services, as this file will be mounted within the Docker containers as a volume in read-only mode.

Below is a simple configuration for running only the three modules on the Hoodi network with two relays, extended from the prior scenario above:

```
chain = "Hoodi"

[pbs]
docker_image = "ghcr.io/commit-boost/pbs:v0.8.0"
relay_check = true
wait_all_registrations = true

[[relays]]
id = "abc"
url = "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz"

[[relays]]
id = "def"
url = "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@def.xyz"

[signer]
port = 20000

[signer.local.loader]
format = "lighthouse"
keys_path = "./keys"
secrets_path = "./secrets"

[[modules]]
id = "DA_COMMIT"
type = "commit"
docker_image = "test_da_commit"
sleep_secs = 5
```

Note that there are many more parameters that Commit-Boost supports, but they are all omitted and thus will use their default options. For a full description of the default options within the config file, go to the [annotated configuration example](../../../../config.example.toml).

The relays here are placeholder for the sake of the example; for a list of actual relays, visit [the EthStaker relay list](https://github.com/eth-educators/ethstaker-guides/blob/main/MEV-relay-list.md).

In this scenario there are two folders in the same directory as the configuration file (the working directory): `keys` and `secrets`. These correspond to the folders containing the [EIP-2335 keystores](../configuration.md#local-signer) and secrets in Lighthouse format. For your own keys, adjust the `format` parameter within the configuration and directory paths accordingly.


### Commit-Boost CLI Output

Run `commit-boost-cli init --config cb-config.toml` with the above configuration, the CLI will produce two files:

- `cb.docker-compose.yml`
- `.cb.env`

The Docker compose file will have these contents:

```
services:
  cb_da_commit:
    image: test_da_commit
    container_name: cb_da_commit
    environment:
      CB_MODULE_ID: DA_COMMIT
      CB_CONFIG: /cb-config.toml
      CB_SIGNER_JWT: ${CB_JWT_DA_COMMIT}
      CB_SIGNER_URL: http://cb_signer:20000
    volumes:
    - ./cb-config.toml:/cb-config.toml:ro
    networks:
    - signer_network
    depends_on:
      cb_signer:
        condition: service_healthy
  cb_pbs:
    healthcheck:
      test: curl -f http://localhost:18550/eth/v1/builder/status
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 5s
    image: ghcr.io/commit-boost/pbs:latest
    container_name: cb_pbs
    ports:
    - 127.0.0.1:18550:18550
    environment:
      CB_CONFIG: /cb-config.toml
      CB_PBS_ENDPOINT: 0.0.0.0:18550
    volumes:
    - ./cb-config.toml:/cb-config.toml:ro
  cb_signer:
    healthcheck:
      test: curl -f http://localhost:20000/status
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 5s
    image: ghcr.io/commit-boost/signer:latest
    container_name: cb_signer
    ports:
    - 127.0.0.1:20000:20000
    environment:
      CB_CONFIG: /cb-config.toml
      CB_JWTS: ${CB_JWTS}
      CB_SIGNER_ENDPOINT: 0.0.0.0:20000
      CB_SIGNER_LOADER_KEYS_DIR: /keys
      CB_SIGNER_LOADER_SECRETS_DIR: /secrets
    volumes:
    - ./cb-config.toml:/cb-config.toml:ro
    - ./keys:/keys:ro
    - ./secrets:/secrets:ro
    networks:
    - signer_network
networks:
  signer_network:
    driver: bridge

```

This will create three Docker containers when executed:

- `cb_pbs` for the PBS service
- `cb_signer` for the Signer service
- `cb_da_commit` for the example / test module that interacts with the Signer service API

Finally, the `.cb.env` file produced will look like this:

```
CB_JWT_DA_COMMIT=mwDSSr7chwy9eFf7RhedBoyBtrwFUjSQ
CB_JWTS=DA_COMMIT=mwDSSr7chwy9eFf7RhedBoyBtrwFUjSQ
```

The Signer service needs JWT authentication from each of its modules. The CLI creates these and embeds them into the containers via environment variables automatically for convenience. This is demonstrated for the Signer module within the `environment` compose block: the `CB_JWTS: ${CB_JWTS}` forwards the `CB_JWTS` environment variable that's present when running Docker compose. The CLI requests that you do so via the command `docker compose --env-file "./.cb.env" -f "./cb.docker-compose.yml" up -d`; the `--env-file "./.cb.env"` handles loading the CLI's JWT output into this environment variable.

Similarly, for the `cb_da_commit` module, the `CB_SIGNER_JWT: ${CB_JWT_DA_COMMIT}` line within its `environment` block will set the JWT that it should use to authenticate with the Signer service.


### Configuration File Volume

As with the PBS-only example, the configuration file is placed into a read-only volume binding for all three images to reference. The same rules apply, so please read the [section in the PBS example](#configuration-file-volume) for details on how this works.


### Networking

The CLI will force both the PBS and Signer API endpoints to bind to `0.0.0.0` within Docker's internal network so other Docker containers can access them, but it will only expose the API port (default `18550` for PBS and `20000` for the Signer) to `127.0.0.1` on your host machine. That way any processes running on the same machine can access them on their respective ports. If you want to open the ports for access across your entire network, not just your local machine, you can add the line:

```
host = "0.0.0.0"
```

to both the `[pbs]` and `[signer]` sections in the configuration. This will cause the resulting `ports` entries in the Docker compose file to become:

```
  cb_pbs:
    ...
    ports:
    - 0.0.0.0:18550:18550


  cb_signer:
    ...
    ports:
    - 0.0.0.0:20000:20000
```

though you will need to add entries to your local machine's firewall software (if applicable) for other machines to access them.

Currently, the CLI will always export the PBS and Signer services' API ports in one of these two ways. If you don't want to expose them at all, so they can only be accessed by other Docker containers running within Docker's internal network, you will need to manually remove the `ports` entries from the Docker compose files after they've been created:

```
    ports: []
```
