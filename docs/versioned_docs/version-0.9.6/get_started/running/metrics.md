---
description: Setup metrics collection
---

# Metrics

Commit-Boost can be configured to collect metrics from the different services and expose them to be scraped from Prometheus.

Make sure to add the `[metrics]` section to your config file:

```toml
[metrics]
enabled = true
```
If the section is missing, metrics collection will be disabled. If you generated the `docker-compose.yml` file with `commit-boost-cli`, metrics ports will be automatically configured, and a sample `target.json` file will be created. If you're running the binaries directly, you will need to set the correct environment variables, as described in the [previous section](/get_started/running/binary#common).

## Example setup

:::note
The following examples assume you're running Prometheus/Grafana on the same machine as Commit-Boost. In general you should avoid this setup, and instead run them on a separate machine. cAdvisor should run in the same machine as the containers you want to monitor.
:::


### cAdvisor
[cAdvisor](https://github.com/google/cadvisor) is a tool for collecting and reporting resource usage and performance characteristics of running containers.

```yml title="cb.docker-compose.yml"
cb_cadvisor:
    image: gcr.io/cadvisor/cadvisor
    container_name: cb_cadvisor
    ports:
    - 127.0.0.1:8080:8080
    volumes:
    - /var/run/docker.sock:/var/run/docker.sock:ro
    - /sys:/sys:ro
    - /var/lib/docker/:/var/lib/docker:ro
```

### Prometheus

For more information on how to setup Prometheus, see the [Prometheus documentation](https://prometheus.io/docs/prometheus/latest/getting_started/).

```yml title="cb.docker-compose.yml"
cb_prometheus:
    image: prom/prometheus:v3.0.0
    container_name: cb_prometheus
    ports:
    - 127.0.0.1:9090:9090
    volumes:
    - ./prometheus.yml:/etc/prometheus/prometheus.yml
    - prometheus-data:/prometheus
```

```yml title="prometheus.yml"
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "commit-boost"
    static_configs:
      - targets: ["cb_da_commit:10000", "cb_pbs:10001", "cb_signer:10002", "cb_cadvisor:8080"]
```

### Grafana
For more information on how to setup Grafana, see the [Grafana documentation](https://grafana.com/docs/grafana/latest/getting-started/).

```yml title="cb.docker-compose.yml"
cb_grafana:
    image: grafana/grafana:11.3.1
    container_name: cb_grafana
    ports:
    - 127.0.0.1:3000:3000
    volumes:
    - ./grafana/datasources:/etc/grafana/provisioning/datasources
    - grafana-data:/var/lib/grafana
```

```yml title="datasources.yml"
apiVersion: 1

datasources:
  - name: prometheus
    type: prometheus
    uid: prometheus
    access: proxy
    orgId: 1
    url: http://cb_prometheus:9090
    isDefault: true
    editable: true
```

Once Grafana is running, you can [import](https://grafana.com/docs/grafana/latest/dashboards/build-dashboards/import-dashboards/) the Commit-Boost dashboards from [here](https://github.com/Commit-Boost/commit-boost-client/tree/main/provisioning/grafana), making sure to select the correct `Prometheus` datasource.


