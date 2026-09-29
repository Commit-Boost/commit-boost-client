---
description: Setup metrics collection
---

# Metrics

Commit-Boost can be configured to collect metrics from the different services and expose them to be scraped from Prometheus.

For a full reference of every metric the PBS and Signer services expose, see the [Metrics catalog](./metrics-catalog.md).

Make sure to add the `[metrics]` section to your config file (fields and the `start_port` port ladder: [Configuration > Metrics](../configuration.md#metrics)):

```toml
[metrics]
enabled = true
```
If you generated the `cb.docker-compose.yml` file with `commit-boost init`, metrics ports will be automatically configured. If you're running the binaries directly, you will need to set the correct environment variables, as described in the [previous section](./binary.md#common).

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

For more information on how to set up Prometheus, see the [Prometheus documentation](https://prometheus.io/docs/prometheus/latest/getting_started/).

```yml title="cb.docker-compose.yml"
cb_prometheus:
    image: prom/prometheus:v3.0.0
    container_name: cb_prometheus
    ports:
    - 127.0.0.1:9090:9090
    volumes:
    - ./prometheus.yml:/etc/prometheus/prometheus.yml
    - prometheus-data:/prometheus
    networks:
    - default
    - signer_network
```

The generated compose file attaches the signer and commit module containers only to `signer_network`, so Prometheus must join that network too or the `cb_signer` and `cb_da_commit` scrape targets below will be unreachable.

```yml title="prometheus.yml"
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "commit-boost"
    static_configs:
      - targets: ["cb_da_commit:10000", "cb_pbs:10001", "cb_signer:10002", "cb_cadvisor:8080"]
```

### Grafana
For more information on how to set up Grafana, see the [Grafana documentation](https://grafana.com/docs/grafana/latest/fundamentals/getting-started/).

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

The mounted datasource provisioning file points Grafana at the Prometheus service:

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

### Named volumes

The Prometheus and Grafana services above use the named volumes `prometheus-data` and `grafana-data`. The generated compose file has no top-level `volumes:` block, and Docker Compose refuses to start the whole project if a service references an undeclared volume, so declare both when merging the snippets:

```yml title="cb.docker-compose.yml"
volumes:
  prometheus-data:
  grafana-data:
```

Once Grafana is running, you can [import](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/import-dashboards/) the Commit-Boost dashboards from [here](https://github.com/Commit-Boost/commit-boost-client/tree/main/provisioning/grafana), making sure to select the correct `Prometheus` datasource.

## Bid stream

For a relay with `get_header = "stream"` (see [Configuration > Bid streaming](../configuration.md#bid-streaming)), every series below is labelled by `relay_id`. The stream's outcome and time-to-first-bid share the two general relay series under `endpoint="get_header_stream"`, and the HTTP fallback keeps `endpoint="get_header"`.

| Question | Series |
|---|---|
| Is the stream serving bids? | `cb_pbs_relay_status_code_total{endpoint="get_header_stream"}`: `200` a bid was delivered, `204` connected but no bid before the deadline, `555` the bid window ran out during the handshake, `556` a transport error (connect failed, the stream broke mid-window, or the handshake was answered with a success code instead of the upgrade), any other code the relay's own refusal of the upgrade |
| How fast does the first bid arrive? | `cb_pbs_relay_latency{endpoint="get_header_stream"}` |
| Is it falling back to HTTP? | `cb_pbs_relay_stream_fallback_total`: handshake failures that had bid window left to retry over HTTP. A steady rate means the relay is refusing or dropping the upgrade. The fallback's own results are under `endpoint="get_header"` |
| Is the handshake slow? | `cb_pbs_relay_stream_connect_latency` |
| Is it actually streaming? | `cb_pbs_relay_stream_updates`: bid updates received per window. A healthy relay sends several; windows that carry at most one update mean the stream connects but does not stream |
| Are the frames usable? | `cb_pbs_relay_stream_invalid_frames_total`: frames that could not be parsed as a bid, absent while zero |
