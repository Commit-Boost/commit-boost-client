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
If the section is missing, metrics collection will be disabled. If you generated the `docker-compose.yml` file with `commit-boost init`, metrics ports will be automatically configured, and a sample `target.json` file will be created. If you're running the binaries directly, you will need to set the correct environment variables, as described in the [previous section](/get_started/running/binary#common).

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



## Bid stream

For a relay with `get_header = "stream"`, Commit-Boost sends the relay's normal HTTP get_header alongside the stream, timing games included, and the two are separate candidates in the auction; the `auction winner` log line names the winning `transport`. Every series below is labelled by `relay_id`, and the stream-only series also by `endpoint`. The stream's own outcome and time-to-first-bid share the two general relay series under `endpoint="get_header_stream"`; the HTTP request keeps `endpoint="get_header"`.

| Question | Series |
|---|---|
| Is the stream serving bids? | `cb_pbs_relay_status_code_total{endpoint="get_header_stream"}`: `200` a bid was delivered, `204` no bid (the relay answered the handshake `204`, or sent no bid before the deadline), `555` the bid window ran out during the handshake, `556` a transport error (connect failed, stream broke before a bid, or the handshake was answered with a `2xx` other than `204`), any other code the relay's own refusal of the upgrade |
| How fast does the first bid arrive? | `cb_pbs_relay_latency{endpoint="get_header_stream"}` |
| Is the stream failing? | `cb_pbs_relay_stream_fallback_total{endpoint="get_header_stream"}`: streams that failed while the relay's HTTP request ran alongside: a handshake that could not connect, timed out or was refused, a stream that broke before a bid, or a window in which every held bid failed decoding or validation. A `204` is no bid, not a failure. It counts every failed stream, whether or not the HTTP request returned a bid; the HTTP results are under `endpoint="get_header"`. One at startup is the registration race; for a steady rate, the status series above gives the reason |
| Is the handshake slow? | `cb_pbs_relay_stream_connect_latency` |
| Is it actually streaming? | `cb_pbs_relay_stream_updates`: frames accepted per window, which is every frame whose message type and fork byte can be read; their bids are decoded and validated only when the window closes. A healthy relay sends several; windows that carry at most one update mean the stream connects but does not stream |
| Are the frames usable? | `cb_pbs_relay_stream_invalid_frames_total`: frames dropped on arrival because their message type or fork byte cannot be read, absent while zero. A bid that fails decoding or validation is not counted here |

When the window closes, the stream serves the latest bid that passes decoding and validation, from the newest 8 it holds. A failing bid newer than the one served is not counted as a failure; the error is in the logs. A window in which every held bid fails counts as `200` on the status series, the same as an invalid bid over HTTP, and as one failed stream. A request the beacon node abandons mid-window records no outcome at all.
