---
description: Deploy Commit-Boost on Kubernetes
---

# Kubernetes

Commit-Boost can be deployed on Kubernetes using the [Helm chart](https://helm.sh/) available in the repository's `provisioning/k8s/commit-boost/` directory.

## Scope limitation

:::warning
The current Helm chart supports only the **PBS Service**. It does **not** support the Signer Service or custom commit modules. If you need Signer or module support, please use the [Docker](./docker.md) or [Binary](./binary.md) deployment methods instead.
:::

## Prerequisites

- A Kubernetes cluster
- [Helm](https://helm.sh/docs/intro/install/) installed (v3+)

## Installation

1. Clone the repository or navigate to the chart directory:

```bash
git clone https://github.com/Commit-Boost/commit-boost-client.git
cd commit-boost-client/provisioning/k8s/commit-boost
```

2. Edit the `values.yaml` file to configure the PBS service according to your needs. The key configuration options are described in the [Values table](#values) below.

3. Install the chart:

```bash
helm install commit-boost . -f values.yaml
```

This will deploy the Commit-Boost PBS service. By default, the PBS service is available on port `18550`. Point your beacon nodes and validator clients to this port.

## Values

The PBS service is configured through the `values.yaml` file. The chart exposes the following key configuration options under the `commitBoost.pbs` section:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `commitBoost.pbs.enable` | bool | `true` | Enable the PBS service |
| `commitBoost.pbs.image.repository` | string | `ghcr.io/commit-boost/commit-boost` | PBS container image repository |
| `commitBoost.pbs.image.tag` | string | `v0.4.0` | PBS container image tag |
| `commitBoost.pbs.config.chain` | string | `Holesky` | Ethereum network (e.g. Holesky, Hoodi) |
| `commitBoost.pbs.config.pbs.port` | int | `18550` | PBS service port |
| `commitBoost.pbs.config.relays` | list | `[]` | List of relays to connect to |
| `commitBoost.pbs.config.mux` | list | `[]` | Multiplexer configuration for validator-specific relay routing |
| `commitBoost.pbs.config.metrics.server_port` | int | `10000` | Metrics server port |
| `replicaCount` | int | `1` | Number of PBS pod replicas |
| `service.type` | string | `ClusterIP` | Kubernetes service type |
| `service.pbs_port` | int | `18550` | Service port for PBS |
| `resources` | object | `{}` | Pod resource requests and limits |
| `autoscaling.enabled` | bool | `false` | Enable horizontal pod autoscaling |

For the full list of available values and their descriptions, see the [README.md](https://github.com/Commit-Boost/commit-boost-client/blob/main/provisioning/k8s/commit-boost/README.md) in the chart directory.

## Upgrading

To upgrade an existing release after modifying `values.yaml`:

```bash
helm upgrade commit-boost . -f values.yaml
```

## Uninstalling

To uninstall the release:

```bash
helm uninstall commit-boost
```
