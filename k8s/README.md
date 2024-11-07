# Commit boost on k8s

Currently, only the PBS module is supported and it can be used as a
drop-in replacement to mev-boost. To quickly install it, from the
chart directory, edit the `values.yaml` configuration file to your
liking, then:

```
helm install commit-boost . -f myvalues.yaml
```

By default the PBS service should be available on port `18550`, you
can then point your beacons to it.
