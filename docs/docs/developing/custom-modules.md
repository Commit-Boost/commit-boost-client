---
sidebar_position: 1
---
# Custom Modules
Commit-Boost aims to provide an open platform for developers to create and distribute commitment protocols sidecars. 

There are three ways to leverage Commit-Boost modularity:
1. Commit Modules, which request signatures from the proposer, e.g. for preconfirmations ([example](https://github.com/Commit-Boost/commit-boost-client/tree/78bdc47bf89082f4d1ea302f9a3f86f609966b28/examples/da_commit))
2. PBS Modules, which tweak the default PBS Module with additional logic, e.g. verifying additional constraints in `get_header` ([example](https://github.com/Commit-Boost/commit-boost-client/tree/78bdc47bf89082f4d1ea302f9a3f86f609966b28/examples/status_api))
3. PBS Events, which trigger based on the different events of the PBS lifecycle and can be used e.g. for monitoring and reporting ([example](https://github.com/Commit-Boost/commit-boost-client/tree/78bdc47bf89082f4d1ea302f9a3f86f609966b28/examples/builder_log))

