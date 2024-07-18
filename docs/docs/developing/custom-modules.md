---
sidebar_position: 1
---
# Custom Modules
Commit-Boost aims to provide an open platform for developers to create and distribute commitment protocols sidecars. 

There are three ways to leverage Commit-Boost modularity:
1. Commit Modules, which request signatures from the proposer, e.g. for preconfirmations
2. PBS Modules, which tweak the default PBS Module with additional logic, e.g. verifying additional constraints in `get_header`
3. PBS Events, which trigger based on the different events of the PBS lifecycle and can be used e.g. for monitoring and reporting

You find can an example of 1. [here](https://github.com/Commit-Boost/commit-boost-client/tree/main/examples/da_commit) which is detailed in the next section, examples and docs for 2. and 3. are stil WIP.
