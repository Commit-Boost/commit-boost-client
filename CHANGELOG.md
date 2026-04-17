### v0.9.4-rc1
- Unifies the `pbs`, `signer`, and `cli` binaries into one: `commit-boost`. This change changes the CLI, notably the `init` command is now invoked as `commit-boost init --config <config_name>`.
- Includes new quality of life testing improvements in the Justfile: unit test coverage tooling, local Kurtosis testnet, and microbenchmark diffing. 
- Robustifies the release process to ensure no compromised maintainer can unilaterally cut a release. Additionally all binaries are now signed during CI and can easily be verified before use.
