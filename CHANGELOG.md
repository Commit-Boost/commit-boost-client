# Release Changelog

### v0.9.6
- Fix pagination issue with SSV keys
- Bump rust toolchain to 1.91
- Bump lighthouse dependencies to v8.1.3

### v0.9.7-rc1
- Test new release process (duplicate of v0.9.6)

### v0.9.8
- Add new log that prints winning relay's id and bid amount

### v0.10.0-rc1
**Breaking changes**
- Unified binary: CLI, PBS, and Signer combined into a single `commit-boost` binary with subcommands (#425). This change changes the CLI, notably the `init` command is now invoked as `commit-boost init --config <config_name>`.
- New unified Docker image `commit-boost` (#464). Dedicated `commit-boost-pbs` and `commit-boost-signer` images continue to ship for backward compatibility.
- Signer service API updated, see signer-api.yml

**Security**
- Sigma Prime audit fixes for the signer service (#438)

**Features**
- SSV-node API support (#415)
- Custom chain ID support (#429)
- PBS reloads config on file changes without restart (#409)
- New log line for `get_header` auction winner (#443)

**Fixes**
- CLI double-parse bug (#428)
- Test updates for SSV API rename and PbsState signature change (#427)

**Infrastructure**
- New release process based on `.releases/` YAML model (#462 and #464)
