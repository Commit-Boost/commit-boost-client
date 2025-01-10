# Signer Module

## Compile proto files

### Requirements

- `protoc` compiler
- Submodules initialized: `git submodule update --init`

To compile the `.proto` files and generate the Rust bindings, simply run `cargo build`. This will only run if there are changes to the `.proto` files. If you want to force a rebuild, run `cargo clean` first.

Note that this process is not required to run Commit-Boost as the generated files are already included in the repository.
