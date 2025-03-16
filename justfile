# Makes sure the nightly-2025-02-26 toolchain is installed
toolchain := "nightly-2025-02-26"

fmt:
  rustup toolchain install {{toolchain}} > /dev/null 2>&1 && \
  cargo +{{toolchain}} fmt

fmt-check:
  rustup toolchain install {{toolchain}} > /dev/null 2>&1 && \
  cargo +{{toolchain}} fmt --check

clippy:
  cargo clippy --all-features --no-deps -- -D warnings


test:
    cargo test --all-features