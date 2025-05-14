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

docker-build-pbs:
  docker build -t commitboost_pbs_default . -f ./provisioning/pbs.Dockerfile

docker-build-signer:
  docker build -t commitboost_signer . -f ./provisioning/signer.Dockerfile

docker-build-test-modules:
  docker build -t test_da_commit . -f examples/da_commit/Dockerfile
  docker build -t test_builder_log . -f examples/builder_log/Dockerfile
  docker build -t test_status_api . -f examples/status_api/Dockerfile

test:
    cargo test --all-features