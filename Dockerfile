# Commit-Boost PBS — Multi-stage Docker build for interop testing
# Build: docker build -t local/commit-boost-pbs:ws-dev .
FROM rust:1.91-bookworm AS builder
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates/common/Cargo.toml crates/common/
COPY crates/pbs/Cargo.toml crates/pbs/
COPY crates/metrics/Cargo.toml crates/metrics/
COPY crates/signer/Cargo.toml crates/signer/
COPY crates/cli/Cargo.toml crates/cli/
COPY bin/Cargo.toml bin/

# Stub source for dep resolution
RUN mkdir -p crates/common/src crates/pbs/src crates/metrics/src crates/signer/src crates/cli/src bin/src && \
    echo "pub fn dummy() {}" > crates/common/src/lib.rs && \
    echo "pub fn dummy() {}" > crates/pbs/src/lib.rs && \
    echo "pub fn dummy() {}" > crates/metrics/src/lib.rs && \
    echo "pub fn dummy() {}" > crates/signer/src/lib.rs && \
    echo "pub fn dummy() {}" > crates/cli/src/lib.rs && \
    echo "fn main() {}" > bin/src/main.rs

# Fetch dependencies
RUN cargo build --release --bin commit-boost 2>/dev/null || true

# Copy real source
COPY . .

# Patch: set ws-wire path dependency (it won't be inside the container)
RUN mkdir -p /ws-wire/src && \
    echo 'pub mod messages { pub enum WsMessage {} }' > /ws-wire/src/lib.rs && \
    echo '[package]' > /ws-wire/Cargo.toml && \
    echo 'name = "ws-wire"' >> /ws-wire/Cargo.toml && \
    echo 'version = "0.1.0"' >> /ws-wire/Cargo.toml && \
    echo 'edition = "2021"' >> /ws-wire/Cargo.toml && \
    echo '[dependencies]' >> /ws-wire/Cargo.toml && \
    echo 'ethereum_ssz = "0.10"' >> /ws-wire/Cargo.toml && \
    echo 'ethereum_ssz_derive = "0.10"' >> /ws-wire/Cargo.toml && \
    echo 'ssz_types = "0.10"' >> /ws-wire/Cargo.toml || true

# Override ws-wire path dependency — for Docker, we bundle ws-wire inside the image
# The simplest approach: copy ws-wire source into the container
# But since we can't path-dep across filesystem boundaries,
# we adjust Cargo.toml to use a local copy.
COPY ../ws-wire /_ws-wire
RUN sed -i 's|path = "../../../pbs-stack/ws-wire"|path = "/_ws-wire"|g' crates/pbs/Cargo.toml

# Build
RUN cargo build --release --bin commit-boost

# Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/commit-boost /usr/local/bin/commit-boost
EXPOSE 18550
ENTRYPOINT ["/usr/local/bin/commit-boost"]
CMD ["pbs"]
