FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 
COPY --from=planner /app/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release --bin commit-boost-signer


FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y \
  openssl \
  ca-certificates \
  libssl3 \
  libssl-dev \
  && apt-get clean autoclean \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/commit-boost-signer /usr/local/bin
ENTRYPOINT ["/usr/local/bin/commit-boost-signer"]



