# Commit-Boost PBS — Docker build for interop testing
# Build context: pbs-stack parent directory
# Build: from docker-compose.test.yml (context: ..)
FROM rust:1.91-bookworm AS builder
WORKDIR /src

# Copy commit-boost source and ws-wire
COPY commit-boost-client/ ./commit-boost-client/
COPY pbs-stack/ws-wire/ ./pbs-stack/ws-wire/

# Build in commit-boost workspace
WORKDIR /src/commit-boost-client
RUN cargo build --release --bin commit-boost

# Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/commit-boost-client/target/release/commit-boost /usr/local/bin/commit-boost
EXPOSE 18550
ENTRYPOINT ["/usr/local/bin/commit-boost"]
CMD ["pbs"]
