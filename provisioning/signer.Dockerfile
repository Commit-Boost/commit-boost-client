FROM debian:bookworm-slim
ARG BINARIES_PATH TARGETOS TARGETARCH
COPY ${BINARIES_PATH}/commit-boost-signer-${TARGETOS}-${TARGETARCH} /usr/local/bin/commit-boost-signer
RUN apt-get update && apt-get install -y \
  openssl \
  ca-certificates \
  libssl3 \
  libssl-dev \
  curl && \
  # Cleanup
  apt-get clean autoclean && \
  rm -rf /var/lib/apt/lists/*

# Create a non-root user to run the application
RUN groupadd -g 10001 commitboost && \
  useradd -u 10001 -g commitboost -s /sbin/nologin commitboost
USER commitboost

ENTRYPOINT ["/usr/local/bin/commit-boost-signer"]