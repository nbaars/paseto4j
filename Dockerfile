FROM eclipse-temurin:21-jdk-jammy

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libsodium23 \
    libsodium-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace