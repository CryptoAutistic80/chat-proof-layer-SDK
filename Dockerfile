# syntax=docker/dockerfile:1.7

FROM rust:1.86-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY packages/core-rust/Cargo.toml packages/core-rust/Cargo.toml
COPY packages/cli/Cargo.toml packages/cli/Cargo.toml
COPY packages/proof-service/Cargo.toml packages/proof-service/Cargo.toml
COPY packages/core-rust/src packages/core-rust/src
COPY packages/cli/src packages/cli/src
COPY packages/proof-service/src packages/proof-service/src

RUN cargo build --release -p proof-service

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY --from=builder /app/target/release/proof-service /usr/local/bin/proof-service

EXPOSE 8080
ENV PROOF_SERVICE_ADDR=0.0.0.0:8080
ENV PROOF_SERVICE_STORAGE_DIR=/app/storage

CMD ["proof-service"]
