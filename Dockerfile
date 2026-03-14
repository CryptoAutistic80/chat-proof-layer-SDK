# syntax=docker/dockerfile:1.7

FROM rust:1.88-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml crates/core/Cargo.toml
COPY crates/cli/Cargo.toml crates/cli/Cargo.toml
COPY crates/vault/Cargo.toml crates/vault/Cargo.toml
COPY crates/napi/Cargo.toml crates/napi/Cargo.toml
COPY crates/napi/build.rs crates/napi/build.rs
COPY crates/pyo3/Cargo.toml crates/pyo3/Cargo.toml
COPY crates/pyo3/build.rs crates/pyo3/build.rs
COPY crates/core/src crates/core/src
COPY crates/core/tests crates/core/tests
COPY crates/cli/src crates/cli/src
COPY crates/vault/src crates/vault/src
COPY crates/napi/src crates/napi/src
COPY crates/pyo3/src crates/pyo3/src
COPY fixtures fixtures

RUN cargo build --release -p proof-service

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY --from=builder /app/target/release/proof-service /usr/local/bin/proof-service

EXPOSE 8080
ENV PROOF_SERVICE_ADDR=0.0.0.0:8080
ENV PROOF_SERVICE_STORAGE_DIR=/app/storage

CMD ["proof-service"]
