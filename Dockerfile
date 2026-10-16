# Build stage
FROM rust:1.93.1-bookworm AS builder

WORKDIR /app

# Keep native TLS dependencies available to Cargo in the Linux deployment build.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libssl-dev pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy manifests and source
COPY Cargo.toml .
COPY Cargo.lock .
COPY src ./src

# Build resilience for flaky networks (common in remote CI/deploy builds)
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    CARGO_NET_RETRY=10 \
    CARGO_HTTP_TIMEOUT=120 \
    SQLX_OFFLINE=true

# Build the application and the gated production dataset utility.
RUN cargo build --release --locked --bin server --bin capstone-dataset

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN groupadd --system sentinel && \
    useradd --system --gid sentinel --create-home --home-dir /home/sentinel sentinel

# Copy the server and gated operational utility from the Linux builder.
COPY --from=builder --chown=sentinel:sentinel /app/target/release/server /app/server
COPY --from=builder --chown=sentinel:sentinel /app/target/release/capstone-dataset /app/capstone-dataset

EXPOSE 5000

ENV RUST_LOG=info

USER sentinel

CMD ["/app/server"]
