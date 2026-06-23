# ── Build Stage ──
FROM rust:1.76-slim AS builder
WORKDIR /build
COPY Cargo.toml .
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -f target/release/deps/honeycloud_backend*
COPY src ./src
RUN cargo build --release

# ── Runtime Stage ──
FROM debian:bookworm-slim AS runtime
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/honeycloud-backend app
COPY static ./static

# Expose ports for REST API, static files, and honeypots
EXPOSE 8000 8080 2121 2222 2323 2525 3389

ENTRYPOINT ["./app"]
