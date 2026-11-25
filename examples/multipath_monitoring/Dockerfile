FROM rust:1.80-slim as builder

WORKDIR /usr/src/ifa
COPY . .

# Build only ifa-cli in release mode for lightweight production runtime
RUN cargo build --release -p ifa-cli

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/ifa/target/release/ifa /usr/local/bin/ifa

# Telemetry server HTTP & WebSocket port
EXPOSE 9100

ENTRYPOINT ["ifa", "net", "session", "telemetry-serve"]
CMD ["--addr", "0.0.0.0:9100", "--node-id", "ifa-gateway-prod-01", "--ws-interval-ms", "500"]
