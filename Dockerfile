# Multi-stage build of the zero-dependency Onced gateway.
# Build stage: compile the static-ish std-only binary.
FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p onced-gateway

# Runtime stage: distroless (no shell, no package manager) — tiny + hardened.
FROM gcr.io/distroless/cc-debian12
COPY --from=build /src/target/release/onced-gateway /onced-gateway
# Listen on all interfaces inside the container; override via env at run time.
ENV ONCED_LISTEN=0.0.0.0:8080 \
    ONCED_BACKEND=127.0.0.1:9000 \
    ONCED_WAL=/data/onced
EXPOSE 8080
ENTRYPOINT ["/onced-gateway"]
