# CertiWatch: one Rust binary, one non-root runtime container.
#
# Build:  docker build -t certiwatch:local .
# Run:    docker run --rm -p 8080:8080 \
#           -v "$PWD/certiwatch.toml:/config/certiwatch.toml:ro" \
#           -v certiwatch-data:/data certiwatch:local

FROM rust:1.100-bookworm AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 certiwatch \
    && useradd --system --uid 10001 --gid certiwatch \
        --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin certiwatch \
    && mkdir -p /data /config \
    && chown certiwatch:certiwatch /data

COPY --from=build /src/target/release/certiwatch /usr/local/bin/certiwatch

WORKDIR /app

ENV CERTIWATCH_CONFIG=/config/certiwatch.toml \
    CERTIWATCH_DATA_DIR=/data \
    CERTIWATCH_LISTEN=0.0.0.0:8080

USER 10001:10001

EXPOSE 8080
VOLUME ["/data"]
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["certiwatch"]
CMD ["serve"]
