# Build
# Keep the builder on the same Debian/glibc generation as the runtime image.
# A floating Rust tag moved to a newer base and produced binaries
# requiring GLIBC_2.38, which cannot start in bookworm-slim (GLIBC_2.36).
FROM rust:1.98-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p llm-firewall

# Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN addgroup --system --gid 65532 soupwall \
    && adduser --system --uid 65532 --gid 65532 --no-create-home soupwall
WORKDIR /app
COPY --from=build /src/target/release/llm-firewall /usr/local/bin/soup-wall-gateway
COPY LICENSE NOTICE /usr/share/doc/soup-wall/
# Preserve the config layout the app expects: firewall.yaml resolves
# policy_file "policies/default.yaml" relative to WORKDIR (/app).
COPY firewall.yaml ./
COPY policies/ ./policies/
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["curl", "--fail", "--silent", "http://127.0.0.1:8080/healthz"]
ENTRYPOINT ["soup-wall-gateway"]
