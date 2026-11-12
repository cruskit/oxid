# syntax=docker/dockerfile:1

# Build stage. The same Debian release is used for both stages so the binary
# links against the glibc it will run with.
FROM rust:1-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Cache mounts keep the registry and build artefacts between builds, so only
# changed crates are recompiled.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin oxid \
    && cp target/release/oxid /usr/local/bin/oxid

FROM debian:trixie-slim
# Root certificates, for outbound HTTPS to the ConnectID registry.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 oxid
COPY --from=build /usr/local/bin/oxid /usr/local/bin/oxid
USER oxid
EXPOSE 9443 9444
ENTRYPOINT ["/usr/local/bin/oxid"]
CMD ["serve", "--config", "/etc/oxid/oxid.toml"]
