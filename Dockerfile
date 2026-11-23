# The Rust version is NOT pinned by this tag — it comes from
# rust-toolchain.toml, which rustup in this image reads. The tag only
# bootstraps rustup, so it deliberately floats on the latest 1.x.
FROM rust:1-slim-bookworm AS builder
WORKDIR /workspace

# Install the pinned toolchain before copying the source, so the download
# is cached in its own layer and is not invalidated by code changes.
COPY rust-toolchain.toml .
RUN rustup toolchain install

COPY . .

RUN cargo build --locked --release

# Runtime stage
FROM debian:bookworm-slim

# Run as a non-root user so a compromised container cannot write host-mapped
# paths as root, and so wallet / cookie files created at runtime are not owned
# by uid 0.
RUN groupadd --system --gid 1000 bitnames \
    && useradd --system --uid 1000 --gid bitnames --home-dir /var/lib/bitnames \
       --shell /usr/sbin/nologin bitnames \
    && mkdir -p /var/lib/bitnames \
    && chown -R bitnames:bitnames /var/lib/bitnames

COPY --from=builder /workspace/target/release/plain_bitnames_app /bin/plain_bitnames_app
COPY --from=builder /workspace/target/release/plain_bitnames_app_cli /bin/plain_bitnames_app_cli

# Verify we placed the binary in the right place,
# and that it's executable.
RUN plain_bitnames_app --help
RUN plain_bitnames_app_cli --help

USER bitnames
WORKDIR /var/lib/bitnames
ENV HOME=/var/lib/bitnames

ENTRYPOINT ["plain_bitnames_app"]
