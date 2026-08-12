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

COPY --from=builder /workspace/target/release/plain_bitnames_app /bin/plain_bitnames_app
COPY --from=builder /workspace/target/release/plain_bitnames_app_cli /bin/plain_bitnames_app_cli

# Verify we placed the binaries in the right place, 
# and that it's executable.
RUN plain_bitnames_app --help
RUN plain_bitnames_app_cli --help

ENTRYPOINT ["plain_bitnames_app"]

