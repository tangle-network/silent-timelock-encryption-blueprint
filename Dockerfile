FROM rustlang/rust:nightly AS chef

RUN cargo install cargo-chef
WORKDIR /app

COPY Cargo.toml Cargo.lock ./

RUN cargo chef prepare --recipe-path recipe.json
RUN cargo chef cook --recipe-path recipe.json

COPY . .

RUN cargo build --release

FROM debian:bookworm-slim AS runtime
WORKDIR /app
COPY --from=chef /app/target/release/silent-timelock-encryption-blueprint /usr/local/bin

LABEL org.opencontainers.image.authors="Drew Stone <drewstone329@gmail.com>"
LABEL org.opencontainers.image.description="A Tangle Blueprint for silent timelock encryption systems."
LABEL org.opencontainers.image.source="https://github.com/tangle-network/silent-timelock-encryption-blueprint"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

ENV RUST_LOG="gadget=info"
ENV BIND_ADDR="0.0.0.0"
ENV BIND_PORT=9632
ENV BLUEPRINT_ID=0
ENV SERVICE_ID=0

ENTRYPOINT ["/usr/local/bin/silent-timelock-encryption-blueprint", "run"]