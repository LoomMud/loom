# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

FROM rust:1.98.1-bookworm AS chef
WORKDIR /app
RUN cargo install --locked cargo-chef --version 0.1.72

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked -p loom-cli && install -Dm755 target/release/loom-cli /out/loom

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libmimalloc2 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home --home-dir /srv/loom loom
WORKDIR /srv/loom
ENV LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libmimalloc.so.2
COPY --from=builder /out/loom /usr/local/bin/loom
EXPOSE 4000/tcp
USER loom
ENTRYPOINT ["/usr/local/bin/loom"]
CMD ["serve", "--mudlib", "/mudlib"]
