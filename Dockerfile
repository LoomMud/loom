# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only

FROM rust:1.98.1-bookworm AS chef
WORKDIR /app
RUN cargo install --locked cargo-chef --version 0.1.72

FROM node:22-bookworm-slim AS web-client-builder
WORKDIR /app/web-client
COPY web-client/package.json web-client/package-lock.json ./
RUN npm ci
COPY web-client/. .
RUN npm run build

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# loom-persist uses sqlx query! macros; compile against the committed .sqlx cache.
ENV SQLX_OFFLINE=true
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked -p loom-cli && install -Dm755 target/release/loom-cli /out/loom

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libmimalloc2.0 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home --home-dir /srv/loom loom
WORKDIR /srv/loom
ENV LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libmimalloc.so.2
# OBI-158: same-origin web client, served by loom-http's router fallback
# (see LOOM_WEB_ROOT below) -- it connects to /ws on this same origin, so
# it has to ship in lockstep with the protocol, not as a second artifact.
ENV LOOM_WEB_ROOT=/usr/share/loom/web
COPY --from=web-client-builder /app/web-client/index.html /usr/share/loom/web/index.html
COPY --from=web-client-builder /app/web-client/dist /usr/share/loom/web/dist
COPY --from=builder /out/loom /usr/local/bin/loom
EXPOSE 4000/tcp
USER loom
ENTRYPOINT ["/usr/local/bin/loom"]
CMD ["serve", "--mudlib", "/mudlib"]
