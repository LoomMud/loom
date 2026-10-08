# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only

FROM rust:1.98.1-bookworm AS chef
WORKDIR /app
RUN cargo install --locked cargo-chef --version 0.1.72

FROM node:22-bookworm-slim AS web-client-builder
WORKDIR /app/web-client
COPY web-client/package.json web-client/package-lock.json ./
# `--include=dev` is deliberate, not a workaround: `typescript` and the
# lint/test toolchain are devDependencies, and an image build is exactly
# where a production `NODE_ENV`/`omit=dev` default would otherwise produce
# a half-built client that only looks like it worked. Nothing is installed
# globally and this stage's output is a file tree, so dev deps cost layers.
RUN npm ci --include=dev
# The vendor step lives in the repo's `scripts/`, not in `web-client/`, and
# resolves paths from its own location (`../web-client`), so it needs the
# same relative layout here: `/app/scripts` next to `/app/web-client`.
COPY scripts/vendor-monaco.mjs /app/scripts/vendor-monaco.mjs
COPY web-client/. .
# `build` runs `scripts/vendor-monaco.mjs` first: the IDE's Monaco is
# staged out of *this* lockfile's `node_modules`, and the step fails the
# build if the staged tree does not match it (OBI-180 M-IDE-3 -- fetching
# from a CDN at build time would only move the dependency off the audit).
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
# git (B3.5/OBI-192, D-B3.1): the driver's one git client, loom-git, shells
# out to the `git` CLI on a dedicated GitWorker thread rather than linking a
# Git library. No recommends -- loom-git's own tests are the only thing
# that needs more than a bare `git` binary (no gnupg, no editor, no email).
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libmimalloc2.0 git \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home --home-dir /srv/loom loom
WORKDIR /srv/loom
ENV LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libmimalloc.so.2
# OBI-158: same-origin web client, served by loom-http's router fallback
# (see LOOM_WEB_ROOT below) -- it connects to /ws on this same origin, so
# it has to ship in lockstep with the protocol, not as a second artifact.
ENV LOOM_WEB_ROOT=/usr/share/loom/web
# Every document the fallback serves, not just the player page. The
# router's fallback is a plain `ServeDir`, so `/admin` (OBI-165) and `/ide`
# (OBI-180) work in dev and 404 in production unless their html, their
# stylesheets, and the vendored Monaco tree are in the web root. Listed
# explicitly rather than `COPY web-client/.` so an accidental source file
# (node_modules, a stray secret) cannot ride along.
COPY --from=web-client-builder /app/web-client/index.html /usr/share/loom/web/index.html
COPY --from=web-client-builder /app/web-client/loom.css /usr/share/loom/web/loom.css
COPY --from=web-client-builder /app/web-client/admin.html /usr/share/loom/web/admin.html
COPY --from=web-client-builder /app/web-client/ide.html /usr/share/loom/web/ide.html
COPY --from=web-client-builder /app/web-client/ide.css /usr/share/loom/web/ide.css
COPY --from=web-client-builder /app/web-client/dist /usr/share/loom/web/dist
COPY --from=web-client-builder /app/web-client/vendor/monaco /usr/share/loom/web/vendor/monaco
COPY --from=builder /out/loom /usr/local/bin/loom
EXPOSE 4000/tcp
USER loom
ENTRYPOINT ["/usr/local/bin/loom"]
CMD ["serve", "--mudlib", "/mudlib"]
