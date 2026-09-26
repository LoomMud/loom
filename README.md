# Loom

[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

Loom is Oberfield's LPMud-style MUD driver, written in Rust. It hosts **Weft**, a sandboxed scripting
language, and runs the **Warp** mudlib. The authoritative design is Loom spec v2 (Paperclip OBI-4, `design`).

## Layout (spec §10, Phase 0 subset)

| Crate | Purpose | Owner |
|---|---|---|
| `crates/loom-syntax` | Weft lexer, parser, AST, diagnostics | Gimli |
| `crates/loom-vm` | Values, object table, program registry, evaluator (tree-walker in Phase 0, bytecode VM in Phase 1) | Gimli |
| `crates/loom-net` | Telnet (later GMCP, WebSocket), sessions | Legolas |
| `crates/loom-cli` | `loom serve` and other commands | Legolas |

## Develop

```sh
cargo run -p loom-cli     # prints the version (Phase 0 bootstrap)
scripts/ci-local.sh       # fmt, clippy, test, cargo-deny, DCO
```

## Docker dev environment

```sh
docker compose up --build
# with Prometheus + Grafana:
docker compose --profile obs up --build
```

- Loom serves telnet on `localhost:4000` and reads the mounted mudlib from `./mudlib`.
- Postgres is available at `localhost:5432` with `loom/loom` credentials.
- With `obs` profile: Prometheus (`localhost:9090`) and Grafana (`localhost:3000`, anonymous viewer) start with a starter dashboard.

## Remotes

- Canonical remote: `https://github.com/LoomMud/loom` (public).
- Interim mirror (read-only until Phase 1 completes):
  `/paperclip/instances/default/shared/oberfield/loom.git`.

## Licence

Copyright 2026 Oberfield. Licensed under the [GNU Affero General Public License v3.0 only](LICENSE)
(`AGPL-3.0-only`). See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution policy.
