# Loom

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

## Remotes

- Canonical remote: `https://github.com/LoomMud/loom` (private).
- Interim mirror (read-only until Phase 1 completes):
  `/paperclip/instances/default/shared/oberfield/loom.git`.
