# `loom-lsp`: the Weft language server

OBI-168 (Loom Phase 2, P2-B1). Owner: Gimli.

`loom-lsp` implements four LSP features over the existing compiler
front-end (`loom-syntax`, `loom-compiler`):

- **Diagnostics** (`textDocument/publishDiagnostics`): every `W####` parse,
  resolver/type-checker and lint diagnostic (spec \u00a75.9), with its span,
  severity and hint.
- **Hover** (`textDocument/hover`): the checker's inferred type at the
  cursor -- a local, a program variable, a call's return type, an efun's
  signature, or (on an `inherit`/`import` path) the target program.
- **Go to definition** (`textDocument/definition`): `inherit`/`import`
  paths jump to the target file; calls and variable references jump to
  the declaring program's `fn`/`var`/`const`.
- **Completion** (`textDocument/completion`): every efun, every known
  driver apply (`create`, `heartbeat`, `valid_read`, ...), and every
  function/variable/const the current program inherits (its whole
  `/std` API, generalised to whatever it actually inherits).

It runs two ways:

- **stdio** (`loom-lsp --stdio`): one process per editor session, the
  usual LSP contract. This is what VS Code and neovim use.
- **WebSocket** (`loom-lsp --ws HOST:PORT`): one LSP session per
  connection, each LSP message as one WS text frame (no
  `Content-Length` framing -- the WS frame boundary is the message
  boundary). This is the transport the web IDE (P2-B2) uses; the
  protocol core (`src/server.rs`) is identical either way, so stdio and
  WS get exactly the same behaviour and exactly the same test coverage
  (`tests/lsp_integration.rs` drives the core directly over an in-memory
  `lsp_server::Connection` pair, not a real socket).

## Scope note: per-request recompilation

Every request recompiles the file it names from scratch, against the
workspace's current buffers (`src/workspace.rs`'s `OverlayLoader`: open,
unsaved text wins over what's on disk). There is no cross-file
dependent-invalidation graph yet -- editing `/std/room` does not re-push
diagnostics for every open file that inherits it until *that* file is
itself re-requested. `loom_compiler::mudlib::Session::invalidate`'s own
doc comment flags this exact gap for a future incremental pass; it was out
of scope for the M-size estimate here. Re-running on every edit (the
client debounces this the same as any LSP server) keeps the file the
builder is actually looking at accurate, which is what the acceptance
criterion asks for.

## Security (spec P2-S1 threat model, `docs/threat-model-phase2.md` §6.3)

`loom-lsp` implements the mitigations the threat model assigns to OBI-168:

- **M-LSP-2 (never reads the filesystem directly).** All source text goes
  through a `FileProvider` trait (`src/file_provider.rs`): a
  `LocalDirectoryProvider` for `--stdio`/`--root` (a trusted local
  checkout -- "directory impl for stdio/local"), or a `GatedProvider`
  wrapping a `ReadAuthorizer` for the per-session/web-IDE case. A denied
  read looks **exactly** like a missing file (same error string, same
  `W0114` diagnostic, no distinct "exists but denied" signal), and
  `textDocument/definition` returns **no** `Location` at all -- not a
  zero-range one -- for a target it cannot read. `loom-lsp` has no
  session/uid/Postgres concept of its own (by design: D-TM5 rejects "an
  HTTP-side ACL mirroring the master"), so the real `valid_read`-backed
  `ReadAuthorizer` is OBI-180's to wire in; this crate only defines and
  tests the policy shape (`tests/lsp_integration.rs`'s
  `m_lsp_2_*` test is literally the threat model's own T1/T4 example).
- **M-LSP-3 (`loom-vfs://` only in session mode).** `Workspace::new_vfs`
  accepts and emits only `loom-vfs:///path` URIs; a `file://` URI is
  rejected outright (`program_path` returns `None`), so a host path can
  never reach a response and never be accepted as one. `--stdio`/`--root`
  (`Workspace::new`) keeps `file://`, which is correct and expected for a
  local editor on a trusted checkout -- the threat model's trust boundary
  is "a browser reaching the service", not a local editor. A client's
  `initialize` `rootUri`/`workspaceFolders` is honoured **only** when the
  workspace is already in `Local` mode (`run_with_workspace` checks
  `ws.is_local()` first); a `Vfs`-mode session ignores it entirely, since
  honouring it there would silently replace the gated workspace with an
  ungated one (CTO review of OBI-168, F1 -- `tests/lsp_integration.rs`'s
  `f1_*` test sends a real `rootUri` to a `Vfs` session and checks both
  that it's still gated and that it hasn't otherwise broken).
- **M-LSP-4 (limits, deadline, cancellation, fuzzing).** Documents over 1
  MiB and a 65th open document are refused (with a `publishDiagnostics`
  explaining why, not a silent drop). Requests run on `MAX_CONCURRENT_REQUESTS`
  (4) **persistent** worker threads pulling from a bounded job queue (16
  pending); a request beyond that queue is refused immediately with no
  thread spawned at all. A worker only picks up its next job once the
  current one *actually* finishes -- a 5 s client-facing deadline is
  enforced by a separate, cheap timer thread per in-flight job that
  replies to the client without touching the worker, so a slow compile
  can't make the pool grow or free a slot early (CTO review of OBI-168,
  F3). `$/cancelRequest` is honoured the same way -- whichever of
  "finished" / "timed out" / "cancelled" happens first wins, and the
  other two become no-ops (the in-flight compile itself cannot be
  force-stopped; see `server.rs`'s module docs for why). The WS bridge
  additionally caps messages at 4 MiB / frames at 1 MiB, sessions at 32
  concurrent, and closes an idle (60 s) session. `crates/loom-lsp/fuzz`'s
  `lsp_requests` target fuzzes `hover`/`definition`/`completion` over
  arbitrary `(offset, source)` pairs (`scripts/fuzz-smoke.sh lsp`, wired
  into the same PR-triggered smoke job as the parser/bytecode fuzz
  targets -- there is no separate scheduled *nightly* workflow in this
  repo yet for any fuzz target, parser/bytecode included, so this matches
  the existing pattern rather than inventing a new one).
- **M-LSP-5 (no inherited secrets).** `env_guard::maybe_reexec` (called
  first thing in `main`) re-execs the process with every environment
  variable dropped except a small allowlist (`PATH`, `HOME`, `LANG`,
  `LC_ALL`, `TMPDIR`, `RUST_LOG`). It cannot mutate the current process's
  environment in place -- `std::env::remove_var` is `unsafe fn`, and this
  crate (like every crate except `loom-vm`) carries `unsafe_code =
  "deny"` -- so it re-execs itself via the safe `std::process::Command`
  builder instead, which configures the *child's* environment at spawn
  time without needing `unsafe` at all.

## Running it

### VS Code

Point any generic LSP client extension (e.g. "vscode-languageclient" via a
tiny wrapper extension, or a community "Generic LSP Client") at:

```json
{
  "command": "/path/to/loom-lsp",
  "args": ["--stdio"]
}
```

VS Code sends `rootUri` from the open folder automatically, so
`loom-lsp` picks up the warp checkout without `--root`.

### neovim (built-in LSP client, 0.8+)

```lua
vim.api.nvim_create_autocmd("FileType", {
  pattern = "weft", -- set up a filetype for `.wf` files, e.g. via a ftdetect autocmd on *.wf
  callback = function(args)
    vim.lsp.start({
      name = "loom-lsp",
      cmd = { "/path/to/loom-lsp", "--stdio" },
      root_dir = vim.fs.root(args.buf, { "std", "secure", "domains" }), -- any warp-shaped checkout
    })
  end,
})
```

### Local smoke test against a warp checkout

```sh
cargo build -p loom-lsp
./target/debug/loom-lsp --stdio --root /path/to/warp
```

`--root` is only needed when the client doesn't send a `rootUri`/
`workspaceFolders` (or for the WS transport, which has no such client
concept at the socket level -- today every WS connection shares the one
`--root` the server was started with; a multi-tenant bridge would need a
`?root=` query param or an initial handshake message, not yet built).

### WebSocket (web IDE integration, P2-B2)

```sh
./target/debug/loom-lsp --ws 127.0.0.1:7777 --root /path/to/warp
```

**This is a local/dev bridge, not the production path** (CTO review of
OBI-168, F2): it has no authentication, and today it always runs `Local`
mode (every file under `--root` readable), so `serve` refuses to bind
anything but a loopback address. Real staff exposure goes through
`loom-http` with a D-TM4 single-use ticket in front of a `Vfs`-mode
workspace (OBI-180's job, via [`run_with_workspace`]). If you have
deliberately put real auth/gating in front of this process some other
way and need it reachable off-box anyway, pass
`--ws-insecure-public` to skip the bind check -- the server logs a loud
warning when you do.

Each new WS connection gets an independent LSP session (its own
`initialize` handshake, its own open-buffer overlay), up to 32 concurrent
sessions (spec M-LSP-4); a session idle for 60 s is closed. The wire
format is plain JSON-RPC 2.0 objects, one per WS text frame -- exactly the
`DidOpenTextDocumentParams`/`HoverParams`/etc. shapes `lsp-types` defines,
with no transport envelope beyond the WS frame itself. Frames are capped
at 1 MiB and whole messages at 4 MiB (spec M-LSP-4).

## Testing

- `cargo test -p loom-lsp` -- unit tests per module (`position`,
  `workspace`, `hover`, `definition`, `completion`) plus
  `tests/lsp_integration.rs`, which drives the whole protocol core
  (`initialize` → `didOpen` → each of the four features) against the
  fixture tree in `tests/fixtures/warp/` (same convention as
  `loom-cli/tests/fixtures/warp-phase0`: a small, self-contained mudlib
  shaped like warp, not a copy of the real repo).
- `cargo clippy -p loom-lsp --all-targets`.
