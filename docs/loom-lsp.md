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

Each new WS connection gets an independent LSP session (its own
`initialize` handshake, its own open-buffer overlay). The wire format is
plain JSON-RPC 2.0 objects, one per WS text frame -- exactly the
`DidOpenTextDocumentParams`/`HoverParams`/etc. shapes `lsp-types` defines,
with no transport envelope beyond the WS frame itself.

## Testing

- `cargo test -p loom-lsp` -- unit tests per module (`position`,
  `workspace`, `hover`, `definition`, `completion`) plus
  `tests/lsp_integration.rs`, which drives the whole protocol core
  (`initialize` → `didOpen` → each of the four features) against the
  fixture tree in `tests/fixtures/warp/` (same convention as
  `loom-cli/tests/fixtures/warp-phase0`: a small, self-contained mudlib
  shaped like warp, not a copy of the real repo).
- `cargo clippy -p loom-lsp --all-targets`.
