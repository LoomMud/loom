// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Mudlib file path <-> `loom-lsp`'s VFS document URI (OBI-180, spec
 * M-LSP-3).
 *
 * `loom-lsp` speaks exactly one URI scheme per mode, and in the web IDE's
 * mode (`UriMode::Vfs`, the per-session `/lsp` socket) that scheme is
 * `loom-vfs://<program path>.wf` -- see `crates/loom-lsp/src/workspace.rs`'s
 * `program_path_to_vfs_uri`/`vfs_uri_to_program_path`. This module is the
 * client half of that pair, and it is deliberately a *re*implementation
 * rather than a shared abstraction: the two halves live in different
 * languages with different parsers, and what makes the boundary safe is
 * that both sides independently refuse everything outside the scheme.
 *
 * Two properties the security review cares about:
 *
 * 1. **Nothing but `loom-vfs://` leaves or enters.** A `file:` URI is
 *    never generated (M-LSP-3: "no host path can reach a response"), and
 *    a `file:` URI in something the server sent us is *refused* rather
 *    than opened (T-LSP-3's client-side half). `documentUri` returns
 *    `null` for a path it cannot express; the caller then does not sync
 *    the buffer at all instead of guessing at a scheme.
 * 2. **Percent-decoding happens exactly once**, and the result must still
 *    pass the mudlib's own path grammar. `%2e%2e` decodes to `..`, `..`
 *    fails the segment test, and the answer is `null`. There is no
 *    "normalise and hope" step: the grammar here mirrors
 *    `loom_compiler::mudlib::normalize_path` (letters, digits, `_`, `-`,
 *    absolute, no empty/`.`/`..` segments), which is also why no escaping
 *    is needed on the way out -- every character that grammar allows is a
 *    URI `pchar`, so `documentUri`'s output is byte-identical to what the
 *    server's percent-encoder produces for the same path.
 *
 * Paths here are the IDE's file paths -- the same strings
 * `/api/v1/files/content?path=...` takes, so they carry the `.wf`
 * extension. `loom-lsp`'s internal *program* paths do not; the `.wf` is
 * the URI form's only difference from them, and it is added and stripped
 * here, at the boundary, and nowhere else.
 */

/** The scheme `loom-lsp`'s VFS mode uses, with the `//` authority (empty,
 * so the URI reads `loom-vfs:///std/room.wf`). */
export const VFS_URI_PREFIX = "loom-vfs://";

/** Every program path ends in it; the server appends it in `uri_for_path`
 * and requires it in `vfs_uri_to_program_path`. */
const WF_SUFFIX = ".wf";

/** One `normalize_path`-legal segment. Note what is *absent*: `.`, `..`,
 * the empty string, `/`, `\`, `:`, and every character `PATH_ESCAPE`
 * percent-encodes. A segment containing any of them is not a program path
 * the driver would read, so it is not one we will name in a URI either. */
const SEGMENT = /^[A-Za-z0-9_-]+$/;

/** The bytes that could make `decoded` mean something other than what it
 * looks like: `%` followed by two hex digits. Replaced once, left alone if
 * malformed (`%zz`, `%`) -- `percent_decode_str` in the server does the
 * same (it is lossy, not strict), so a stray `%` round-trips as `%` rather
 * than throwing away the frame. */
function percentDecode(value: string): string {
  if (!value.includes("%")) {
    return value;
  }
  return value.replace(/%([0-9A-Fa-f]{2})/g, (_match, hex: string) =>
    String.fromCharCode(Number.parseInt(hex, 16)),
  );
}

/** `true` when `path` is a mudlib file path this session may name:
 * absolute, `normalize_path`-legal segments, `.wf` suffix (added when it
 * is missing, so a tree entry and its program path agree). */
export function isMudlibFilePath(path: string): boolean {
  return filePathFromProgramPath(path) !== null;
}

/** The program path part of `path` (`/std/room` from `/std/room.wf`), or
 * `null` when `path` is not one the driver would read. Exported for the
 * tests and for the IDE's "is this file analyzable at all" check. */
export function programPath(path: string): string | null {
  const trimmed = path.trim();
  const withoutSuffix = trimmed.endsWith(WF_SUFFIX)
    ? trimmed.slice(0, -WF_SUFFIX.length)
    : trimmed;
  if (!withoutSuffix.startsWith("/")) {
    return null;
  }
  const segments = withoutSuffix.slice(1).split("/");
  if (segments.length === 0 || segments.some((segment) => !SEGMENT.test(segment))) {
    return null;
  }
  return withoutSuffix;
}

function filePathFromProgramPath(path: string): string | null {
  const normalized = programPath(path);
  return normalized === null ? null : `${normalized}${WF_SUFFIX}`;
}

/**
 * The `loom-lsp` document URI for an IDE file path, or `null` when the
 * path is not a mudlib program (a `.txt`, a `..`, an absolute host path,
 * anything with a character the VFS resolver would refuse). Callers must
 * treat `null` as "do not sync this buffer", not as an error to paper
 * over: sending a URI the server cannot map would leave the buffer
 * silently un-analyzed, which looks to the builder like a dead analyzer.
 */
export function documentUri(path: string): string | null {
  const normalized = programPath(path);
  if (normalized === null) {
    return null;
  }
  return `${VFS_URI_PREFIX}${normalized}${WF_SUFFIX}`;
}

/**
 * The IDE file path a `loom-lsp` document URI names, or `null`.
 *
 * This is the only place a server-supplied URI becomes something the IDE
 * acts on (a diagnostics payload's `uri`, a go-to-definition target), so
 * it is where M-LSP-3 is enforced on the way back in: the prefix is
 * mandatory, decoding happens once, and the result must satisfy the same
 * grammar `documentUri` requires. A `file:///etc/passwd` or a
 * `https://evil/` in a response yields `null` and is dropped by the
 * caller -- it never reaches `openFile`, the model URI, or the tree.
 */
export function pathFromDocumentUri(uri: string): string | null {
  if (!uri.startsWith(VFS_URI_PREFIX)) {
    return null;
  }
  const decoded = percentDecode(uri.slice(VFS_URI_PREFIX.length));
  if (!decoded.endsWith(WF_SUFFIX)) {
    return null;
  }
  return filePathFromProgramPath(decoded);
}
