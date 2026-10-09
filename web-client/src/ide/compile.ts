// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The compiler's diagnostics text -> editor markers (OBI-180 M-IDE:
 * "sees a diagnostic, fixes it, object updates").
 *
 * `POST /api/v1/files/compile` (M-FS-5, PR #119) answers
 * `{ ok: false, diagnostics: "<text>", truncated?: true }`, and that text
 * is `loom-syntax`'s own rustc-style rendering, emitted verbatim (only
 * byte-capped) by `loom-http`:
 *
 * ```text
 * /cmds/kill.c:12:9: error[W0201]: unknown efun `foo`
 *    |
 * 12 |   foo(this);
 *    |         ^^^
 *    = help: did you mean `foreach`?
 * ```
 *
 * (`crates/loom-syntax/src/diag.rs`'s `Diagnostic::render` is the source
 * of that shape; the follow-on gutter/caret/help lines carry no position
 * of their own and are kept with the diagnostic above them so the panel
 * can show the whole block.)
 *
 * This is a *display* parser, not a second authority on what an error
 * is: an unrecognised line becomes a diagnostic with no position, which
 * still shows in the panel. That keeps the IDE working when the compiler's
 * rendering changes and `loom-lsp`'s `publishDiagnostics` (M-LSP-3, the
 * structured replacement for this) lands later.
 */

/** Diagnostic severities the panel distinguishes. `loom-syntax` labels
 * are `"error"` and `"warning"` (see its `Severity::label`); anything
 * else in a header line is treated as an error, since an unrecognised
 * prefix in compiler output should never look like good news. */
export type Severity = "error" | "warning" | "info";

export interface ParsedDiagnostic {
  /** Mudlib path the compiler named, e.g. `/cmds/kill.c`. `null` when
   * the header line had no recognisable `path:line:col:` prefix. */
  path: string | null;
  /** 1-based, as the compiler renders it. Monaco's markers are 1-based
   * too, so no adjustment happens at the call site. */
  line: number | null;
  /** 1-based character column of the span start. */
  column: number | null;
  severity: Severity;
  code: string | null;
  message: string;
  /** The caret/source/help lines that followed, kept verbatim. */
  context: string[];
}

/** A diagnostics body capped at `MAX_DIAGNOSTICS_BYTES` server-side can
 * end mid-line; `truncated` says so and the panel appends this note
 * rather than letting a cut-off sentence look like a complete one. */
export const TRUNCATION_NOTE = "(diagnostics truncated by the driver)";

const HEADER =
  /^(?<path>[^\r\n]*?):(?<line>\d{1,9}):(?<col>\d{1,9}): (?<severity>error|warning|note|help)(?:\[(?<code>[^\]\r\n]*)\])?: (?<message>.*)$/;

/** One diagnostic header: `path:line:col: error[Wxxxx]: message`. */
export function parseDiagnosticLine(line: string): ParsedDiagnostic | null {
  const match = HEADER.exec(line);
  if (match?.groups === undefined) {
    return null;
  }
  const groups = match.groups;
  const severity = groups["severity"];
  return {
    path: groups["path"]!.length > 0 ? groups["path"]! : null,
    line: numberOrNull(groups["line"]),
    column: numberOrNull(groups["col"]),
    severity: severity === "warning" ? "warning" : severity === "note" || severity === "help" ? "info" : "error",
    code: groups["code"] ?? null,
    message: groups["message"] ?? "",
    context: [],
  };
}

function numberOrNull(raw: string | undefined): number | null {
  if (raw === undefined) return null;
  const n = Number.parseInt(raw, 10);
  // A `0` line or column is not a position the editor can point at:
  // Monaco markers are 1-based, and the compiler never renders a 0.
  if (!Number.isFinite(n) || n < 1) return null;
  return n;
}

/** Parse a whole `diagnostics` text into ordered diagnostics, attaching
 * each one's caret/source/help block to it. */
export function parseDiagnostics(text: string): ParsedDiagnostic[] {
  const out: ParsedDiagnostic[] = [];
  let current: ParsedDiagnostic | null = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\s+$/, "");
    if (line.length === 0) {
      continue;
    }
    const header = parseDiagnosticLine(line);
    if (header !== null) {
      current = header;
      out.push(header);
      continue;
    }
    if (current === null) {
      // Output the parser doesn't recognise at all (a driver message, a
      // half-line from a truncated body): still worth showing.
      current = {
        path: null,
        line: null,
        column: null,
        severity: "error",
        code: null,
        message: line,
        context: [],
      };
      out.push(current);
      continue;
    }
    // The gutter/source/caret/help lines `Diagnostic::render` emits under
    // a header belong to it verbatim; anything else that is not a header
    // is treated as continuation text for the same reason.
    current.context.push(line);
  }
  return out;
}

/** `true` if the diagnostics name `path`, so the IDE can decide whether
 * to jump to the first one (a recompile of *this* file) or just report
 * that another file failed (`/adm/room.c` can break on a dependency's
 * error). */
export function diagnosticsFor(diagnostics: ParsedDiagnostic[], path: string): ParsedDiagnostic[] {
  return diagnostics.filter((d) => d.path === null || d.path === path);
}

export function hasErrors(diagnostics: ParsedDiagnostic[]): boolean {
  return diagnostics.some((d) => d.severity === "error");
}

/** The panel's plain-text rendering of one diagnostic. Returned as a
 * string for the caller to put in a text node -- this module never
 * touches the DOM (M-IDE-2: no HTML sink anywhere in the IDE's
 * rendering path; see `src/admin/dom.ts`). */
export function formatDiagnostic(diagnostic: ParsedDiagnostic): string {
  const head = diagnostic.path ?? "(unknown file)";
  const position =
    diagnostic.line !== null ? `:${diagnostic.line}${diagnostic.column !== null ? `:${diagnostic.column}` : ""}` : "";
  const code = diagnostic.code !== null ? `[${diagnostic.code}] ` : "";
  const lines = [
    `${head}${position}: ${diagnostic.severity} ${code}${diagnostic.message}`,
    ...diagnostic.context,
  ];
  return lines.join("\n");
}
