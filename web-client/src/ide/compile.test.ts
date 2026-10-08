// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import test from "node:test";
import assert from "node:assert/strict";

import {
  diagnosticsFor,
  formatDiagnostic,
  hasErrors,
  parseDiagnosticLine,
  parseDiagnostics,
} from "./compile.js";

/** Verbatim `loom-syntax`'s `Diagnostic::render` output for
 * `/cmds/kill.c`, line 12: a header, the gutter, the source line, the
 * caret, and a help line. */
const RENDERED = [
  "/cmds/kill.c:12:9: error[W0201]: unknown efun `foo`",
  "   |",
  "12 |   foo(this);",
  "   |         ^^^",
  "   = help: did you mean `foreach`?",
  "",
].join("\n");

test("a compiler header line parses into path, position, severity and code", () => {
  const parsed = parseDiagnosticLine("/cmds/kill.c:12:9: error[W0201]: unknown efun `foo`");
  assert.ok(parsed);
  assert.equal(parsed.path, "/cmds/kill.c");
  assert.equal(parsed.line, 12);
  assert.equal(parsed.column, 9);
  assert.equal(parsed.severity, "error");
  assert.equal(parsed.code, "W0201");
  assert.equal(parsed.message, "unknown efun `foo`");
});

test("warnings and code-less headers parse too", () => {
  const warning = parseDiagnosticLine("/a.c:1:1: warning[W0007]: unused variable `x`");
  assert.equal(warning?.severity, "warning");
  const noCode = parseDiagnosticLine("/a.c:3:4: error: expected `;`");
  assert.equal(noCode?.code, null);
  assert.equal(noCode?.severity, "error");
});

test("non-position lines are not headers", () => {
  assert.equal(parseDiagnosticLine("   = help: did you mean `foreach`?"), null);
  assert.equal(parseDiagnosticLine("12 |   foo(this);"), null);
  // A line/col of 0 is not a position the editor can point at.
  const zero = parseDiagnosticLine("/a.c:0:0: error[W1]: x");
  assert.equal(zero?.line, null);
  assert.equal(zero?.column, null);
});

test("a rendered diagnostic keeps its gutter art with it", () => {
  const diagnostics = parseDiagnostics(RENDERED);
  assert.equal(diagnostics.length, 1);
  const first = diagnostics[0]!;
  assert.equal(first.line, 12);
  assert.deepEqual(first.context, [
    "   |",
    "12 |   foo(this);",
    "   |         ^^^",
    "   = help: did you mean `foreach`?",
  ]);
});

test("several diagnostics split in order", () => {
  const text = [
    "/a.c:1:1: error[W0201]: first",
    "  |",
    "1 | x;",
    "  | ^",
    "/b.c:9:3: warning[W0007]: second",
  ].join("\n");
  const diagnostics = parseDiagnostics(text);
  assert.deepEqual(
    diagnostics.map((d) => [d.path, d.line, d.severity]),
    [
      ["/a.c", 1, "error"],
      ["/b.c", 9, "warning"],
    ],
  );
});

test("unrecognised output still shows, as an error with no position", () => {
  const diagnostics = parseDiagnostics("compile of /a.c failed: no such file");
  assert.equal(diagnostics.length, 1);
  assert.equal(diagnostics[0]?.line, null);
  assert.equal(diagnostics[0]?.path, null);
  assert.equal(diagnostics[0]?.severity, "error");
  assert.equal(hasErrors(diagnostics), true);
});

test("warnings alone are not errors", () => {
  const diagnostics = parseDiagnostics("/a.c:1:1: warning[W0007]: unused");
  assert.equal(hasErrors(diagnostics), false);
});

test("only the open file's diagnostics become markers, and path-less ones are kept", () => {
  const diagnostics = parseDiagnostics(
    ["/a.c:5:2: error[W1]: mine", "/b.c:7:1: error[W2]: someone else's"].join("\n"),
  );
  const mine = diagnosticsFor(diagnostics, "/a.c");
  assert.deepEqual(
    mine.map((d) => d.path),
    ["/a.c"],
  );
  const withHeaderless = parseDiagnostics("boom\n/a.c:2:2: error[W1]: x");
  assert.equal(diagnosticsFor(withHeaderless, "/a.c").length, 2);
});

test("the panel line is plain text a caller can put in a text node", () => {
  const [diagnostic] = parseDiagnostics(RENDERED);
  const line = formatDiagnostic(diagnostic!);
  assert.match(line, /^\/cmds\/kill\.c:12:9: error \[W0201\] unknown efun `foo`/);
  assert.match(line, /did you mean `foreach`\?/);
  // Nothing here is HTML: the renderer's only sink is `textContent`.
  assert.equal(line.includes("<"), false);
});

test("a truncated body that ends mid-line does not throw", () => {
  const diagnostics = parseDiagnostics("/a.c:3:4: error[W0201]: incomplete mes");
  assert.equal(diagnostics.length, 1);
  assert.equal(diagnostics[0]?.message, "incomplete mes");
});
