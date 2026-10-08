// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Tests for the M-IDE-1/M-IDE-3 static-document audit
 * (`scripts/check-static-csp.mjs`): the checker is the thing that keeps
 * `script-src 'self'` true in practice, so it is tested against the
 * escape hatches it exists to catch, not only against the pages it
 * currently passes.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { auditDocument, servedDocuments } from "./check-static-csp.mjs";

const PAGES = 3;

function policy(content) {
  return `<meta http-equiv="Content-Security-Policy" content="${content}" />`;
}
const GOOD_POLICY = policy("default-src 'self'; script-src 'self'; style-src 'self'");

function doc(body, head = GOOD_POLICY) {
  return `<!doctype html>\n<html lang="en">\n  <head>\n    <meta charset="utf-8" />\n    ${head}\n  </head>\n  <body>\n    ${body}\n  </body>\n</html>\n`;
}

function findings(documentText) {
  return auditDocument(documentText, "fixture.html");
}

test("a page with only external scripts and styles is clean", () => {
  const text = doc(
    `<nav id="nav"></nav>\n<script type="module" src="./dist/ide/main.js"></script>`,
  );
  assert.deepEqual(findings(text), []);
});

test("comments are not code: an explained-about inline script does not trip the audit", () => {
  const text = doc(
    `<!-- this page used to have an inline <script>bootstrap</script> and a style="" attribute -->\n` +
      `<script src="./dist/ide/main.js"></script>`,
  );
  assert.deepEqual(findings(text), []);
});

test("an inline script body is reported", () => {
  const text = doc(`<script>window.boot = 1;</script>`);
  assert.ok(
    findings(text).some((f) => f.includes("inline <script> body")),
    findings(text).join("\n"),
  );
});

test("a script without src but with a type is still inline", () => {
  const text = doc(`<script type="module">import "./dist/ide/main.js";</script>`);
  assert.equal(findings(text).filter((f) => f.includes("inline <script>")).length, 1);
});

test("a CDN script is reported even when the CSP would allow it", () => {
  const text = doc(`<script src="https://cdn.jsdelivr.net/npm/monaco-editor/min/vs/loader.js"></script>`);
  assert.ok(
    findings(text).some((f) => f.includes("off-origin script src")),
    findings(text).join("\n"),
  );
});

test("a protocol-relative or data: reference is off-origin", () => {
  assert.ok(
    findings(doc(`<script src="//cdn.example/x.js"></script>`)).some((f) =>
      f.includes("off-origin script src"),
    ),
  );
  assert.ok(
    findings(doc(`<link rel="icon" href="data:image/png;base64,iVBOR" />`)).some((f) =>
      f.includes("off-origin href"),
    ),
  );
});

test("a <style> element or an inline style attribute is reported", () => {
  assert.ok(findings(doc(`<style>body{color:red}</style>`)).some((f) => f.includes("<style> element")));
  assert.ok(
    findings(doc(`<div style="color:red"></div>\n<script src="./a.js"></script>`)).some((f) =>
      f.includes("inline style attribute"),
    ),
  );
});

test("an on* handler attribute is reported", () => {
  const text = doc(`<button onclick="doThing()">go</button>\n<script src="./a.js"></script>`);
  assert.ok(
    findings(text).some((f) => f.includes("inline handler onclick")),
    findings(text).join("\n"),
  );
});

test("a page with no meta CSP is reported", () => {
  const text = doc(`<script src="./a.js"></script>`, "");
  assert.ok(findings(text).some((f) => f.includes("no <meta")));
});

test("two meta CSP policies are reported: a document is held to all of them", () => {
  const text = doc(
    `<script src="./a.js"></script>`,
    `${GOOD_POLICY}\n    ${policy("script-src 'self' 'unsafe-inline'")}`,
  );
  const found = findings(text);
  assert.ok(found.some((f) => f.includes("2 <meta> CSP policies")), found.join("\n"));
  assert.ok(found.some((f) => f.includes("unsafe-inline")), found.join("\n"));
});

test("a meta CSP whose script-src is a wildcard or missing is reported", () => {
  assert.ok(
    findings(doc(`<script src="./a.js"></script>`, policy("script-src *"))).some((f) =>
      f.includes("wildcard"),
    ),
  );
  assert.ok(
    findings(doc(`<script src="./a.js"></script>`, policy("default-src 'self'"))).some((f) =>
      f.includes("no script-src"),
    ),
  );
  assert.ok(
    findings(doc(`<script src="./a.js"></script>`, policy("script-src https://cdn.example"))).some(
      (f) => f.includes("not 'self'"),
    ),
  );
});

test("the audited document set is the authored pages, not vendored or built files", () => {
  const rel = servedDocuments().map((f) => f.slice(f.indexOf("web-client") + "web-client/".length));
  assert.deepEqual(rel.sort(), ["admin.html", "ide.html", "index.html"]);
});

// Rule 6: the websocket carve-out. A `<meta>` is fixed text and cannot
// name the host it will be served from, so for a page that opens a socket
// it must not decide `connect-src` at all (see `static_csp` in
// `crates/loom-http/src/lib.rs`, which does it per request). These tests
// pin both halves of that rule, because the failure mode is a silently
// dead `/ws` or `/lsp` in the browser that follows CSP3 literally.

/** A policy of the shape a socket page is allowed to carry. */
const SOCKET_POLICY = policy(
  "script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
);

function socketFindings(documentText) {
  return auditDocument(documentText, "web-client/ide.html");
}

test("a socket page whose <meta> omits connect-src and default-src is clean", () => {
  assert.deepEqual(socketFindings(doc(`<script src="./a.js"></script>`, SOCKET_POLICY)), []);
});

test("a socket page that carries default-src or connect-src is reported", () => {
  for (const content of [
    `default-src 'self'; ${SOCKET_POLICY.match(/content="([^"]*)"/)[1]}`,
    SOCKET_POLICY.match(/content="([^"]*)"/)[1] + "; connect-src 'self'",
  ]) {
    const found = socketFindings(doc(`<script src="./a.js"></script>`, policy(content)));
    assert.ok(
      found.some((f) => f.includes("websocket")),
      `expected a websocket finding for ${JSON.stringify(content)}, got ${found.join("\n")}`,
    );
  }
});

test("a socket page must still narrow object-src/base-uri/frame-ancestors itself", () => {
  const found = socketFindings(
    doc(`<script src="./a.js"></script>`, policy("script-src 'self'")),
  );
  for (const directive of ["object-src", "base-uri", "frame-ancestors"]) {
    assert.ok(
      found.some((f) => f.includes(`must narrow ${directive}`)),
      found.join("\n"),
    );
  }
});

test("a non-socket page that drops default-src is reported", () => {
  const found = findings(doc(`<script src="./a.js"></script>`, SOCKET_POLICY));
  assert.ok(
    found.some((f) => f.includes("non-socket page must carry a standalone default-src")),
    found.join("\n"),
  );
});

test("the repo's own documents satisfy the policy pair they advertise", () => {
  // Not a tautology: this reads the real `web-client/*.html`, so a page
  // that gains a socket without joining `SOCKET_PAGES` -- or a header
  // policy quietly narrowed back to `connect-src 'self'` alone with the
  // meta still carrying it -- fails here instead of failing in staging.
  for (const file of servedDocuments()) {
    const name = file.slice(file.lastIndexOf("/") + 1);
    const found = auditDocument(readFileSync(file, "utf8"), file);
    assert.deepEqual(found, [], `${name} is not clean:\n${found.join("\n")}`);
  }
});
