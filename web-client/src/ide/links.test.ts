// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import test from "node:test";
import assert from "node:assert/strict";

import {
  ALLOWED_LINK_SCHEMES,
  asPlainText,
  linkCandidates,
  safeLinkUrls,
  sanitizeLinkUrl,
  vfsPathOf,
} from "./links.js";

test("https: and loom-vfs: are the only accepted schemes", () => {
  assert.deepEqual(ALLOWED_LINK_SCHEMES, ["https:", "loom-vfs:"]);
  assert.equal(sanitizeLinkUrl("https://www.looqmud.example/docs"), "https://www.looqmud.example/docs");
  assert.equal(sanitizeLinkUrl("loom-vfs:/cmds/kill.c"), "loom-vfs:/cmds/kill.c");
});

test("the schemes that steal a session are refused", () => {
  for (const url of [
    "javascript:alert(1)",
    "JavaScript:alert(1)",
    "  javascript:alert(1)  ",
    "data:text/html,<script>alert(1)</script>",
    "data:image/svg+xml,<svg onload=alert(1)>",
    "blob:https://example/uuid",
    "file:///etc/passwd",
    "about:blank",
    "view-source:https://example/x",
    "ftp://example/x",
  ]) {
    assert.equal(sanitizeLinkUrl(url), null, `${url} must be refused`);
  }
});

test("a scheme-less or relative URL is refused rather than resolved against this origin", () => {
  for (const url of ["/adm/room.c", "./x.c", "../x.c", "room.c", "//cdn.example/x.js", ""]) {
    assert.equal(sanitizeLinkUrl(url), null, `${JSON.stringify(url)} must be refused`);
  }
});

test("https credentials, an empty host, or a bare hostname are refused", () => {
  assert.equal(sanitizeLinkUrl("https://user:pass@evil.example/"), null);
  assert.equal(sanitizeLinkUrl("https://@evil.example/"), null);
  assert.equal(sanitizeLinkUrl("https://localhost/x"), null);
  assert.equal(sanitizeLinkUrl("https:///x"), null);
  assert.equal(sanitizeLinkUrl("https:/\\/\\/evil.example"), null);
  assert.equal(sanitizeLinkUrl("https://not a url"), null);
});

test("a loom-vfs path must be an absolute mudlib path and nothing more", () => {
  assert.equal(sanitizeLinkUrl("loom-vfs:/adm/room.c"), "loom-vfs:/adm/room.c");
  assert.equal(sanitizeLinkUrl("loom-vfs:/cmds/kill player.c"), "loom-vfs:/cmds/kill player.c");
  assert.equal(sanitizeLinkUrl("loom-vfs:cmds/kill.c"), null);
  assert.equal(sanitizeLinkUrl("loom-vfs:/a/../b.c"), null);
  assert.equal(sanitizeLinkUrl("loom-vfs:/%2e%2e/a.c"), null);
  assert.equal(sanitizeLinkUrl("loom-vfs:/a.c?x=1"), null);
  assert.equal(sanitizeLinkUrl("loom-vfs:/a.c#frag"), null);
  assert.equal(sanitizeLinkUrl("loom-vfs:/a\\b.c"), null);
  assert.equal(sanitizeLinkUrl("loom-vfs://evil.example/a.c"), null);
});

test("candidates are found in markdown, autolinks, and bare text", () => {
  assert.deepEqual(
    linkCandidates("see [docs](https://www.example.com/d) and ![img](https://www.example.com/i.png)"),
    ["https://www.example.com/d", "https://www.example.com/i.png"],
  );
  assert.deepEqual(linkCandidates("<https://www.example.com/a>"), ["https://www.example.com/a"]);
  assert.deepEqual(linkCandidates("loom-vfs:/adm/room.c is the file"), ["loom-vfs:/adm/room.c"]);
  assert.deepEqual(linkCandidates("https://x.example/a)tail"), ["https://x.example/a"]);
});

test("safeLinkUrls drops the unsafe ones from a mixed string", () => {
  const text =
    "[a](javascript:alert(1)) [b](loom-vfs:/adm/room.c) [c](data:text/html,x) [d](https://www.example.com/ok)";
  assert.deepEqual(safeLinkUrls(text), ["loom-vfs:/adm/room.c", "https://www.example.com/ok"]);
  // Duplicates collapse: a repeated URL is one link, not two providers.
  assert.deepEqual(safeLinkUrls("loom-vfs:/a.c loom-vfs:/a.c"), ["loom-vfs:/a.c"]);
});

test("asPlainText strips markup but keeps the words", () => {
  assert.equal(asPlainText("<b>bold</b> text"), "bold text");
  assert.equal(asPlainText("a < b and c > d"), "a < b and c > d");
  assert.equal(asPlainText("<img src=x onerror=alert(1)>"), "");
});

test("vfsPathOf round-trips a safe loom-vfs url", () => {
  assert.equal(vfsPathOf("loom-vfs:/adm/room.c"), "/adm/room.c");
  assert.equal(vfsPathOf("https://www.example.com/x"), null);
  assert.equal(vfsPathOf("loom-vfs:/a/../b"), null);
});
