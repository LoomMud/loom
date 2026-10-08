// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import test from "node:test";
import assert from "node:assert/strict";

import {
  VFS_URI_PREFIX,
  documentUri,
  isMudlibFilePath,
  pathFromDocumentUri,
  programPath,
} from "./lsp-uri.js";

/**
 * The contract under test is `crates/loom-lsp`'s own, restated on the client:
 * `program_path_to_vfs_uri` / `vfs_uri_to_program_path` in `workspace.rs`, and
 * the segment grammar of `loom_compiler::mudlib::normalize_path`.
 */

test("a mudlib file path becomes an empty-authority loom-vfs URI", () => {
  // Three slashes: `loom-vfs://` + an absolute path. One slash would put the
  // first segment in the URI's *authority*, where the server's
  // `vfs_uri_to_program_path` never looks -- the single most likely way for a
  // client to be silently never-analysed, so it is asserted as text.
  assert.equal(documentUri("/std/room.wf"), "loom-vfs:///std/room.wf");
  assert.ok(documentUri("/std/room.wf")?.startsWith(`${VFS_URI_PREFIX}/`));
});

test("a path without .wf is the same program, so the same URI", () => {
  // The tree and the program path have to agree or a buffer would be opened
  // twice under two URIs and analysed as two unrelated files.
  assert.equal(documentUri("/std/room"), documentUri("/std/room.wf"));
  assert.equal(programPath("/std/room.wf"), "/std/room");
});

test("the round trip is exact for legal paths", () => {
  for (const path of ["/room.wf", "/std/room.wf", "/d/bo/long_name-2.wf", "/x1/_y/z_.wf"]) {
    const uri = documentUri(path);
    assert.notEqual(uri, null, `${path} should be expressible`);
    assert.equal(pathFromDocumentUri(uri as string), path);
  }
});

test("nothing outside the mudlib's grammar gets a URI", () => {
  const rejected = [
    "std/room.wf", // relative: the VFS resolves nothing relative to a client's cwd
    "/std/../etc/passwd.wf", // traversal
    "/std/./room.wf", // dot segment
    "/.hidden.wf", // a dotfile is not a program
    "/std/room.txt", // not a program file
    "",
    "/",
    "//std/room.wf", // empty segment
    "/std/room .wf", // space
    "/std/ro\\om.wf", // backslash: a Windows separator, never a mudlib one
    "/std/ro:om.wf", // would be read as a scheme
    "/std/room\n.wf", // control byte
    "C:/Windows/system32.wf", // a host path is not a program path
  ];
  for (const path of rejected) {
    assert.equal(documentUri(path), null, `${JSON.stringify(path)} must not get a URI`);
    assert.equal(isMudlibFilePath(path), false);
  }
});

test("a path inside the mudlib namespace is accepted even when it looks like a host path", () => {
  // `/etc/passwd` here is `<mudlib>/etc/passwd.wf`, which the VFS would happily
  // read if it exists and the uid may read. Keeping host paths out is M-FS-2's
  // resolver's job, not this grammar's; asserting the difference keeps that
  // division from being mistaken for a hole.
  assert.equal(documentUri("/etc/passwd.wf"), "loom-vfs:///etc/passwd.wf");
});

test("a response URI that is not loom-vfs is refused, not opened", () => {
  // T-LSP-3's client half: whatever a server (or a spoofed frame) claims a
  // target is, only the mudlib scheme can name a file the IDE will act on.
  for (const uri of [
    "file:///etc/passwd",
    "https://evil.example/std/room.wf",
    "loom-vfs:/std/room.wf", // one slash: authority would be "std", not empty
    "loom-vfs://std/room.wf", // non-empty authority
    "LOOM-VFS:///std/room.wf", // the server emits lowercase; case tricks are a no
    "loom-vfs:///std/room", // no .wf
    "loom-vfs:///std/../etc/passwd.wf",
  ]) {
    assert.equal(pathFromDocumentUri(uri), null, `${uri} must be refused`);
  }
});

test("percent-encoding is decoded exactly once, then re-checked", () => {
  // The server percent-encodes on the way out, so a legal URI can contain
  // `%`. One decode is what makes `%2e%2e` *visible* to the grammar check;
  // two decodes would make `%252e%252e` look like `%2e%2e` and pass.
  assert.equal(pathFromDocumentUri("loom-vfs:///std/%72oom.wf"), "/std/room.wf");
  assert.equal(pathFromDocumentUri("loom-vfs:///std/%2e%2e/passwd.wf"), null);
  assert.equal(pathFromDocumentUri("loom-vfs:///std/%252e%252e/passwd.wf"), null);
  // A stray or malformed `%` is lossy in `percent_decode_str` too, so it is
  // left as `%` -- and `%` is not a legal segment character either way.
  assert.equal(pathFromDocumentUri("loom-vfs:///std/ro%zz.wf"), null);
  assert.equal(pathFromDocumentUri("loom-vfs:///std/ro%oom.wf"), null);
});

test("a decoded result must still be one the client would have sent", () => {
  // Whatever comes back in must round-trip: if it did not, the client and
  // server disagree about the URI space and the disagreement is invisible.
  for (const uri of ["loom-vfs:///std/room.wf", "loom-vfs:///d/bo/x-2.wf"]) {
    const path = pathFromDocumentUri(uri);
    assert.notEqual(path, null);
    assert.equal(documentUri(path as string), uri);
  }
});
