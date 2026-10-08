// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import test from "node:test";
import assert from "node:assert/strict";

import {
  baseName,
  FileTree,
  isShowableName,
  joinPath,
  parentOf,
  type TreeRow,
} from "./tree.js";

function rowByPath(rows: TreeRow[], path: string): TreeRow {
  const row = rows.find((r) => r.path === path);
  assert.ok(row, `no row for ${path} in ${JSON.stringify(rows.map((r) => r.path))}`);
  return row;
}

test("path helpers", () => {
  assert.equal(joinPath("/", "adm"), "/adm");
  assert.equal(joinPath("/cmds", "kill.c"), "/cmds/kill.c");
  assert.equal(joinPath("/cmds/", "kill.c"), "/cmds/kill.c");
  assert.equal(baseName("/cmds/kill.c"), "kill.c");
  assert.equal(baseName("/adm/"), "adm");
  assert.equal(baseName("/"), "/");
  assert.equal(parentOf("/cmds/kill.c"), "/cmds");
  assert.equal(parentOf("/adm.c"), "/");
  assert.equal(parentOf("/cmds/adm/"), "/cmds");
});

test("names the tree will not display", () => {
  assert.equal(isShowableName("kill.c"), true);
  assert.equal(isShowableName("adm"), true);
  // The server's `to_string_lossy` marker: the real name cannot be
  // requested back, so showing it would offer a dead click.
  assert.equal(isShowableName(`bad\uFFFDname.c`), false);
  // Dotfiles are already dropped server-side (PR #117), but the filter is
  // defence in depth: nothing here trusts the listing it was handed.
  assert.equal(isShowableName(".git"), false);
  assert.equal(isShowableName(""), false);
  assert.equal(isShowableName("."), false);
  assert.equal(isShowableName(".."), false);
  // A name with a separator would make the row's path differ from the
  // path the click asks for.
  assert.equal(isShowableName("a/b"), false);
  // Control characters let `/room\u0000.c` render as `/room.c`.
  assert.equal(isShowableName("room\u0000.c"), false);
  assert.equal(isShowableName("esc\u001b[31m"), false);
});

test("a listing renders in the server's order at depth 0, unfiltered names dropped", () => {
  const tree = new FileTree("/");
  tree.setListing("/", ["adm", "cmds", ".git", "bad\uFFFD.c", "std"]);
  const rows = tree.rows();
  assert.deepEqual(
    rows.map((r) => r.path),
    ["/adm", "/cmds", "/std"],
  );
  assert.deepEqual(rows.map((r) => r.depth), [0, 0, 0]);
  assert.equal(rows[0]?.kind, null);
  assert.equal(rows[0]?.expanded, false);
});

test("an unknown entry becomes a directory only after a probe says so", () => {
  const tree = new FileTree("/");
  tree.setListing("/", ["cmds"]);
  assert.equal(tree.rows()[0]?.kind, null);

  tree.setKind("/cmds", "dir");
  tree.setListing("/cmds", ["kill.c"]);
  tree.expand("/cmds");
  const rows = tree.rows();
  assert.deepEqual(
    rows.map((r) => [r.path, r.depth, r.kind, r.expanded]),
    [
      ["/cmds", 0, "dir", true],
      ["/cmds/kill.c", 1, null, false],
    ],
  );
  assert.equal(rowByPath(rows, "/cmds").needsListing, false);
});

test("a resolved directory that has never been listed says it needs a listing", () => {
  const tree = new FileTree("/");
  tree.setListing("/", ["cmds"]);
  tree.setKind("/cmds", "dir");
  tree.expand("/cmds");
  assert.equal(rowByPath(tree.rows(), "/cmds").needsListing, true);
  assert.equal(rowByPath(tree.rows(), "/cmds").expanded, true);
});

test("collapse hides children; expand again without re-listing keeps them", () => {
  const tree = new FileTree("/");
  tree.setListing("/", ["cmds"]);
  tree.setKind("/cmds", "dir");
  tree.setListing("/cmds", ["kill.c"]);
  tree.expand("/cmds");
  assert.equal(tree.rows().length, 2);
  tree.collapse("/cmds");
  assert.equal(tree.rows().length, 1);
  tree.expand("/cmds");
  assert.equal(tree.rows().length, 2);
  tree.invalidate("/cmds");
  assert.equal(rowByPath(tree.rows(), "/cmds").needsListing, true);
});

test("a truncated listing marks the row so the UI can say \u201cthere is more\u201d", () => {
  const tree = new FileTree("/");
  tree.setListing("/", ["cmds"], false);
  tree.setKind("/cmds", "dir");
  tree.setListing("/cmds", ["a.c", "b.c"], true);
  tree.expand("/cmds");
  assert.equal(rowByPath(tree.rows(), "/cmds").truncated, true);
  assert.equal(rowByPath(tree.rows(), "/cmds/a.c").truncated, false);
});

test("a listing cannot make the walk revisit a path, so rows() always terminates", () => {
  // The walk's `visiting` guard is there for the case a *malformed*
  // listing would create: an entry name carrying a separator, which is
  // how `/loop` could end up as its own child. `isShowableName` drops
  // those, so every child path is strictly longer than its parent's and
  // the recursion has an ordering to ride on. Both halves are asserted
  // because the guard alone would hide a filter regression.
  const tree = new FileTree("/");
  tree.setListing("/", ["loop", "a/../b", "x/y"]);
  tree.setKind("/loop", "dir");
  tree.setListing("/loop", ["../../etc", "passwd"]);
  tree.expand("/loop");
  const rows = tree.rows();
  assert.deepEqual(
    rows.map((r) => [r.path, r.depth]),
    [
      ["/loop", 0],
      ["/loop/passwd", 1],
    ],
  );
});

test("a re-list forgets the old children's kinds", () => {
  const tree = new FileTree("/");
  tree.setListing("/", ["cmds"]);
  tree.setKind("/cmds", "dir");
  tree.setListing("/", ["cmds"]);
  assert.equal(tree.kindOf("/cmds"), null);
});

test("the root is always the expanded starting point and is not itself a row", () => {
  const tree = new FileTree("/");
  assert.equal(tree.rootPath, "/");
  assert.equal(tree.isExpanded("/"), true);
  assert.deepEqual(tree.rows(), []);
});
