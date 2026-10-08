// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Tests for the version-stamp drift gate in `scripts/vendor-monaco.mjs`
 * (OBI-338).
 *
 * `loom-http` promises that anything under `vendor/monaco/<version>/` is
 * frozen for a year. That is only true while the version literal written
 * into `ide.html` and `src/ide/amd-boot.ts` matches the version the staging
 * script put on disk, so the match is a gate rather than a convention --
 * and this tests the gate against the drift it exists to catch, in both
 * directions, plus against the mentions that are prose rather than a URL.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { monacoVendorRefs, unpinnedRefs, vendorPrefix } from "./vendor-monaco.mjs";

const here = dirname(fileURLToPath(import.meta.url));

/**
 * The version the drift gate will demand. `stage()` compares against the
 * *installed* version, which under `npm ci` and a committed lockfile is this
 * one; reading the pin rather than hardcoding it means a bump moves the
 * fixtures and the real check together, and nothing here rots silently.
 */
const VERSION = JSON.parse(
  readFileSync(join(here, "..", "web-client", "package.json"), "utf8"),
).dependencies["monaco-editor"];
const STAMPED = `${vendorPrefix(VERSION)}/vs/loader.js`;

function problems(text) {
  return unpinnedRefs(text, VERSION);
}

test("a reference to the stamped path is the only thing that passes", () => {
  assert.deepStrictEqual(problems(`<script src="./${STAMPED}"></script>`), []);
  assert.deepStrictEqual(
    problems(`const require = { paths: { vs: "${vendorPrefix(VERSION)}/vs" } };`),
    [],
  );
  // Deep inside the tree is still inside the stamped directory.
  assert.deepStrictEqual(
    problems(`<link rel="stylesheet" href="./${vendorPrefix(VERSION)}/vs/editor/editor.main.css" />`),
    [],
  );
});

test("the path shape from before the stamp fails, because it moves", () => {
  // `vendor/monaco/vs/loader.js` is served for whatever version the image
  // happens to contain. `immutable` on that URL is a browser holding the
  // previous deploy's Monaco forever, so it must not pass the gate.
  for (const stale of [
    `<script src="./vendor/monaco/vs/loader.js"></script>`,
    `<script src="/vendor/monaco/vs/loader.js"></script>`,
    `href="./vendor/monaco/vs/editor/editor.main.css"`,
  ]) {
    const found = problems(stale);
    assert.ok(found.length > 0, stale);
    assert.ok(
      found.some((problem) => problem.includes("vendor/monaco/vs/")),
      `${stale} must name the stale path it found: ${found.join("; ")}`,
    );
  }
});

test("a reference to some other version fails too", () => {
  // The version in the URL is a claim about the bytes; a bump that misses a
  // file keeps the *old* bytes cached under a URL the new build still asks
  // for, which is the same failure wearing a different hat.
  const other = `${VERSION.split(".", 2).join(".")}.999`;
  const found = problems(`<script src="./vendor/monaco/${other}/vs/loader.js"></script>`);
  assert.ok(
    found.some((problem) => problem.includes(`vendor/monaco/${other}`)),
    found.join("; "),
  );
  assert.ok(
    found.some((problem) => problem.includes(`not ${VERSION}`)),
    found.join("; "),
  );

  // ...and so does a file that mixes both, because one of the two is lying --
  // and names only the one that is.
  const mixed = problems(
    `<link href="./${STAMPED}" />\n<script src="./vendor/monaco/${other}/vs/loader.js"></script>`,
  );
  assert.equal(mixed.length, 1, `the pinned reference is fine; the other is not: ${mixed}`);
  assert.ok(mixed[0].includes(other));
});

test("a file that stopped naming the tree at all fails", () => {
  // The gate is only a gate if silence is an error: an `ide.html` whose
  // script tags were rewritten to something else would otherwise pass with
  // the loader 404ing at runtime.
  assert.deepStrictEqual(problems(`<nav id="nav"></nav>`), [
    `no reference to ${vendorPrefix(VERSION)}/`,
  ]);
  // A bare mention of the undated directory is the same bug: there is no
  // such thing as a stable URL for the directory itself.
  const bare = problems(`<script src="./vendor/monaco/"></script>`);
  assert.ok(
    bare.some((problem) => problem.includes("references vendor/monaco/ (not")),
    bare.join("; "),
  );
});

test("a mention in a comment is read as the URL it is written as", () => {
  // Both of these are in the real files' shape: HTML comments and doc-block
  // prose. A comment that spells the unstamped path is a hazard -- it is
  // where a future edit copies its URL from -- so it fails, and says so.
  assert.ok(
    problems(`<!-- it used to be ./vendor/monaco/vs/loader.js -->`).length > 0,
    "a comment naming the unstamped path is a reference to it",
  );
  assert.deepStrictEqual(
    problems(`/* boot from ${STAMPED} */`),
    [],
    "a comment that names the stamped path is accurate",
  );
  // Prose that talks about the tree without naming a URL under it is not a
  // reference and must not be treated as one.
  assert.deepStrictEqual(
    problems("Monaco is vendored under vendor/monaco and cached."),
    [`no reference to ${vendorPrefix(VERSION)}/`],
  );
});

test("monacoVendorRefs reports the segment of every mention", () => {
  assert.deepStrictEqual(
    monacoVendorRefs(`"${vendorPrefix(VERSION)}/vs" './other' ${STAMPED}?v=2`),
    [VERSION, VERSION],
  );
  // A query or fragment ends the segment; so does a path separator.
  assert.deepStrictEqual(monacoVendorRefs(`${vendorPrefix(VERSION)}?cache=1`), [VERSION]);
  assert.deepStrictEqual(monacoVendorRefs("vendor/monaco/latest/vs"), ["latest"]);
});

test("the served files in this repository pass their own gate", () => {
  // The fixture tests above prove the gate has teeth; this proves it is not
  // asserting something the real pages violate. It reads the same files
  // `stage()` reads, against the same pin, so a bump that forgets them fails
  // here before it fails the build.
  const webClient = join(here, "..", "web-client");
  for (const file of ["ide.html", "src/ide/amd-boot.ts"]) {
    const text = readFileSync(join(webClient, file), "utf8");
    const found = problems(text);
    assert.deepStrictEqual(found, [], `${file} must reference the pinned Monaco version`);
  }
});
