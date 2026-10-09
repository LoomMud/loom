#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * M-IDE-3 (OBI-179 threat model v2 §5, OBI-180): stage Monaco into the
 * served web root from the exact version `web-client/package.json` pins,
 * so the editor is self-hosted and there is no CDN anywhere in the path.
 *
 * `web-client/vendor/monaco/` is a build artifact, not source: it is
 * gitignored, produced by `npm run vendor` (which `npm run build` runs
 * first), and copied into the image by the Dockerfile. Staging it as a
 * directory instead of pointing the loader at `node_modules` keeps the
 * served tree to exactly one root (`LOOM_WEB_ROOT`), which is what makes
 * `scripts/check-static-csp.mjs`'s "nothing off-origin" claim decidable.
 *
 * The whole `min/vs` tree is copied (~25 MB) except `nls/` (2.6 MB of
 * message bundles for locales we do not offer -- the AMD loader only
 * fetches them when `MonacoEnvironment.locale` names one). The per-
 * language `language/` and `basic-languages/` bundles are *kept*:
 * `vs/editor/editor.main.js` declares them in its AMD dependency list, so
 * a missing one is a loader error and a blank page, not a graceful
 * degrade. Carving the bundle down to the `loom-lpc` language alone means
 * switching to the ESM build and a bundler, which is a separate decision
 * (it adds a build step to a web client that has none today) -- noted in
 * OBI-180 for the CTO rather than done silently here.
 *
 * Known advisories in what gets staged (so the next reader of
 * `npm run audit` does not have to rediscover this): the LOW findings are
 * `dompurify` <=3.4.15, and they are *not* merely graph noise -- DOMPurify
 * 3.4.15 and `marked` are prebundled inside `vs/editor-*.js`, so pruning
 * the file or adding an npm override changes neither the served bundle nor
 * the advisory. 0.57.0 is the newest release and pins 3.4.15; the fix lands
 * in dompurify 3.4.16, which no Monaco release carries yet.
 *
 * What limits the exposure is our own configuration, and the tests in
 * `src/ide/editor.ts` pin it: the markdown renderers run with
 * `supportHtml: false`, so builder-authored text is escaped before
 * DOMPurify is ever reached, and `isTrusted: false` keeps Monaco's Trusted
 * Types path from handing raw strings to the DOM. The advisory's actual
 * blast radius is HTML that *this* client deliberately does not render.
 * Re-checked when Monaco ships 3.4.16.
 *
 * ## The tree is version-stamped, and that is a security property
 *
 * Staged at `vendor/monaco/<version>/vs`, and `loom-http` promises that
 * directory's contents are frozen for a year (`Cache-Control: immutable`,
 * OBI-338) -- which is the only way 21.9 MB of editor stops being paid on
 * every IDE load. The promise is only sound while the URL changes whenever
 * the bytes do, so the version is *in* the URL.
 *
 * That makes the served documents carry a version literal (`ide.html`'s two
 * references and `src/ide/amd-boot.ts`'s `paths.vs`), and a literal that can
 * drift from the pin is a bug worth a gate rather than a convention: this
 * script refuses to stage unless every reference it finds in those files
 * names the version being staged. Bumping `monaco-editor` in
 * `package.json` then means editing two source lines, in the same commit,
 * or `npm run build` -- and with it CI and the image build -- fails with the
 * file and the stale path named. The alternative (a `vendor/monaco/vs`
 * symlink or a generated HTML file) would either move a *year*-cached URL
 * under a new version's feet or make a served document a build artifact.
 */

import {
  cpSync,
  existsSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
} from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const webClient = join(root, "web-client");
const pkgDir = join(webClient, "node_modules", "monaco-editor");
const srcRoot = join(pkgDir, "min", "vs");

/** Top-level directories under `min/vs` that the default (English, `en`)
 * build never fetches. See the header comment for why nothing else is
 * pruned. */
const SKIP_TOP_LEVEL = new Set(["nls"]);

/** The entry points the boot sequence and `ide.html` name directly. A
 * layout change upstream must fail *here*, in CI, rather than as a blank
 * editor in a staff browser. */
const REQUIRED = [
  "loader.js",
  "editor/editor.main.js",
  "editor/editor.main.css",
];

/** Monaco is MIT and ships its own third-party notices. Both belong
 * beside the code in the image, not just in `node_modules` of whoever
 * ran the build; `npm run check-licenses` audits the dependency, this
 * makes the shipped artifact carry the same paperwork. Beside it
 * literally here: inside the stamped directory, so the notices travel
 * with the bytes they describe. */
const NOTICES = ["LICENSE", "ThirdPartyNotices.txt"];

/** The served files that name a path into the vendored tree, relative to
 * `web-client/`. Each one must reference exactly the version being staged;
 * see `unpinnedRefs` and the header comment. */
const REFERENCED_BY = ["ide.html", "src/ide/amd-boot.ts"];

/** The URL prefix `web-client` is served from -- the one place that spells
 * it out, so the drift gate and the served documents cannot disagree about
 * what they are checking. */
export function vendorPrefix(version) {
  return `vendor/monaco/${version}`;
}

/**
 * The `<segment>` of every `vendor/monaco/<segment>` mention in `text` --
 * a version when the mention is stamped, anything else (`vs`, `latest`,
 * the empty string of a bare directory mention) when it is not.
 *
 * Quotation marks and backticks end a mention so that a prose reference in
 * a comment is read the same way as an attribute or a string literal.
 */
export function monacoVendorRefs(text) {
  return [...text.matchAll(/vendor\/monaco\/([^/?#\s"'`)\]]*)/g)].map((match) => match[1]);
}

/**
 * Why `text` does not point only at the stamped path for `version`, as a
 * list of human-readable problems -- empty when it does.
 *
 * Both directions are errors, for the same reason: a reference to a
 * directory that is not staged is a 404 in a staff browser, and no
 * reference at all means the gate is checking a file that stopped naming
 * the tree. Pure, so a test can drive it with fixtures instead of a
 * fixture-shaped repository.
 */
export function unpinnedRefs(text, version) {
  const refs = [...new Set(monacoVendorRefs(text))];
  const problems = [];
  if (!refs.includes(version)) {
    problems.push(`no reference to ${mention(version)}`);
  }
  for (const ref of refs) {
    if (ref !== version) {
      problems.push(`references ${mention(ref)} (not ${version})`);
    }
  }
  return problems;
}

/** A mention as it is written in the served file: `vendor/monaco/<ref>/`,
 * collapsing the doubled slash of a mention that named only the directory. */
function mention(ref) {
  return `${vendorPrefix(ref).replace(/\/+$/, "")}/`;
}

function fail(message) {
  console.error(`vendor-monaco: ${message}`);
  process.exit(1);
}

export function stage() {
  if (!existsSync(join(pkgDir, "package.json"))) {
    fail(
      "monaco-editor is not installed. Run `npm ci` first -- this script " +
        "copies from node_modules, it never downloads anything.",
    );
  }

  // The version copied must be the version the lockfile pinned, or a build
  // would serve a Monaco other than the one `npm audit` and the licence
  // gate looked at. `npm ci` guarantees this by construction; the check is
  // here so a hand-run `npm install monaco-editor@newer` without a
  // matching package.json change gets caught.
  const installed = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8")).version;
  const declared = JSON.parse(readFileSync(join(webClient, "package.json"), "utf8"))
    .dependencies?.["monaco-editor"];
  if (declared !== installed) {
    fail(
      `web-client/package.json pins monaco-editor ${JSON.stringify(declared)} ` +
        `but node_modules has ${installed}. Reconcile the pin and the lockfile.`,
    );
  }

  for (const rel of REQUIRED) {
    if (!existsSync(join(srcRoot, rel))) {
      fail(`expected entry point min/vs/${rel} is missing in ${installed}`);
    }
  }

  // The gate on the URL contract (see the header comment): the version in
  // the served documents must be the version about to be staged, because
  // `loom-http` promises the stamped directory's bytes for a year.
  for (const rel of REFERENCED_BY) {
    const file = join(webClient, rel);
    if (!existsSync(file)) {
      fail(`${rel} is gone; if the file that names the vendored tree moved, update REFERENCED_BY here`);
    }
    const problems = unpinnedRefs(readFileSync(file, "utf8"), installed);
    if (problems.length > 0) {
      fail(
        `${rel} does not match monaco-editor ${installed}:\n  - ` +
          problems.join("\n  - ") +
          `\nEvery reference must be ${mention(installed)} -- that stamp is what makes\n` +
          `the immutable cache entry safe, so a bump edits these files too.`,
      );
    }
  }

  // The whole tree is restaged, so the only version directories that exist
  // are the one the pin names: a stale `vendor/monaco/<older>/` left behind
  // would still be reachable, still be served `immutable`, and still be in
  // the image -- 21.9 MB at a time.
  const monacoDir = join(webClient, "vendor", "monaco");
  const destRoot = join(monacoDir, installed, "vs");
  rmSync(monacoDir, { recursive: true, force: true });
  for (const entry of readdirSync(srcRoot)) {
    if (SKIP_TOP_LEVEL.has(entry)) continue;
    cpSync(join(srcRoot, entry), join(destRoot, entry), { recursive: true });
  }
  for (const notice of NOTICES) {
    if (existsSync(join(pkgDir, notice))) {
      cpSync(join(pkgDir, notice), join(monacoDir, installed, notice));
    }
  }

  const bytes = directoryBytes(destRoot);
  console.log(
    `vendor-monaco: staged monaco-editor ${installed} -> ` +
      `${relative(root, destRoot)} (${(bytes / 1024 / 1024).toFixed(1)} MB)`,
  );
  return { version: installed, bytes };
}

function directoryBytes(dir) {
  let total = 0;
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    total += statSync(full).isDirectory() ? directoryBytes(full) : statSync(full).size;
  }
  return total;
}

const invokedDirectly =
  process.argv[1] !== undefined &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  stage();
}
