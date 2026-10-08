#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * M-IDE-1/M-IDE-3 gate (OBI-179 threat model v2 §5, OBI-180): the
 * documents `loom-http` serves must not grow an escape hatch back into
 * the CSP it stamps on them.
 *
 * `loom-http`'s `STATIC_CSP` gives the static bundle `script-src 'self'`
 * with exactly two documented exceptions for Monaco (`style-src
 * 'unsafe-inline'`, `worker-src blob:`). Those exceptions are only
 * exceptions *for Monaco*. A page that gains an inline `<script>`, an
 * `on*=` handler, or a CDN reference would either be blocked by the
 * policy (broken page, noticed in staging) or -- if someone "fixed" that
 * by relaxing the header -- turn the whole staff origin into an
 * XSS-amplifier, since that origin carries a live session cookie. This
 * script makes the relaxed-header option unavailable by making the
 * offending document the thing CI fails.
 *
 * What it enforces on every served document (every `.html` under
 * ignoring the vendored Monaco tree):
 *   1. no inline `<script>` -- every script has `src` (M-IDE-1).
 *   2. no `<style>` element and no inline `style=` attribute (M-IDE-1).
 *   3. no `on*=` event-handler attribute (M-IDE-1).
 *   4. no `src`/`href` with a scheme or protocol-relative authority --
 *      nothing is fetched from a CDN, so an outage or a compromised CDN
 *      cannot take the staff tool down or into it (M-IDE-3).
 *   5. exactly one `meta http-equiv=Content-Security-Policy`, whose
 *      `script-src` is `'self'` with no `unsafe-inline` /
 *      `unsafe-eval` / wildcard (M-IDE-1) -- a `<meta>` policy is only an
 *      addition to the header (both are enforced), so this checks the
 *      page isn't *weakening* its own document with, e.g., a second
 *      policy that grants `unsafe-eval`.
 *
 * `frame-ancestors`, `sandbox`, `report-to` and friends are ignored in
 * `<meta>` per the CSP spec, so they are loom-http's job alone -- and
 * `crates/loom-http/src/lib.rs`'s `static_fallback_carries_the_m_ide_1_csp_and_header_set`
 * test covers them there.
 */

import { readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const webClientDir = join(root, "web-client");

/** Directories that are never authored source: the staged Monaco tree
 * (its own `min/vs/loader.js` et al. is third-party MIT code, checked by
 * the vendor step and the licence gate instead) and build output. */
const IGNORED_DIRS = new Set(["node_modules", "vendor", "dist"]);

/** @param {string} dir */
function htmlDocuments(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    if (IGNORED_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...htmlDocuments(full));
    } else if (entry.endsWith(".html")) {
      out.push(full);
    }
  }
  return out.sort();
}

/** Strip HTML comments so this file's own examples, and the explanatory
 * comments in the pages themselves, don't trip the textual checks. Line
 * and column positions are preserved so a reported line number is the
 * real one. */
function withoutComments(text) {
  return text.replace(/<!--[\s\S]*?-->/g, (block) => block.replace(/[^\n]/g, " "));
}

/**
 * Parse the attribute text of an opening tag -- the part *after* the tag
 * name, which every caller here gets from a capture group -- into
 * `[name, value]` pairs with lower-cased names. Values are unquoted
 * except for the surrounding quotes the regex consumed; `> ` can never
 * appear inside a captured attribute run because the tag regexes above
 * delimit on it.
 *
 * @param {string} attrText
 * @returns {[string, string][]}
 */
function attributes(attrText) {
  /** @type {[string, string][]} */
  const attrs = [];
  const re = /([a-zA-Z_:][\w:.-]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let match;
  while ((match = re.exec(attrText)) !== null) {
    attrs.push([match[1].toLowerCase(), match[2] ?? match[3] ?? match[4] ?? ""]);
  }
  return attrs;
}

const URL_CARRYING = new Set(["src", "href"]);

/** @param {string} text @param {string} path @returns {string[]} findings */
export function auditDocument(text, path) {
  const findings = [];
  const flat = withoutComments(text).replace(/\n/g, " ");
  const report = (message) => findings.push(`${path}: ${message}`);
  const attrOf = (tagText) => attributes(tagText ?? "");

  for (const tag of flat.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
    const attrs = attrOf(tag[1]);
    const src = attrs.find(([n]) => n === "src")?.[1];
    if (!src) {
      report("inline <script> body (M-IDE-1: script-src 'self' has no inline exception)");
    }
  }
  for (const tag of flat.matchAll(/<script\b([^>]*)\/?>/gi)) {
    const attrs = attrOf(tag[1]);
    const src = attrs.find(([n]) => n === "src")?.[1];
    if (src && isOffOrigin(src)) {
      report(`off-origin script src ${JSON.stringify(src)} (M-IDE-3: no CDN)`);
    }
  }

  if (/<style\b/i.test(flat)) {
    report("<style> element (M-IDE-1: styles belong in a .css file)");
  }

  for (const match of flat.matchAll(/<([a-zA-Z][\w-]*)\b([^>]*)>/g)) {
    for (const [name, value] of attrOf(match[2])) {
      if (/^on[a-z]/.test(name)) {
        report(`${match[1]} has inline handler ${name}= (M-IDE-1)`);
      }
      if (name === "style") {
        report(`${match[1]} has an inline style attribute (M-IDE-1)`);
      }
      if (URL_CARRYING.has(name) && isOffOrigin(value)) {
        report(`${match[1]} references off-origin ${name}=${JSON.stringify(value)} (M-IDE-3)`);
      }
    }
  }

  const policies = [
    ...flat.matchAll(/<meta\b([^>]*http-equiv\s*=\s*(?:"|')?content-security-policy(?:'|"|\/|>)[^>]*)>/gi),
  ];
  if (policies.length === 0) {
    report("no <meta http-equiv=\"Content-Security-Policy\"> (M-IDE-1)");
  }
  if (policies.length > 1) {
    report(`${policies.length} <meta> CSP policies -- a document is held to all of them; keep one (M-IDE-1)`);
  }
  for (const policy of policies) {
    const content = attrOf(policy[1]).find(([n]) => n === "content")?.[1] ?? "";
    const scriptSrc = /(?:^|;)\s*script-src([^;]*)/i.exec(content)?.[1]?.trim();
    if (scriptSrc === undefined) {
      report("the <meta> CSP has no script-src (M-IDE-1)");
      continue;
    }
    if (/\bunsafe-(inline|eval)\b/i.test(scriptSrc)) {
      report(`meta CSP script-src grants unsafe-inline/unsafe-eval: ${JSON.stringify(scriptSrc)}`);
    }
    if (/\*/.test(scriptSrc)) {
      report(`meta CSP script-src uses a wildcard: ${JSON.stringify(scriptSrc)}`);
    }
    if (!/'self'/.test(scriptSrc)) {
      report(`meta CSP script-src is not 'self': ${JSON.stringify(scriptSrc)}`);
    }
  }

  return findings;
}

/** A URL this document may not fetch: anything with an explicit scheme
 * (including `data:` -- images are inlined via `'self'` files or an
 * `img-src` allow-list, never a base64 blob in a served page) or a
 * protocol-relative `//host`. */
function isOffOrigin(url) {
  const trimmed = url.trim();
  if (trimmed === "") return false;
  if (/^(?:https?:|http:|ws:|wss:|data:|blob:|file:|about:|javascript:)/i.test(trimmed)) {
    return true;
  }
  return trimmed.startsWith("//");
}

/** Every served document under `web-client/`, ignoring staged/vendor and
 * build trees (exported so the test can assert the set it audits is the
 * set it thinks it is). */
export function servedDocuments(dir = webClientDir) {
  return htmlDocuments(dir);
}

// Run only as a CLI: `check-static-csp.test.mjs` imports the audit above
// to test the rules themselves without tripping on this repo's own
// documents.
const invokedDirectly =
  process.argv[1] !== undefined &&
  realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));

if (invokedDirectly) {
  process.exit(main());
}

function main() {
  const files = servedDocuments();
  if (files.length === 0) {
    console.error(`check-static-csp: no documents found under ${relative(root, webClientDir)}`);
    return 1;
  }

  let violations = 0;
  for (const file of files) {
    const findings = auditDocument(readFileSync(file, "utf8"), relative(root, file));
    for (const finding of findings) {
      console.error(finding);
      violations += 1;
    }
  }

  if (violations > 0) {
    console.error(`\ncheck-static-csp: ${violations} violation(s) in ${files.length} document(s).`);
    return 1;
  }
  console.log(`check-static-csp: ${files.length} document(s) clean`);
  return 0;
}
