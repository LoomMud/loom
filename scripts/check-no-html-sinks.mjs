#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * M-IDE-1/M-IDE-2 (OBI-179 threat model, OBI-235 acceptance): fails if
 * any `web-client/src/**` file uses an HTML sink -- `innerHTML`,
 * `outerHTML`, `insertAdjacentHTML`, or `document.write`. Every admin
 * page renders staff-/driver-controlled strings (who names, audit rows,
 * error messages, broadcast text) through `src/admin/dom.ts`'s
 * `createElement`/`textContent` helpers instead; this script is the
 * enforcement that stays true, run from `npm run lint` and in CI,
 * rather than a one-time manual review note that can silently rot.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// Any mention of these is a violation (assignment, `+=`, or read-then-
// write): the admin UI has no legitimate use for any of them.
const SINKS = [
  /\binnerHTML\b/,
  /\bouterHTML\b/,
  /\binsertAdjacentHTML\b/,
  /\bdocument\.write(ln)?\s*\(/,
  /\bcreateContextualFragment\b/,
  /\bDOMParser\b/,
  /\bsrcdoc\b/,
  /\beval\s*\(/,
  /\bnew\s+Function\s*\(/,
  /setAttribute\(\s*["'`]on/i,
];

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      out.push(...walk(full));
    } else if (/\.(ts|tsx|js)$/.test(entry) && !entry.endsWith(".test.js") && !entry.endsWith(".test.ts")) {
      out.push(full);
    }
  }
  return out;
}

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..", "web-client", "src");
let violations = 0;

for (const file of walk(root)) {
  // Strip comments (keeping line numbers) so doc comments that *name*
  // the banned sinks don't trip the check.
  const text = readFileSync(file, "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, (block) => block.replace(/[^\n]/g, " "))
    .replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
  const lines = text.split("\n");
  lines.forEach((line, i) => {
    for (const sink of SINKS) {
      if (sink.test(line)) {
        console.error(`${file}:${i + 1}: HTML sink found: ${line.trim()}`);
        violations += 1;
      }
    }
  });
}

if (violations > 0) {
  console.error(`\n${violations} HTML sink violation(s) found (M-IDE-1/M-IDE-2).`);
  process.exit(1);
}

console.log("no-html-sinks: clean");
