// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The one non-module script in the web client, and the reason `ide.html`
 * can hold `script-src 'self'` while Monaco's AMD build stays un-imported
 * (OBI-180 M-IDE-1/M-IDE-3).
 *
 * Written as a classic script (no `import`/`export` statement, so
 * `tsc` emits it as a plain file, not an ES module), because that is what
 * the vendored `vs/loader.js` is: an AMD loader that registers modules
 * into `window.monaco` and has no ESM entry point. `ide.html` loads
 * `loader.js` first, then this module, and this module's only job is to
 * sequence the two worlds: wait for the AMD `vs/editor/editor.main`
 * module, then hand control to the ES module app (`./main.js`).
 *
 * `paths.vs` is relative (`vendor/monaco/vs`) so it resolves against the
 * page's own URL and never away from this origin -- there is no host name
 * in this file for someone to later point at a CDN (M-IDE-3), and
 * `scripts/check-static-csp.mjs` fails CI if the page itself grows an
 * off-origin reference.
 *
 * Monaco's language services run in a worker it creates from a `blob:`
 * URL; that is what the document's `worker-src 'self' blob:` grants, and
 * nothing here configures a worker URL, so the worker's own script
 * resolves inside the same `vs` tree.
 */

interface AmdRequire {
  config(options: { paths: Record<string, string> }): void;
  (dependencies: string[], callback: (error?: unknown) => void): void;
}

/** Read off `globalThis` rather than declared as a bare global:
 * `@types/node` is in this project's type graph (the tests run under
 * Node), and a top-level `declare const require` would collide with its
 * `NodeRequire`. The AMD loader installs `require` as a global property,
 * which in a browser *is* `globalThis.require` -- this reads the same
 * object the loader wrote without declaring a second global. */
interface AmdGlobal {
  readonly require?: AmdRequire;
}

const MONACO_AMD_MODULE = "vs/editor/editor.main";

function bootFailure(message: string): void {
  // Inlined rather than imported from `./main.js`: if the AMD module never
  // loads, that module has not been fetched either, and a builder looking
  // at a blank page learns nothing.
  const container = document.getElementById("ide-editor");
  if (container === null) {
    return;
  }
  const heading = document.createElement("h2");
  heading.textContent = "The IDE failed to start";
  const detail = document.createElement("p");
  detail.textContent = message;
  container.append(heading, detail);
}

function start(): void {
  const require = (globalThis as unknown as AmdGlobal).require;
  if (typeof require !== "function") {
    bootFailure(
      "Monaco's AMD loader (vendor/monaco/vs/loader.js) did not load. " +
        "The web root was probably built without `npm run vendor`.",
    );
    return;
  }
  require.config({ paths: { vs: "vendor/monaco/vs" } });
  require([MONACO_AMD_MODULE], (error?: unknown) => {
    if (error !== undefined) {
      bootFailure(`Loading ${MONACO_AMD_MODULE} failed: ${String(error)}`);
      return;
    }
    const monaco = (globalThis as { monaco?: unknown }).monaco;
    if (monaco === undefined) {
      bootFailure(`${MONACO_AMD_MODULE} loaded but window.monaco is not set.`);
      return;
    }
    void import("./main.js")
      .then((app) => app.mountIde(monaco as Parameters<typeof app.mountIde>[0]))
      .catch((err: unknown) => {
        bootFailure(`The IDE app failed to start: ${String(err)}`);
      });
  });
}

start();
