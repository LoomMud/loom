// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * `admin.html`'s entry module. Lives in its own file (not an inline
 * `<script>`) because the admin CSP is `script-src 'self'` with no
 * `'unsafe-inline'`/nonce -- an inline boot script would be blocked and
 * the page would never mount (M-IDE-1/M-IDE-2).
 */

import { mountAdminApp } from "./app.js";
import { storageTokenStore } from "./tokenstore.js";

function byId(id: string): HTMLElement {
  const node = document.getElementById(id);
  if (node === null) {
    throw new Error(`admin.html is missing #${id}`);
  }
  return node;
}

mountAdminApp({
  nav: byId("admin-nav"),
  main: byId("admin-main"),
  modal: byId("admin-modal"),
  baseUrl: "",
  tokens: storageTokenStore(window.sessionStorage),
});
