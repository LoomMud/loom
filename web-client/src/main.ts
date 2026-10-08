// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The player client's bootstrap (OBI-180 M-IDE-1), in a file instead of
 * an inline `<script type="module">` in `index.html`.
 *
 * That is the whole reason this module exists: `loom-http` stamps
 * `script-src 'self'` on the static bundle (M-IDE-1's CSP, threat model
 * v2 §5), and an inline script would be blocked by it. The `<meta>` copy
 * of the policy in `index.html` says the same thing, so the page is
 * still held to it if a deployment ever serves the bundle without
 * loom-http in front.
 *
 * The URL is derived from `location` -- same-origin, always over the
 * protocol the page was loaded with -- because `connect-src 'self'`
 * allows exactly that and nothing else.
 */

import { mountLoomClient } from "./app.js";

/** The player WebSocket's URL for the page's own origin (`/ws`, OBI-39). */
export function playerWsUrl(loc: Location): string {
  return `${loc.protocol === "https:" ? "wss" : "ws"}://${loc.host}/ws`;
}

function required<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) {
    throw new Error(`index.html is missing #${id}`);
  }
  return el as T;
}

const pane = required<HTMLDivElement>("pane");
const input = required<HTMLInputElement>("input");

mountLoomClient({
  pane,
  input,
  wsUrl: playerWsUrl(window.location),
});
