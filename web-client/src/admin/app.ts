// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import { AdminApi } from "./api.js";
import { clear, el } from "./dom.js";
import { renderAuditPage } from "./pages/audit.js";
import { renderBroadcastPage } from "./pages/broadcast.js";
import { renderErrorsPage } from "./pages/errors.js";
import { renderObjectsPage } from "./pages/objects.js";
import { renderRolesPage } from "./pages/roles.js";
import { renderWhoPage } from "./pages/who.js";
import type { TokenStore } from "./tokenstore.js";

export type AdminPageName = "who" | "objects" | "errors" | "roles" | "audit" | "broadcast";

const PAGES: { name: AdminPageName; label: string }[] = [
  { name: "who", label: "Who" },
  { name: "objects", label: "Objects" },
  { name: "errors", label: "Errors" },
  { name: "roles", label: "Roles" },
  { name: "audit", label: "Audit" },
  { name: "broadcast", label: "Broadcast" },
];

export function pageFromHash(hash: string): AdminPageName {
  const name = hash.replace(/^#\/?/, "");
  const match = PAGES.find((p) => p.name === name);
  return match?.name ?? "who";
}

/**
 * Mounts the whole admin app: a nav bar, a `<main>` content region this
 * module clears and re-renders on every hash change, and a modal root
 * that `./stepup-modal.ts` shows into for step-up-gated pages. Routing
 * is `location.hash`-based (no server-side routes to configure, no
 * history-API edge cases to handle for a small staff tool).
 */
export function mountAdminApp(root: {
  nav: HTMLElement;
  main: HTMLElement;
  modal: HTMLElement;
  baseUrl: string;
  tokens: TokenStore;
}): void {
  const api = new AdminApi({
    baseUrl: root.baseUrl,
    getAccessToken: root.tokens.get,
  });

  clear(root.nav);
  for (const page of PAGES) {
    const link = el("a", { href: `#/${page.name}` }, [page.label]);
    root.nav.append(link, el("span", {}, [" "]));
  }

  const render = (name: AdminPageName) => {
    switch (name) {
      case "who":
        void renderWhoPage(root.main, api);
        break;
      case "objects":
        void renderObjectsPage(root.main, api);
        break;
      case "errors":
        void renderErrorsPage(root.main, api);
        break;
      case "roles":
        renderRolesPage(root.main, api, root.tokens, root.modal);
        break;
      case "audit":
        void renderAuditPage(root.main, api);
        break;
      case "broadcast":
        renderBroadcastPage(root.main, api, root.tokens, root.modal);
        break;
    }
  };

  window.addEventListener("hashchange", () => render(pageFromHash(location.hash)));
  render(pageFromHash(location.hash));
}
