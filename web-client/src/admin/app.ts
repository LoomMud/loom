// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import { AdminApi } from "./api.js";
import { clear, el } from "./dom.js";
import { renderAuditPage } from "./pages/audit.js";
import { renderBroadcastPage } from "./pages/broadcast.js";
import { renderErrorsPage } from "./pages/errors.js";
import { renderObjectsPage } from "./pages/objects.js";
import { renderRolesPage } from "./pages/roles.js";
import { renderSignInPage } from "./pages/signin.js";
import { renderWhoPage } from "./pages/who.js";
import { decodeAccessToken } from "./stepup.js";
import type { TokenStore } from "./tokenstore.js";

/** How long before an access token's `exp` to fire the proactive silent
 * refresh (OBI-297) -- comfortably inside the 10-minute access-token
 * lifetime (D-TM2) so the refresh round-trip has room to finish before
 * the token staff are mid-request with actually expires. Reactive
 * refresh-on-401 (`AdminApi.request`) is the backstop if this timer is
 * ever late (a sleeping laptop, a slow network) or simply didn't fire. */
const PROACTIVE_REFRESH_SKEW_SECS = 60;

/** Keeps one `setTimeout` alive that fires a silent `/auth/refresh`
 * shortly before the current access token expires, and reschedules
 * itself off the *new* token's `exp` after every successful refresh.
 * Stops rescheduling (rather than looping forever) the moment there's no
 * token or refresh fails -- a dead/revoked/logged-out session just lets
 * the next 401 (or the sign-in page) take over. Returns a `stop()` so
 * `mountAdminApp` can tear the timer down if it's ever re-mounted.
 *
 * `mountAdminApp`'s `route()` calls this on *every* hash change, not
 * just once at mount -- harmless (it always `stop()`s the previous timer
 * first, so there's never more than one live), but worth knowing if
 * you're tracing why this runs more than once per page load. One gap
 * this doesn't close: after a step-up re-login swaps in a fresh token
 * (`stepup-modal.ts`), this timer is still counting down to the *old*
 * token's `exp` until the next hash change reschedules it. Harmless in
 * practice -- `AdminApi.request`'s refresh-on-401 covers the gap if the
 * old timer fires too late -- but it means the proactive refresh isn't
 * always keyed to the token actually in use. */
function scheduleProactiveRefresh(api: AdminApi, tokens: TokenStore): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined;

  const schedule = () => {
    const token = tokens.get();
    if (token === null) {
      return;
    }
    const claims = decodeAccessToken(token);
    if (claims === null) {
      return;
    }
    const nowSecs = Math.floor(Date.now() / 1000);
    const delayMs = Math.max(0, (claims.exp - PROACTIVE_REFRESH_SKEW_SECS - nowSecs) * 1000);
    timer = setTimeout(() => {
      void (async () => {
        if (await api.refresh()) {
          schedule();
        }
      })();
    }, delayMs);
  };

  schedule();
  return () => {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  };
}

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
    setAccessToken: root.tokens.set,
  });
  let stopProactiveRefresh: (() => void) | undefined;

  const renderNav = () => {
    clear(root.nav);
    if (root.tokens.get() === null) {
      return;
    }
    for (const page of PAGES) {
      const link = el("a", { href: `#/${page.name}` }, [page.label]);
      root.nav.append(link, el("span", {}, [" "]));
    }
    const signOut = el("button", { type: "button", class: "signout" }, [
      `Sign out (${root.tokens.username() ?? "?"})`,
    ]);
    signOut.addEventListener("click", () => {
      void (async () => {
        await api.logout();
        stopProactiveRefresh?.();
        root.tokens.clear();
        route();
      })();
    });
    root.nav.append(signOut);
  };

  const route = () => {
    renderNav();
    if (root.tokens.get() === null) {
      renderSignInPage(root.main, api, root.tokens, route);
      return;
    }
    stopProactiveRefresh?.();
    stopProactiveRefresh = scheduleProactiveRefresh(api, root.tokens);
    render(pageFromHash(location.hash));
  };

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

  window.addEventListener("hashchange", route);
  route();
}
