// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * `ide.html`'s entry module (OBI-180 M-IDE-4/M-IDE-5). Auth gate, then
 * mount. Kept apart from the controller (`./app.ts`) so the controller
 * stays testable without a session, and apart from Monaco's AMD load
 * (`./amd-boot.ts`) so this file is a normal ES module.
 *
 * Sign-in reuses the admin page's `renderSignInPage` (OBI-235, PR #101):
 * the same `POST /auth/login` step-up round trip, the same TOTP field,
 * the same DOM-safe form. An IDE login *is* a staff login -- there is no
 * second credential, and therefore no second place to get M-AUTH-2's
 * rate limiting or T-IDE-7's session isolation wrong.
 *
 * The access token lives in `sessionStorage` via the same `TokenStore`
 * the admin pages use (OBI-297: never in a cookie JS can read, and not in
 * `localStorage`, so it does not outlive the tab that minted it). The
 * refresh token never reaches JS at all -- it is the
 * `__Host-loom_rt` HttpOnly cookie, which `AdminApi.requestRaw` rides for
 * a silent re-auth when the 10-minute access token expires mid-edit.
 */

import { AdminApi } from "../admin/api.js";
import { renderSignInPage } from "../admin/pages/signin.js";
import { storageTokenStore } from "../admin/tokenstore.js";
import { el } from "../admin/dom.js";
import { FilesApi } from "./files-api.js";
import { LoomIde, type IdeDom } from "./app.js";
import { createMonacoEditor } from "./editor.js";
import { bridgeForSession } from "./lsp-bridge.js";
import type { LspHooks } from "./lsp-bridge.js";
import { registerLspProviders } from "./lsp-monaco.js";
import { browserSocketOpener, fetchWsTicket, lspSocketUrl } from "./lsp-transport.js";

/** The AMD global `./amd-boot.ts` waited for. Typed as the same narrow
 * surface `./editor.ts` uses -- it is passed straight through. */
type MonacoGlobal = Parameters<typeof createMonacoEditor>[0]["monaco"];

function required<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (node === null) {
    throw new Error(`ide.html is missing #${id}`);
  }
  return node as T;
}

function ideDom(): IdeDom {
  return {
    tree: required("ide-tree"),
    editor: required("ide-editor"),
    diagnostics: required("ide-diagnostics"),
    status: required("ide-status"),
    pathLabel: required("ide-path"),
    saveButton: required<HTMLButtonElement>("ide-save"),
  };
}

/** The auth seam: an `AdminApi` over the session store, and the file
 * client on top of it. */
function buildApi(tokens: ReturnType<typeof storageTokenStore>) {
  const admin = new AdminApi({
    baseUrl: "",
    getAccessToken: () => tokens.get(),
    setAccessToken: (token) => tokens.set(token),
  });
  return { admin, files: new FilesApi(admin) };
}

export function mountIde(monaco: MonacoGlobal): void {
  // `#ide-auth` is the sign-in gate's own container in `ide.html`; the
  // rest of the page is inert until it is gone, because the tree's very
  // first request is one the token has to authorise.
  const auth = required("ide-auth");
  const dom = ideDom();
  const tokens = storageTokenStore(window.sessionStorage);
  const { admin, files } = buildApi(tokens);

  const signout = required<HTMLButtonElement>("ide-signout");
  signout.disabled = tokens.get() === null;
  signout.addEventListener("click", () => {
    void (async () => {
      await admin.logout();
      tokens.clear();
      window.location.reload();
    })();
  });

  const showSignedIn = (): void => {
    auth.remove();
    const editor = createMonacoEditor({ monaco, container: dom.editor, onSave: () => {} });
    // Live analysis (OBI-180): one socket, one synced document, and a bridge
    // that decides what `loom-lsp` is told and when. Every part of it is
    // optional -- `lspSocketUrl` answers null for an origin that cannot hold a
    // WebSocket, and that path is the same IDE minus the squiggles, because
    // the save-compile round trip in `./app.ts` remains the authoritative one.
    let lsp: LspHooks | undefined;
    const socketUrl = lspSocketUrl(window.location.href);
    if (socketUrl !== null) {
      const bridge = bridgeForSession(
        {
          url: socketUrl,
          openSocket: browserSocketOpener,
          getTicket: () => fetchWsTicket(admin),
          clientInfo: { name: "loom-ide", version: "dev" },
        },
        {
          // The analyser's squiggles get their own marker owner. A save's
          // compile result is the driver's answer about the file on disk and
          // lands under `loom-ide`; these are the analyser's answer about the
          // text on screen, and neither may erase the other (M-IDE-5).
          setMarkers: (_path, markers) => editor.setMarkers(markers, "loom-lsp"),
          // The status label belongs to the controller; the bridge only
          // writes it when live analysis stops working, and never when the
          // server closed an idle session on purpose (`./lsp-bridge.ts`).
          onStatus: (message) => {
            dom.status.textContent = message;
          },
        },
      );
      const providers = registerLspProviders(monaco, bridge.providers);
      // An object literal rather than the bridge itself, for the one line
      // below: Monaco's language features are registered per language id, not
      // per editor, so they outlive `#ide-editor` unless something disposes
      // them with it. A provider left pointing at a dead socket is the failure
      // mode where hover quietly stops working after a sign-out.
      lsp = {
        documentOpened: (path, text) => bridge.documentOpened(path, text),
        documentChanged: (path, text) => bridge.documentChanged(path, text),
        documentClosed: (path) => bridge.documentClosed(path),
        dispose: () => {
          for (const provider of providers) {
            provider.dispose();
          }
          bridge.dispose();
        },
      };
    }
    const ide = new LoomIde({ files, editor, dom, lsp });
    ide.start();
  };

  if (tokens.get() === null) {
    renderSignInPage(auth, admin, tokens, showSignedIn);
    return;
  }
  showSignedIn();
}

/** A visible, text-only error rather than a blank pane: the most likely
 * failures here are a 404 on the vendored Monaco tree (a build that ran
 * `npm run build` without `npm run vendor`) or a CSP refusal, and both
 * look identical to a builder who has never seen the console. */
function mountBootFailure(message: string): void {
  const container = document.getElementById("ide-editor");
  if (container === null) {
    return;
  }
  container.append(
    el("div", { class: "ide-boot-failure" }, [
      el("h2", {}, ["The IDE failed to start"]),
      el("p", {}, [message]),
      el("p", { class: "ide-note" }, [
        "This page loads Monaco from /vendor/monaco/vs on this origin. A 404 there means the web root was built without `npm run vendor`.",
      ]),
    ]),
  );
}

export { mountBootFailure };
