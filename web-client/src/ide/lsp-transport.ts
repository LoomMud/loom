// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The browser half of the `/lsp` connection (OBI-180 M-LSP-1, D-TM4).
 *
 * The only LSP module that names `WebSocket`, `window.location`, or the
 * ticket route, which is why it is a separate file: everything else in the
 * client is transport-independent and runs under `node:test` against a fake
 * socket. Two decisions live here and nowhere else:
 *
 * - **The URL is same-origin, derived from the page.** `wss://<this host>/lsp`
 *   over `https:` (and `ws://` only for a `http:` page, which is what
 *   `loom-http` serves in development). There is no configured LSP host: a
 *   socket to a host someone else chose would carry the ticket -- and with it
 *   the session's authority -- somewhere the CSP never intended, and
 *   `connect-src` in `loom-http`'s header is pinned to the request's own
 *   `Host` for exactly this reason. A page whose origin is not `https:` and
 *   not loopback `http:` gets `null` rather than a mixed-content socket the
 *   browser would refuse.
 * - **The ticket is fetched per connect, never reused.** It is single-use
 *   with a 30 s TTL server-side, so caching it would be caching a credential
 *   for nothing. `getTicket` is called from inside `LspSession.connect`, which
 *   is the only place a connect happens.
 */

import type { AdminApi } from "../admin/api.js";
import type { SessionSocket, SocketOpener } from "./lsp-session.js";

/** The path `loom-http` mounts the LSP bridge on. */
export const LSP_PATH = "/lsp";

/** The route that mints a single-use ticket for it
 * (`crates/loom-http/src/handlers.rs::ws_ticket`). */
export const WS_TICKET_PATH = "/api/v1/ws-ticket";

/** The WebSocket URL for the current page, or `null` when the page's origin
 * cannot host one (a `file:` page, or any non-secure, non-loopback host). */
export function lspSocketUrl(href: string): string | null {
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return null;
  }
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    return null;
  }
  const scheme = url.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${url.host}${LSP_PATH}`;
}

/** The socket events `LspSession` needs, in the shape this module fills. */
interface SocketEvents {
  onText(text: string): void;
  onClose(initiated: boolean): void;
}

/** A `WebSocket` that also works with Node's `WebSocket` global, which is what
 * the local end-to-end script uses against `loom-lsp --ws`. Only the text
 * frames are surfaced: a binary frame is not something this protocol sends or
 * accepts, so it is dropped rather than decoded. */
export function openWebSocket(url: string, events: SocketEvents): Promise<SessionSocket> {
  return new Promise((resolve, reject) => {
    const Factory = (globalThis as { WebSocket?: typeof WebSocket }).WebSocket;
    if (typeof Factory !== "function") {
      reject(new Error("this runtime has no WebSocket, so live analysis is unavailable"));
      return;
    }
    let socket: WebSocket;
    try {
      socket = new Factory(url);
    } catch (error) {
      reject(error instanceof Error ? error : new Error(String(error)));
      return;
    }
    let initiated = false;
    const handle = (event: { data?: unknown }): void => {
      if (typeof event.data === "string") {
        events.onText(event.data);
      }
    };
    socket.addEventListener("open", () => {
      resolve({
        send(text: string) {
          socket.send(text);
        },
        close() {
          initiated = true;
          socket.close();
        },
      });
    });
    socket.addEventListener("message", handle);
    socket.addEventListener("error", () => {
      if (!initiated) {
        reject(new Error("the /lsp socket failed"));
      }
    });
    socket.addEventListener("close", () => {
      if (!initiated) {
        reject(new Error("the /lsp socket closed before it opened"));
      }
      events.onClose(initiated);
    });
  });
}

/** The socket opener the session is handed in the page. */
export const browserSocketOpener: SocketOpener = (url, events) => openWebSocket(url, events);

/**
 * Mint a ticket. Throws when there is no token, when the driver refuses, or
 * when the body has no ticket in it -- all of which `LspSession` reports as a
 * connection failure and turns into a status line, never into a retry storm
 * (the failure increments the same bounded counter a dead socket does).
 */
export async function fetchWsTicket(
  http: Pick<AdminApi, "requestRaw">,
  path: string = WS_TICKET_PATH,
): Promise<string> {
  const response = await http.requestRaw(path, { method: "POST" });
  if (!response.ok) {
    throw new Error(`ws-ticket returned HTTP ${response.status}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(response.body) as unknown;
  } catch {
    throw new Error("ws-ticket returned a body that is not JSON");
  }
  const ticket = (parsed as Record<string, unknown>)["ticket"];
  if (typeof ticket !== "string" || ticket === "") {
    throw new Error("ws-ticket returned no ticket");
  }
  return ticket;
}
