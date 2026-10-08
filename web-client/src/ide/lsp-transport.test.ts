// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import test from "node:test";
import assert from "node:assert/strict";

import type { AdminApi } from "../admin/api.js";
import {
  LSP_PATH,
  WS_TICKET_PATH,
  browserSocketOpener,
  fetchWsTicket,
  lspSocketUrl,
  openWebSocket,
} from "./lsp-transport.js";

/** `node --test` has a real `WebSocket` global in current Node, so the
 * transport is exercised against an injected stand-in and restored afterwards.
 * The fake is deliberately event-listener shaped: that is the subset of the
 * browser API `openWebSocket` uses, and it is also what Node's own `WebSocket`
 * implements, which is what `scripts/mcp-bridge.mjs` runs against. */
class FakeSocket {
  static instances: FakeSocket[] = [];
  readonly url: string;
  readyState = 0;
  readonly sent: string[] = [];
  private readonly listeners = new Map<string, ((event: never) => void)[]>();

  constructor(url: string) {
    this.url = url;
    FakeSocket.instances.push(this);
  }

  addEventListener(type: string, listener: (event: never) => void): void {
    const existing = this.listeners.get(type) ?? [];
    existing.push(listener);
    this.listeners.set(type, existing);
  }

  send(data: string): void {
    this.sent.push(data);
  }

  close(): void {
    // The browser's order: CLOSE arrives as a `close` event, and `readyState`
    // is 3 by the time listeners run.
    this.readyState = 3;
    this.dispatch("close", {});
  }

  dispatch(type: string, event: unknown): void {
    for (const listener of this.listeners.get(type) ?? []) {
      listener(event as never);
    }
  }

  fireOpen(): void {
    this.readyState = 1;
    this.dispatch("open", {});
  }

  fireMessage(data: unknown): void {
    this.dispatch("message", { data });
  }
}

function withWebSocket<T>(factory: unknown, run: () => Promise<T>): Promise<T> {
  const saved = (globalThis as { WebSocket?: unknown }).WebSocket;
  FakeSocket.instances = [];
  (globalThis as { WebSocket?: unknown }).WebSocket = factory;
  return run().finally(() => {
    (globalThis as { WebSocket?: unknown }).WebSocket = saved;
  });
}

test("the socket URL is derived from the page origin, never from configuration", () => {
  // The CSP pins `connect-src` to the host the page was actually served from,
  // so a URL built from a configurable string could carry the one-time ticket
  // somewhere the document was never granted to talk to.
  assert.equal(lspSocketUrl("https://mud.example/ide.html"), `wss://mud.example${LSP_PATH}`);
  assert.equal(lspSocketUrl("https://staging.oberfield.net/"), "wss://staging.oberfield.net/lsp");
  // A loopback http page may open a plain ws socket; a remote one may not.
  assert.equal(lspSocketUrl("http://localhost:5173/ide.html"), "ws://localhost:5173/lsp");
  assert.equal(lspSocketUrl("http://127.0.0.1:5173/"), "ws://127.0.0.1:5173/lsp");
  assert.equal(lspSocketUrl("http://[::1]:3000/"), "ws://[::1]:3000/lsp");
  assert.equal(lspSocketUrl("http://mud.example/ide.html"), null);
  assert.equal(lspSocketUrl("file:///home/builder/ide.html"), null);
  assert.equal(lspSocketUrl("not a url"), null);
});

test("a ticket is fetched with the session credential and no body", async () => {
  const calls: [string, RequestInit | undefined][] = [];
  const http: Pick<AdminApi, "requestRaw"> = {
    requestRaw: async (path: string, init?: RequestInit) => {
      calls.push([path, init]);
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        body: JSON.stringify({ ticket: "t-1", expires_in: 5 }),
      };
    },
  };
  assert.equal(await fetchWsTicket(http), "t-1");
  assert.equal(calls[0]?.[0], WS_TICKET_PATH);
  assert.equal(calls[0]?.[1]?.method, "POST");
  assert.equal(calls[0]?.[1]?.body, undefined, "the ticket request has no body to forge");

  // The default path is the only path: there is no second ticket route, and a
  // caller that could name one could send a token anywhere `AdminApi` can
  // reach.
  assert.equal(await fetchWsTicket(http, "/api/v1/ws-ticket"), "t-1");
});

test("a ticket response without a ticket is an error, not an undefined auth frame", async () => {
  // Handing back `undefined` would put `{"auth":null}` on the wire, the server
  // would drop the socket, and the builder would read "the analyzer failed"
  // when what failed was the auth handoff.
  const empty: Pick<AdminApi, "requestRaw"> = {
    requestRaw: async () => ({ ok: true, status: 200, headers: new Headers(), body: "{}" }),
  };
  await assert.rejects(() => fetchWsTicket(empty), /no ticket/);

  const refused: Pick<AdminApi, "requestRaw"> = {
    requestRaw: async () => ({ ok: false, status: 401, headers: new Headers(), body: "" }),
  };
  await assert.rejects(() => fetchWsTicket(refused), /401/);

  const junk: Pick<AdminApi, "requestRaw"> = {
    requestRaw: async () => ({ ok: true, status: 200, headers: new Headers(), body: "<html>" }),
  };
  await assert.rejects(() => fetchWsTicket(junk), /not JSON/);
});

test("an open socket is handed to the session and text frames reach onText", async () => {
  await withWebSocket(FakeSocket, async () => {
    const texts: string[] = [];
    const closes: boolean[] = [];
    // The promise executor constructs the socket synchronously, so the fake is
    // already in `instances` by the time the call returns: the test opens it
    // and then awaits, which is the order a browser would have done it in.
    const pending = openWebSocket(
      "wss://mud.example/lsp",
      { onText: (text) => texts.push(text), onClose: (initiated) => closes.push(initiated) },
    );
    assert.equal(FakeSocket.instances.length, 1);
    assert.equal(FakeSocket.instances[0]?.url, "wss://mud.example/lsp");
    FakeSocket.instances[0]?.fireOpen();
    const socket = await pending;

    FakeSocket.instances[0]?.fireMessage('{"jsonrpc":"2.0","id":1}');
    // Only text frames are surfaced: this protocol never sends binary, and a
    // session must not be handed half a parsed message.
    FakeSocket.instances[0]?.fireMessage(new Uint8Array([1, 2, 3]));
    socket.send("{\"a\":1}");
    assert.deepEqual(texts, ['{"jsonrpc":"2.0","id":1}']);
    assert.deepEqual(FakeSocket.instances[0]?.sent, ['{"a":1}']);

    socket.close();
    assert.deepEqual(closes, [true], "a close we asked for is reported as such");
  });
});

test("a socket that never opened rejects the connect", async () => {
  await withWebSocket(FakeSocket, async () => {
    const closes: boolean[] = [];
    const pending = openWebSocket(
      "wss://mud.example/lsp",
      { onText: () => {}, onClose: (initiated) => closes.push(initiated) },
    );
    const socket = FakeSocket.instances[0];
    assert.ok(socket);
    // A real browser fires `error` and then `close` when a handshake fails; the
    // fake follows that order, because the session must see the hang-up and
    // not just the rejection.
    socket.dispatch("error", {});
    socket.close();
    await assert.rejects(pending, /socket failed/);
    assert.deepEqual(closes, [false], "the hang-up is reported to whoever is watching");

    const other = openWebSocket("wss://mud.example/lsp", { onText: () => {}, onClose: () => {} });
    FakeSocket.instances[1]?.close();
    await assert.rejects(other, /closed before it opened/);
  });
});

test("a runtime without WebSocket degrades instead of throwing", async () => {
  await withWebSocket(undefined, async () => {
    const events = { onText: () => {}, onClose: () => {} };
    await assert.rejects(() => openWebSocket("wss://mud.example/lsp", events), /no WebSocket/);
    await assert.rejects(() => browserSocketOpener("wss://mud.example/lsp", events), /no WebSocket/);
  });
});
