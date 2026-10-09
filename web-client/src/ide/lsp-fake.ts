// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * An in-memory stand-in for `crates/loom-http/src/lsp.rs`, for the client's
 * tests. It is a *fake* rather than a mock of the protocol: the framing (one
 * JSON-RPC message per text frame), the auth-first rule, and the shape of the
 * `initialize` answer are the server's, and each is asserted from this side
 * rather than assumed.
 *
 * Two behaviours it models that are easy to get wrong in a test harness:
 *
 * - **Replies arrive later, on the socket that asked.** `send()` returns
 *   before anything comes back, which is what makes the client's pending
 *   bookkeeping observable; a synchronous fake would pass a test of code that
 *   deadlocks in the browser.
 * - **`closeAfterFrames` closes from the server side.** That is the idle
 *   timeout, the revocation recheck, and the session-cap refusal, all of which
 *   reach the client as a bare close -- the only way to write the reconnect
 *   test without waiting a real 60 seconds.
 *
 * What it does *not* model is a server-initiated request, because `loom-lsp`
 * never sends one; the client's `MethodNotFound` refusal is tested by pushing
 * an invented frame.
 */

import type { SessionSocket, SessionSocketEvents, SocketOpener } from "./lsp-session.js";

/** One frame the client sent, parsed. A frame that is not JSON arrives as
 * `{ "__invalid": "<text>" }` so a test can still assert on it. */
export type SentFrame = Record<string, unknown>;

/** The `result` a request should be answered with. Return `undefined` for the
 * fake's "not implemented" error, or a `{ __error: ... }` object to answer with
 * a JSON-RPC error. */
export type Responder = (method: string, params: SentFrame) => unknown;

export interface FakeOptions {
  respond?: Responder;
  /** Reject the connect itself, as a refused or blocked WebSocket would. */
  failConnect?: boolean;
  /** Answer `initialize` with an error, which is what a bad, expired, or
   * already-used ticket looks like from the client's side. */
  refuseInitialize?: boolean;
  /** Close the socket from the server side once this many frames have been
   * sent. */
  closeAfterFrames?: number;
}

const DEFAULT_CAPABILITIES = { capabilities: { hoverProvider: true, completionProvider: { triggerCharacters: ["."] } } };

export class FakeLspServer {
  /** Every frame the client sent, in order, across all connections. */
  readonly frames: SentFrame[] = [];
  readonly sockets: FakeSocket[] = [];
  connects = 0;

  private options: FakeOptions;

  constructor(options: FakeOptions = {}) {
    this.options = options;
  }

  /** Method names in order, which is what most assertions want. */
  get methods(): string[] {
    return this.frames
      .map((frame) => (typeof frame["method"] === "string" ? frame["method"] : null))
      .filter((method): method is string => method !== null);
  }

  /** `textDocument/didOpen` payloads. */
  get opened(): { uri: string; text: string; version: number }[] {
    return this.documentsOf("textDocument/didOpen", (params) => {
      const doc = params["textDocument"] as { uri: string; text?: string; version?: number };
      return { uri: doc.uri, text: doc.text ?? "", version: doc.version ?? 0 };
    });
  }

  /** `textDocument/didChange` payloads (full sync, so the text is there). */
  get changed(): { uri: string; text: string; version: number }[] {
    return this.documentsOf("textDocument/didChange", (params) => {
      const doc = params["textDocument"] as { uri: string; version?: number };
      const changes = (params["contentChanges"] ?? []) as { text: string }[];
      return { uri: doc.uri, text: changes[0]?.text ?? "", version: doc.version ?? 0 };
    });
  }

  /** `textDocument/didClose` URIs. */
  get closedUris(): string[] {
    return this.documentsOf("textDocument/didClose", (params) => {
      const doc = params["textDocument"] as { uri: string };
      return doc.uri;
    });
  }

  /** The `{"auth": "<ticket>"}` first frame, or `null` when the client never
   * sent one (D-TM4's whole requirement, so it gets its own accessor). */
  get authTickets(): string[] {
    return this.frames
      .filter((frame) => typeof frame["auth"] === "string")
      .map((frame) => frame["auth"] as string);
  }

  /** Start answering differently partway through a test. */
  setResponder(responder: Responder): void {
    this.options.respond = responder;
  }

  /** The `openSocket` implementation the session is handed. */
  readonly opener: SocketOpener = (_url, events) => {
    this.connects += 1;
    if (this.options.failConnect === true) {
      return Promise.reject(new Error("connection refused"));
    }
    const socket = new FakeSocket(this, events, this.options.closeAfterFrames);
    this.sockets.push(socket);
    return Promise.resolve(socket);
  };

  /** The newest live socket, for pushing a frame the server would send. */
  get last(): FakeSocket | undefined {
    return this.sockets.at(-1);
  }

  /** `textDocument/publishDiagnostics` for a document URI. */
  publish(uri: string, diagnostics: unknown[]): void {
    this.last?.push({
      jsonrpc: "2.0",
      method: "textDocument/publishDiagnostics",
      params: { uri, diagnostics },
    });
  }

  /** Push any message to the client, inventing a frame the real server would
   * not send (a server-initiated request, a malformed object). */
  push(message: unknown): void {
    this.last?.push(message);
  }

  /** Close the newest socket from the server side. */
  hangUp(): void {
    this.last?.serverClose();
  }

  /** Called by `FakeSocket.send`. */
  handle(text: string, socket: FakeSocket): void {
    let frame: SentFrame;
    try {
      frame = JSON.parse(text) as SentFrame;
    } catch {
      this.frames.push({ __invalid: text });
      return;
    }
    if (typeof frame !== "object" || frame === null) {
      this.frames.push({ __invalid: text });
      return;
    }
    this.frames.push(frame);
    const method = typeof frame["method"] === "string" ? frame["method"] : null;
    const id = typeof frame["id"] === "number" ? frame["id"] : null;
    if (method === null || id === null) {
      return; // a notification or the auth frame: nothing to answer
    }
    socket.answer(id, method, (frame["params"] ?? {}) as SentFrame, this.options);
  }

  private documentsOf<T>(
    method: string,
    extract: (params: SentFrame) => T,
  ): T[] {
    const out: T[] = [];
    for (const frame of this.frames) {
      if (frame["method"] === method) {
        out.push(extract((frame["params"] ?? {}) as SentFrame));
      }
    }
    return out;
  }
}

class FakeSocket implements SessionSocket {
  /** Frames this socket sent, in order. */
  readonly sent: string[] = [];
  closed = false;
  /** True when the *client* hung up (`dispose`), which is the difference the
   * status line draws between "disconnected" and "session lost". */
  initiatedClose = false;

  constructor(
    private readonly server: FakeLspServer,
    private readonly events: SessionSocketEvents,
    private readonly closeAfter: number | undefined,
  ) {}

  send(text: string): void {
    if (this.closed) {
      return;
    }
    this.sent.push(text);
    this.server.handle(text, this);
    if (this.closeAfter !== undefined && this.sent.length >= this.closeAfter) {
      this.serverClose();
    }
  }

  close(): void {
    if (this.closed) {
      return;
    }
    this.initiatedClose = true;
    this.closed = true;
    this.events.onClose(true);
  }

  /** Deliver a message, as the wire would: after the current task. */
  push(message: unknown): void {
    if (this.closed) {
      return;
    }
    this.events.onText(typeof message === "string" ? message : JSON.stringify(message));
  }

  serverClose(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.events.onClose(false);
  }

  /** Queue this socket's reply to request `id`. */
  answer(id: number, method: string, params: SentFrame, options: FakeOptions): void {
    const reply = (message: unknown): void => {
      // Deferred so `send()` has already returned, matching a real socket: a
      // fake that answers synchronously hides ordering bugs.
      setTimeout(() => this.push(message), 0);
    };
    if (method === "initialize") {
      if (options.refuseInitialize === true) {
        reply({ jsonrpc: "2.0", id, error: { code: -32000, message: "invalid ticket" } });
        return;
      }
      reply({ jsonrpc: "2.0", id, result: DEFAULT_CAPABILITIES });
      return;
    }
    if (method === "shutdown") {
      reply({ jsonrpc: "2.0", id, result: null });
      return;
    }
    const result = options.respond?.(method, params);
    if (result === undefined) {
      reply({ jsonrpc: "2.0", id, error: { code: -32601, message: `${method} is unhandled` } });
      return;
    }
    if (isError(result)) {
      reply({ jsonrpc: "2.0", id, error: result["__error"] });
      return;
    }
    reply({ jsonrpc: "2.0", id, result });
  }
}

function isError(value: unknown): value is { __error: unknown } {
  return (
    typeof value === "object" &&
    value !== null &&
    Object.prototype.hasOwnProperty.call(value, "__error")
  );
}

/** Let queued replies and any promise chains settle. Three turns: the reply's
 * `setTimeout`, the await on it, and the await on the caller's promise. */
export async function settle(rounds = 3): Promise<void> {
  for (let index = 0; index < rounds; index += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}
