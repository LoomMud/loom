// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * JSON-RPC 2.0 over WebSocket text frames (OBI-180, spec M-LSP-1/M-LSP-4).
 *
 * `loom-lsp`'s `/lsp` bridge puts **one whole JSON-RPC message per WebSocket
 * text frame**: `crates/loom-http/src/lsp.rs` does
 * `serde_json::from_str::<lsp_server::Message>(&text)` on each frame and
 * `Connection::sender` emits one frame per message. There is no
 * `Content-Length` header framing -- that is the stdio transport's job, and
 * the framing difference is the whole reason this file exists instead of a
 * vendored `vscode-jsonrpc`.
 *
 * Written by hand rather than pulled from npm for two reasons. The first is
 * the supply-chain rule the CTO set for the web client: no new dependency to
 * get one socket (the same reasoning that made Monaco a vendored, pinned
 * directory instead of a CDN `<script>`). The second is that the
 * `vscode-languageserver-protocol` package is ~1 MB of generated LSP type
 * definitions whose only consumer would be this file; the handful of message
 * shapes the IDE actually speaks -- `initialize`, four `textDocument/*`
 * requests, three sync notifications, `publishDiagnostics`,
 * `$/cancelRequest` -- are easier to read than to configure.
 *
 * What is *not* hand-rolled is the protocol's guarantees, and they are the
 * reason the peer is separate from the session (`./lsp-session.ts`):
 *
 * - **Every request has exactly one outcome.** A response resolves or
 *   rejects it; a timeout rejects it *and* sends `$/cancelRequest`, which
 *   `loom-lsp` honours (`handle_cancel` in `server.rs`), so the server is
 *   not left compiling for a builder who closed the tab; a socket close
 *   rejects all of them. Nothing waits forever.
 * - **In flight is bounded.** `maxPending` (16, the same number the server
 *   refuses beyond) is a hard client-side ceiling: a 17th request is
 *   rejected immediately rather than queued, so a stalled server cannot grow
 *   the browser's memory. Queuing would be the wrong instinct -- the point of
 *   cancelling is that a stale analysis answer is worthless.
 * - **Inbound is validated, not trusted.** A frame that is not an object, is
 *   not `2.0`, carries a non-numeric id it claims to be a response for, or is
 *   larger than the server's own 4 MiB message ceiling is dropped and
 *   counted. `droppedFrames` exists so a test can assert the drop happened
 *   and a future status line can show it.
 * - **Server-initiated requests are refused, not executed.** `loom-lsp`
 *   never sends one (all it emits are responses and notifications), so if a
 *   frame arrives with both a `method` and an `id` the peer answers with
 *   JSON-RPC's `MethodNotFound` and moves on. That is the honest reply, and
 *   it stops the server from blocking on an answer we will never produce.
 */

/** The one transport operation the peer needs; `WebSocket.send` in the
 * page, an array push in a test. */
export type FrameSender = (text: string) => void;

/** A notification the server sent us (`method` + `params`). */
export interface InboundNotification {
  method: string;
  params: unknown;
}

/** JSON-RPC's error object, as `lsp_server::Response` serialises it. */
export interface RpcErrorInfo {
  code: number;
  message: string;
  data?: unknown;
}

/** Why a request did not succeed. `cancelled`/`timeout`/`closed`/`busy` are
 * the client's own; `server` carries a JSON-RPC error object. */
export type RpcFailureKind = "cancelled" | "timeout" | "closed" | "busy" | "server";

export class RpcError extends Error {
  readonly kind: RpcFailureKind;
  readonly code: number | null;

  constructor(kind: RpcFailureKind, message: string, code: number | null = null) {
    super(message);
    this.name = "RpcError";
    this.kind = kind;
    this.code = code;
  }
}

/** JSON-RPC's `MethodNotFound`, the code the spec assigns to "I will not do
 * that". */
const METHOD_NOT_FOUND = -32601;

/** `loom-lsp`'s outbound message ceiling (spec M-LSP-4). A frame bigger than
 * this is not a message we were meant to read. */
const MAX_INBOUND_BYTES = 4 * 1024 * 1024;

/** The default ceiling on unanswered requests, matching the server's
 * `MAX_PENDING_REQUESTS` so the client gives up before the server does. */
const DEFAULT_MAX_PENDING = 16;

/** A request outlives the server's own per-request deadline by a margin:
 * `loom-lsp` answers or errors within 5 s of picking a job up, so 10 s here
 * means the socket, not the analyser, is the problem. */
const DEFAULT_TIMEOUT_MS = 10_000;

interface Pending {
  method: string;
  resolve: (value: unknown) => void;
  reject: (error: RpcError) => void;
  timer: ReturnType<typeof setTimeout> | null;
  /** Set once the client has given up on it, so a late response is dropped
   * rather than delivered to a caller that moved on. */
  settled: boolean;
}

export interface RpcPeerOptions {
  maxPending?: number;
  timeoutMs?: number;
  /** Tests replace the real timer: a timeout assertion that waits ten seconds
   * is a test nobody runs twice. */
  setTimer?: (fn: () => void, ms: number) => ReturnType<typeof setTimeout>;
  clearTimer?: (timer: ReturnType<typeof setTimeout>) => void;
}

/** A handle the session can cancel when a newer edit makes the answer
 * worthless. */
export interface RpcRequest {
  id: number;
  promise: Promise<unknown>;
  cancel(): void;
}

export class RpcPeer {
  private readonly pending = new Map<number, Pending>();
  private readonly send: FrameSender;
  private readonly maxPending: number;
  private readonly timeoutMs: number;
  private readonly setTimer: NonNullable<RpcPeerOptions["setTimer"]>;
  private readonly clearTimer: NonNullable<RpcPeerOptions["clearTimer"]>;
  private nextId = 1;
  private notificationHandler: ((note: InboundNotification) => void) | null = null;
  private open = true;
  droppedFrames = 0;

  constructor(send: FrameSender, options: RpcPeerOptions = {}) {
    this.send = send;
    this.maxPending = options.maxPending ?? DEFAULT_MAX_PENDING;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.setTimer = options.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
    this.clearTimer = options.clearTimer ?? ((timer) => clearTimeout(timer));
  }

  /** The one handler for server-initiated notifications. Set before
   * connecting: a notification that arrives with nowhere to go is dropped
   * (LSP notifications are inherently droppable -- the next `didChange`
   * republishes). */
  onNotification(handler: (note: InboundNotification) => void): void {
    this.notificationHandler = handler;
  }

  /** Number of unanswered requests. Exposed for tests and for a status line
   * that wants to say "the analyser is busy". */
  inFlight(): number {
    return this.pending.size;
  }

  /**
   * Send `method` and wait for its response. Rejects with `kind: "busy"`
   * when [`RpcPeer.maxPending`] requests are already unanswered -- the call
   * never queues.
   */
  request(method: string, params: unknown): RpcRequest {
    const id = this.nextId;
    if (!this.open) {
      const promise = Promise.reject(new RpcError("closed", `${method}: the session is closed`));
      return { id, promise, cancel: () => {} };
    }
    if (this.pending.size >= this.maxPending) {
      return {
        id,
        promise: Promise.reject(
          new RpcError("busy", `loom-lsp is busy (${this.maxPending} requests pending)`),
        ),
        cancel: () => {},
      };
    }
    this.nextId += 1;
    let resolveFn: (value: unknown) => void = () => {};
    let rejectFn: (error: RpcError) => void = () => {};
    const promise = new Promise<unknown>((resolve, reject) => {
      resolveFn = resolve;
      rejectFn = reject;
    });
    const entry: Pending = { method, resolve: resolveFn, reject: rejectFn, timer: null, settled: false };
    entry.timer = this.setTimer(() => {
      this.settle(id, false, new RpcError("timeout", `loom-lsp did not answer ${method}`));
      this.notifyCancel(id);
    }, this.timeoutMs);
    this.pending.set(id, entry);
    this.write({ jsonrpc: "2.0", id, method, params });
    return {
      id,
      promise,
      cancel: () => {
        this.settle(
          id,
          false,
          new RpcError("cancelled", `${method} was cancelled by the editor`),
        );
        this.notifyCancel(id);
      },
    };
  }

  /** A message with no answer expected. Returns `false` when the session is
   * closed, so a caller doing its own bookkeeping (a version counter) can
   * decide whether the server saw it. */
  notify(method: string, params: unknown): boolean {
    if (!this.open) {
      return false;
    }
    this.write({ jsonrpc: "2.0", method, params });
    return true;
  }

  /** Feed one inbound WebSocket text frame. Never throws: a malformed frame
   * is a dropped frame, and a dropped frame is counted. */
  accept(raw: string): void {
    if (byteLength(raw) > MAX_INBOUND_BYTES) {
      this.droppedFrames += 1;
      return;
    }
    let message: unknown;
    try {
      message = JSON.parse(raw);
    } catch {
      this.droppedFrames += 1;
      return;
    }
    if (typeof message !== "object" || message === null) {
      this.droppedFrames += 1;
      return;
    }
    const frame = message as Record<string, unknown>;
    if (frame["jsonrpc"] !== "2.0") {
      this.droppedFrames += 1;
      return;
    }
    // JSON-RPC's own classification, in the order that gets it right: a
    // message with a `method` is a request (if it has an id) or a
    // notification (if it does not); anything else that carries an id is a
    // response. Checking the id first -- as an earlier draft of this file did
    // -- silently swallows a server-initiated request, because its id is not
    // one we issued and it lands in the "answer to nothing" path instead of
    // the refusal below.
    if (typeof frame["method"] === "string") {
      if (frame["id"] !== undefined && frame["id"] !== null) {
        this.write({
          jsonrpc: "2.0",
          id: frame["id"],
          error: { code: METHOD_NOT_FOUND, message: "the web IDE answers no LSP requests" },
        });
        return;
      }
      this.deliverNotification(frame);
      return;
    }
    const id = requestId(frame["id"]);
    if (id === null) {
      this.droppedFrames += 1;
      return;
    }
    const entry = this.pending.get(id);
    if (entry === undefined) {
      // An answer to a request we already gave up on. Correctly late, not
      // corrupt: drop it silently and let the counter tell the story.
      this.droppedFrames += 1;
      return;
    }
    this.pending.delete(id);
    if (entry.timer !== null) {
      this.clearTimer(entry.timer);
    }
    if (frame["error"] !== undefined && frame["error"] !== null) {
      const info = frame["error"] as Partial<RpcErrorInfo>;
      entry.settled = true;
      entry.reject(
        new RpcError(
          "server",
          typeof info.message === "string" ? info.message : "loom-lsp returned an error",
          typeof info.code === "number" ? info.code : null,
        ),
      );
      return;
    }
    entry.settled = true;
    entry.resolve(frame["result"]);
  }

  /** The socket went away. Every unanswered request fails at once -- a
   * session that is gone cannot answer later. */
  close(): void {
    this.open = false;
    for (const [id, entry] of this.pending) {
      if (entry.timer !== null) {
        this.clearTimer(entry.timer);
      }
      entry.settled = true;
      entry.reject(new RpcError("closed", `loom-lsp closed while ${entry.method} was running`));
      this.pending.delete(id);
    }
  }

  private deliverNotification(frame: Record<string, unknown>): void {
    if (typeof frame["method"] !== "string") {
      // No id and no method: not a response, not a notification, not a
      // request. Refusing it still has to be visible in the accounting, or a
      // stream of garbage looks identical to a quiet socket.
      this.droppedFrames += 1;
      return;
    }
    if (this.notificationHandler === null) {
      this.droppedFrames += 1;
      return;
    }
    this.notificationHandler({ method: frame["method"], params: frame["params"] });
  }

  private settle(id: number, ok: boolean, error: RpcError): void {
    const entry = this.pending.get(id);
    if (entry === undefined || entry.settled) {
      return;
    }
    this.pending.delete(id);
    if (entry.timer !== null) {
      this.clearTimer(entry.timer);
    }
    entry.settled = true;
    if (ok) {
      entry.resolve(undefined);
    } else {
      entry.reject(error);
    }
  }

  /** `$/cancelRequest`, LSP's own cancellation notification. Sent after the
   * local rejection, so a caller is never kept waiting for a server that is
   * still chewing on a job nobody wants. */
  private notifyCancel(id: number): void {
    this.notify(`$/cancelRequest`, { id });
  }

  private write(message: Record<string, unknown>): void {
    this.send(JSON.stringify(message));
  }
}

/** A JSON-RPC id is a number or a string; only numbers are generated here. */
function requestId(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}

/** UTF-8 length without allocating an encoder per call for the common case. */
function byteLength(text: string): number {
  if (text.length > MAX_INBOUND_BYTES) {
    return MAX_INBOUND_BYTES + 1; // cheap rejection before the real count
  }
  return new TextEncoder().encode(text).length;
}
