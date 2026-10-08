// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The IDE's LSP session: `loom-lsp` over the `/lsp` WebSocket (OBI-180,
 * spec M-LSP-1/M-LSP-4, threat model D-TM4).
 *
 * Everything protocol-level lives here, and nothing else: `./lsp-bridge.ts`
 * decides *policy* (which buffer to keep in sync, how often, what a
 * disconnect means for the builder), and `./lsp-monaco.ts` decides how an
 * answer looks. The split matters because the protocol half is the half with
 * a contract to satisfy -- and that contract is a Rust file, not a
 * `node_modules` package, so it is restated here by hand.
 *
 * The handshake, in the order `crates/loom-http/src/lsp.rs` requires it:
 *
 *  1. `POST /api/v1/ws-ticket` with the bearer token -> a single-use ticket
 *     with a 30 s TTL. One ticket per connect, never cached: it is consumed
 *     by the very first frame, and a reconnect after the server's 60 s idle
 *     close needs a fresh one (T-LSP-4: a ticket that outlives a revoked
 *     session would be a way back in).
 *  2. Open the socket, then send `{"auth":"<ticket>"}` as the *first* text
 *     frame, inside the server's 5 s window. A wrong, expired or already-used
 *     ticket closes the socket with no LSP traffic at all.
 *  3. `initialize` -> `initialized`. The server's `initialize_start` accepts
 *     nothing before the former. `rootUri`/`workspaceFolders` are sent as
 *     `null`: in VFS mode a client-supplied root is ignored by design
 *     (M-LSP-2 -- honouring it would swap the gated `ReadAuthorizer` for an
 *     ungated directory), and sending `null` says so on the wire instead of
 *     leaving a field for someone to fill in later.
 *  4. Only then `didOpen`/`didChange`/`didClose` and the requests.
 *
 * Which buffers are synced is the other half of the story. The server keeps
 * at most 64 open documents of at most 1 MiB each, and this client keeps one
 * per visible file and *refuses* to send a buffer over
 * [`MAX_SYNC_BYTES`] -- the server's document limit is 1 MiB but its WebSocket
 * *frame* limit is also 1 MiB, and JSON escaping (`\n`, `\"`, `\u00xx`) only
 * ever makes the frame longer than the text, so a text that squeaks under the
 * document limit can still be the frame that kills the session. Staying
 * strictly under both is what makes one huge buffer a lost analysis rather
 * than a lost connection.
 *
 * Reconnects are lazy and bounded. The server closes an idle session at 60 s
 * on purpose (M-LSP-4/T-LSP-5), and a builder reading code for two minutes
 * then typing one character is the normal case, not an error: the next piece
 * of activity reconnects and replays `didOpen` for every buffer the server
 * has forgotten. What that must never become is a retry loop against a
 * revocation -- which the server also signals by closing, every 15 s, with no
 * distinguishing wire detail -- so [`MAX_FAILED_CONNECTS`] consecutive failed
 * handshades park the session in `failed` until the builder opens a file
 * again. Three is enough to cover a transient network blip and small enough
 * to not look like a brute-force attempt at the ticket endpoint.
 */

import { RpcError, RpcPeer, type RpcRequest } from "./lsp-jsonrpc.js";
import type { EditorMarker } from "./editor-port.js";
import { documentUri, pathFromDocumentUri } from "./lsp-uri.js";
import { LPC_LANGUAGE } from "./lpc.js";

/** The server's `MAX_OPEN_DOCUMENTS` (spec M-LSP-4). Mirrored so a future
 * multi-buffer IDE cannot ask the server to hold a 65th document and get its
 * own diagnostics replaced by a limit message. */
export const MAX_OPEN_DOCUMENTS = 64;

/** Below the server's 1 MiB document *and* 1 MiB frame limits, with room for
 * JSON escaping. See the module comment. */
export const MAX_SYNC_BYTES = 512 * 1024;

/** Consecutive failed handshakes before the session parks. */
export const MAX_FAILED_CONNECTS = 3;

/** `RequestCanceled`, the code `handle_cancel` answers a cancelled request
 * with. Used only to keep a cancelled request's rejection out of the status
 * line: it is the client's own doing. */
const CODE_REQUEST_CANCELLED = -32800;

/** A live document, as the server knows it (or as we are about to make it
 * known). `opened` is whether the *current* connection has seen a `didOpen`
 * for it -- after a reconnect it is `false` for every buffer, which is what
 * makes the replay send `didOpen` rather than a `didChange` the server would
 * take for a document it never opened. */
interface SyncedDocument {
  text: string;
  version: number;
  opened: boolean;
  /** The version the *current connection* last received. A `didOpen` counts
   * as delivering `version`; this is what makes a re-`openDocument` for a
   * buffer that has not changed a no-op instead of a compile. */
  sentVersion: number;
}

export interface SessionSocket {
  send(text: string): void;
  close(): void;
}

export interface SessionSocketEvents {
  /** One inbound text frame. */
  onText(text: string): void;
  /** The socket closed. `initiated` marks a close *we* asked for (a
   * `dispose`), which is the difference between "the session ended" and
   * "the server ended it". */
  onClose(initiated: boolean): void;
}

/** Opens the socket. In the page this is a `WebSocket`; in a test it is a
 * pair of promises and an array of frames. */
export type SocketOpener = (url: string, events: SessionSocketEvents) => Promise<SessionSocket>;

export type SessionState = "idle" | "connecting" | "ready" | "closed" | "failed";

export interface LspSessionOptions {
  /** The `/lsp` URL, same-origin (`wss://<this host>/lsp`). */
  url: string;
  openSocket: SocketOpener;
  /** `POST /api/v1/ws-ticket` -> the ticket. Must not cache. */
  getTicket: () => Promise<string>;
  onDiagnostics?: (path: string, markers: EditorMarker[]) => void;
  onStateChange?: (state: SessionState, detail: string) => void;
  clientInfo?: { name: string; version: string };
  requestTimeoutMs?: number;
  maxInFlight?: number;
}

/** LSP's wire range, 0-based. Kept internal: the IDE's coordinates are
 * 1-based and every conversion happens in this module. */
interface WirePosition {
  line: number;
  character: number;
}

interface WireRange {
  start: WirePosition;
  end: WirePosition;
}

export interface HoverAnswer {
  text: string;
  range: { startLine: number; startColumn: number; endLine: number; endColumn: number } | null;
}

export interface CompletionAnswer {
  label: string;
  kind: number | null;
  detail: string;
  documentation: string;
}

export interface DefinitionAnswer {
  /** The mudlib file path (`/std/room.wf`) the target lives in, already
   * checked against `loom-vfs:`'s grammar -- never a host path (T-LSP-3). */
  path: string;
  line: number;
  column: number;
}

export class LspSession {
  private peer: RpcPeer | null = null;
  private socket: SessionSocket | null = null;
  private state: SessionState = "idle";
  private detail = "";
  private failedConnects = 0;
  private connecting: Promise<boolean> | null = null;
  private readonly documents = new Map<string, SyncedDocument>();
  /** Requests the current connection has not answered. Cancelled en masse
   * when a buffer changes: an answer computed against text the builder has
   * since edited is worse than no answer. */
  private readonly live = new Set<RpcRequest>();
  private disposing = false;

  constructor(private readonly options: LspSessionOptions) {}

  getState(): SessionState {
    return this.state;
  }

  getDetail(): string {
    return this.detail;
  }

  /** How many buffers the server is holding for us. */
  openDocuments(): number {
    return this.documents.size;
  }

  /**
   * Start keeping `path` in sync. Safe to call for a document that is already
   * synced (it refreshes the text); the connection is established lazily, so
   * a session that the server parked in `failed` gets one more try here --
   * opening a file is a deliberate gesture by the builder, which is the only
   * honest way out of `failed`.
   */
  openDocument(path: string, text: string): void {
    if (this.state === "failed") {
      this.failedConnects = 0;
      this.setState("idle", "");
    }
    // A path `loom-lsp` can never hold a document for is not worth a socket:
    // connecting spends a one-time ticket, one of this builder's two session
    // slots on the driver, and an `initialize` round trip -- to analyze
    // nothing. This is also the answer to "why are there no squiggles", which
    // the builder otherwise has to guess between three different causes.
    if (documentUri(path) === null) {
      this.options.onStateChange?.(
        this.state,
        `${path} is not a mudlib program path, so it is not analyzed`,
      );
      return;
    }
    const existing = this.documents.get(path);
    if (existing !== undefined) {
      if (existing.text !== text) {
        existing.text = text;
        existing.version += 1;
      }
    } else {
      this.evictOldestIfNeeded();
      this.documents.set(path, { text, version: 1, opened: false, sentVersion: 0 });
    }
    void this.onActivity(() => {
      this.syncDocument(path);
    });
  }

  /** The buffer's text changed. A document the server has never seen is
   * opened by the same path, so a reconnect racing an edit cannot strand the
   * buffer. */
  changeDocument(path: string, text: string): void {
    const document = this.documents.get(path);
    if (document === undefined) {
      this.openDocument(path, text);
      return;
    }
    if (document.text === text) {
      // The editor reports a change the buffer never made (a re-read, a paste
      // of identical text, a flush of text the bridge already sent). A
      // `didChange` with a new version and the same content costs `loom-lsp`
      // a full compile, which is the one thing the coalescing above exists to
      // avoid.
      return;
    }
    document.text = text;
    document.version += 1;
    // An answer computed against text the builder has since edited is worse
    // than no answer: the hover would describe a buffer that no longer exists.
    this.cancelLiveRequests();
    this.cancelLiveRequests();
    void this.onActivity(() => {
      this.syncDocument(path);
    });
  }

  /** Stop syncing `path`. Also the right call when the IDE closes a buffer
   * for a reason the server can see coming (a file switch), since an
   * un-closed document occupies one of the server's 64 slots for the rest of
   * the session. */
  closeDocument(path: string): void {
    const document = this.documents.get(path);
    if (document === undefined) {
      return;
    }
    const wasOpen = document.opened;
    this.documents.delete(path);
    if (wasOpen && this.peer !== null) {
      const uri = documentUri(path);
      if (uri !== null) {
        this.peer.notify("textDocument/didClose", { textDocument: { uri } });
      }
    }
    this.cancelLiveRequests();
  }

  /** `textDocument/hover`. 1-based `line`/`column`, the IDE's convention. */
  async hover(path: string, line: number, column: number): Promise<HoverAnswer | null> {
    const params = this.textDocumentPosition(path, line, column);
    if (params === null) {
      return null;
    }
    const result = await this.run("textDocument/hover", params);
    if (result === null || typeof result !== "object") {
      return null;
    }
    const contents = (result as Record<string, unknown>)["contents"];
    const text = hoverText(contents);
    if (text === "") {
      return null;
    }
    return { text, range: rangeToMarker((result as Record<string, unknown>)["range"]) };
  }

  /** `textDocument/completion`. An empty array on any failure, which is what
   * Monaco wants to see (it shows "no suggestions", not an error dialog). */
  async completion(path: string, line: number, column: number): Promise<CompletionAnswer[]> {
    const params = this.textDocumentPosition(path, line, column);
    if (params === null) {
      return [];
    }
    const result = await this.run("textDocument/completion", params);
    return toCompletions(result);
  }

  /** `textDocument/definition`. `null` when there is no target, and also
   * when the target's URI is not a `loom-vfs:` one -- the server never emits
   * anything else, and a response that does is not something to open
   * (T-LSP-3). */
  async definition(path: string, line: number, column: number): Promise<DefinitionAnswer | null> {
    const params = this.textDocumentPosition(path, line, column);
    if (params === null) {
      return null;
    }
    const result = await this.run("textDocument/definition", params);
    const target = firstLocation(result);
    if (target === null) {
      return null;
    }
    const targetPath =
      typeof target.uri === "string" ? pathFromDocumentUri(target.uri) : null;
    if (targetPath === null) {
      return null;
    }
    const start = target.range?.start;
    return {
      path: targetPath,
      line: typeof start?.line === "number" ? start.line + 1 : 1,
      column: typeof start?.character === "number" ? start.character + 1 : 1,
    };
  }

  /** `shutdown` + `exit`, then hang up. The server's loop breaks on
   * `shutdown` and its side of the socket closes; `initiated` records that we
   * asked for it, so the status line says "disconnected" rather than
   * "session lost". */
  dispose(): void {
    this.disposeAsync();
  }

  private disposeAsync(): void {
    this.disposing = true;
    const peer = this.peer;
    if (peer !== null) {
      peer.request("shutdown", null).promise.catch(() => {});
      peer.notify("exit", null);
    }
    this.teardown(true);
  }

  // -- connection lifecycle -------------------------------------------------

  /** Run `then` once the session is usable; if it cannot be made usable, the
   * state/detail already say why and nothing is sent. */
  private async onActivity(then: () => void): Promise<void> {
    if (this.disposing) {
      return;
    }
    if (await this.ensureConnected()) {
      then();
    }
  }

  private async ensureConnected(): Promise<boolean> {
    if (this.state === "ready") {
      return true;
    }
    if (this.state === "failed") {
      return false;
    }
    if (this.connecting !== null) {
      return await this.connecting;
    }
    const attempt = this.connect();
    this.connecting = attempt;
    const ok = await attempt;
    this.connecting = null;
    return ok;
  }

  private async connect(): Promise<boolean> {
    this.setState("connecting", "connecting to loom-lsp");
    let ticket: string;
    try {
      ticket = await this.options.getTicket();
    } catch (error) {
      return this.refuse(`sign-in is required for live analysis (${reason(error)})`);
    }
    let socket: SessionSocket;
    try {
      socket = await this.options.openSocket(this.options.url, {
        onText: (text) => {
          this.peer?.accept(text);
        },
        onClose: (initiated) => {
          this.handleSocketClose(initiated);
        },
      });
    } catch (error) {
      return this.refuse(`could not reach /lsp (${reason(error)})`);
    }
    this.socket = socket;
    // D-TM4's first frame. The server's own 5 s window is the reason it goes
    // out before `initialize` is even built, not after.
    socket.send(JSON.stringify({ auth: ticket }));
    const peer = new RpcPeer(
      (text) => {
        if (this.socket === socket) {
          socket.send(text);
        }
      },
      {
        maxPending: this.options.maxInFlight ?? 8,
        timeoutMs: this.options.requestTimeoutMs ?? 10_000,
      },
    );
    peer.onNotification((note) => {
      this.handleNotification(note.method, note.params);
    });
    this.peer = peer;
    try {
      await peer.request("initialize", this.initializeParams()).promise;
      peer.notify("initialized", {});
    } catch (error) {
      peer.close();
      socket.close();
      this.peer = null;
      this.socket = null;
      return this.refuse(`loom-lsp refused the session (${reason(error)})`);
    }
    this.failedConnects = 0;
    this.setState("ready", "");
    // Whatever the previous connection was told about is now gone: the
    // server's `Workspace` dies with the session, so every buffer we still
    // care about has to be re-opened, not merely re-changed.
    for (const path of [...this.documents.keys()]) {
      this.syncDocument(path);
    }
    return true;
  }

  /** One more failed handshake, or a park. */
  private refuse(detail: string): boolean {
    this.failedConnects += 1;
    if (this.failedConnects >= MAX_FAILED_CONNECTS) {
      this.setState("failed", `${detail} (giving up after ${this.failedConnects} attempts)`);
    } else {
      this.setState("closed", detail);
    }
    return false;
  }

  private handleSocketClose(initiated: boolean): void {
    const peer = this.peer;
    if (peer !== null) {
      peer.close();
    }
    for (const document of this.documents.values()) {
      document.opened = false;
    }
    this.peer = null;
    this.socket = null;
    this.cancelLiveRequests();
    if (this.disposing || initiated) {
      this.setState("closed", "disconnected");
      return;
    }
    // The three reasons the server closes are indistinguishable on the wire
    // (all of them are a bare close, M-LSP-4/T-LSP-5): 60 s idle, a revoked
    // tier, or over the per-uid session cap. Saying "the driver closed it"
    // without guessing the cause is the honest form, and the lazy reconnect
    // covers the first while `MAX_FAILED_CONNECTS` bounds the other two.
    this.setState("closed", "the driver closed the live-analysis session");
  }

  private teardown(initiated: boolean): void {
    this.peer?.close();
    this.peer = null;
    this.cancelLiveRequests();
    const socket = this.socket;
    this.socket = null;
    if (socket !== null) {
      socket.close();
    }
    for (const document of this.documents.values()) {
      document.opened = false;
    }
    this.setState("closed", initiated ? "disconnected" : this.detail);
  }

  private setState(state: SessionState, detail: string): void {
    this.state = state;
    this.detail = detail;
    this.options.onStateChange?.(state, detail);
  }

  // -- document sync --------------------------------------------------------

  /** Send the buffer's current text as the server's state requires: `didOpen`
   * if it has never seen this document (including right after a reconnect),
   * `didChange` (full sync) otherwise. */
  private syncDocument(path: string): void {
    const document = this.documents.get(path);
    const peer = this.peer;
    if (document === undefined || peer === null || this.state !== "ready") {
      return;
    }
    const uri = documentUri(path);
    if (uri === null) {
      // Unreachable via `openDocument`, which refuses such a path before it is
      // remembered. Kept because the URI is what goes on the wire, and a
      // silent `undefined` there would be a malformed frame.
      return;
    }
    if (byteLength(document.text) > MAX_SYNC_BYTES) {
      // Refused here rather than at the socket: a frame the server's 1 MiB
      // frame limit rejects would take the whole session with it.
      this.options.onStateChange?.(
        this.state,
        `${path} is over the ${MAX_SYNC_BYTES >> 10} KiB live-analysis limit; save and compile to check it`,
      );
      return;
    }
    if (document.opened && document.sentVersion === document.version) {
      // The server already holds exactly this text. Re-opening the same file
      // from the tree is a common gesture, and a `didChange` that changes
      // nothing is a full recompile of a file nobody edited.
      return;
    }
    // See `documentUri` for why the URI is three slashes and what happens if
    // it is one: the server reads the path out of the URI's *path* component,
    // and a one-slash `loom-vfs:/x.wf` puts `x.wf` in the authority instead,
    // where `vfs_uri_to_program_path` never looks.
    const textDocument = { uri, languageId: LPC_LANGUAGE, version: document.version };
    if (document.opened) {
      peer.notify("textDocument/didChange", {
        textDocument: { uri, version: document.version },
        contentChanges: [{ text: document.text }],
      });
      document.sentVersion = document.version;
      return;
    }
    peer.notify("textDocument/didOpen", {
      textDocument: { ...textDocument, text: document.text },
    });
    document.opened = true;
    document.sentVersion = document.version;
  }

  private evictOldestIfNeeded(): void {
    // `Map` iteration order is insertion order, so this drops the buffer the
    // builder has been away from longest. A bounded client cannot also be a
    // surprising one: the eviction is the server's cap, meted out before the
    // server has to report it.
    if (this.documents.size < MAX_OPEN_DOCUMENTS) {
      return;
    }
    const oldest = this.documents.keys().next().value;
    if (oldest !== undefined) {
      this.closeDocument(oldest);
    }
  }

  // -- notifications --------------------------------------------------------

  private handleNotification(method: string, params: unknown): void {
    if (method !== "textDocument/publishDiagnostics") {
      return;
    }
    const payload = params as Record<string, unknown> | null;
    const uri = typeof payload?.["uri"] === "string" ? payload["uri"] : null;
    const path = uri === null ? null : pathFromDocumentUri(uri);
    if (path === null) {
      // Not a `loom-vfs:` document, so not a file this IDE has open. Nothing
      // to mark, and nothing to say: a server that publishes host paths is
      // broken in a way a status line cannot fix.
      return;
    }
    const raw = Array.isArray(payload?.["diagnostics"]) ? payload["diagnostics"] : [];
    const markers = raw
      .map(toMarker)
      .filter((marker): marker is EditorMarker => marker !== null);
    this.options.onDiagnostics?.(path, markers.slice(0, MAX_MARKERS_PER_DOCUMENT));
  }

  // -- requests -------------------------------------------------------------

  private textDocumentPosition(
    path: string,
    line: number,
    column: number,
  ): Record<string, unknown> | null {
    const uri = documentUri(path);
    if (uri === null || !Number.isInteger(line) || !Number.isInteger(column) || line < 1 || column < 1) {
      return null;
    }
    return {
      textDocument: { uri },
      position: { line: line - 1, character: column - 1 },
    };
  }

  /** Connect if needed, send, and settle a request. Every failure path
   * returns `null` rather than throwing: hover/completion/definition are
   * conveniences, and a builder whose network hiccuped should get an empty
   * answer and a status line, not an exception in Monaco's callback. */
  private async run(method: string, params: unknown): Promise<unknown | null> {
    if (this.disposing) {
      return null;
    }
    if (!(await this.ensureConnected())) {
      return null;
    }
    const peer = this.peer;
    if (peer === null) {
      return null;
    }
    const request = peer.request(method, params);
    this.live.add(request);
    try {
      return await request.promise;
    } catch (error) {
      if (
        error instanceof RpcError &&
        error.kind === "server" &&
        error.code !== CODE_REQUEST_CANCELLED
      ) {
        this.options.onStateChange?.(this.state, `loom-lsp: ${error.message}`);
      }
      return null;
    } finally {
      this.live.delete(request);
    }
  }

  private cancelLiveRequests(): void {
    for (const request of this.live) {
      request.cancel();
    }
    this.live.clear();
  }

  private initializeParams(): Record<string, unknown> {
    const info = this.options.clientInfo ?? { name: "loom-web-ide", version: "0.0.1" };
    return {
      // `processId` is sent as `null` (LSP's "I am not a process you may
      // kill"), and no root is claimed: see the module comment on M-LSP-2.
      processId: null,
      clientInfo: info,
      rootUri: null,
      initializationOptions: null,
      capabilities: {
        textDocument: {
          synchronization: { didSave: false },
          publishDiagnostics: { relatedInformation: false },
          hover: { contentFormat: ["markdown", "plaintext"] },
          completion: { completionItem: { snippetSupport: false } },
          definition: { linkSupport: false },
        },
        workspace: { workspaceFolders: false },
      },
      workspaceFolders: null,
    };
  }
}

/** Enough markers to cover a file that will not be read anyway. Monaco
 * renders every one it is handed, and a 5,000-diagnostic file is a file whose
 * diagnostics are not the point. */
const MAX_MARKERS_PER_DOCUMENT = 500;

/**
 * A diagnostic as the server sends it -> an [`EditorMarker`].
 *
 * LSP ranges are 0-based UTF-16 offsets (`crates/loom-lsp/src/position.rs`
 * counts `encode_utf16` units, so it agrees with Monaco's columns exactly);
 * `EditorMarker` is 1-based, the convention `./compile.ts` uses for
 * compiler-rendered diagnostics. Adding one to each coordinate is the entire
 * conversion, and it happens in this one function so a marker coming from the
 * analyser and a marker coming from a save cannot disagree about where line
 * 1 is.
 */
export function toMarker(value: unknown): EditorMarker | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const diagnostic = value as Record<string, unknown>;
  const range = rangeToMarker(diagnostic["range"]);
  if (range === null) {
    return null;
  }
  const message = typeof diagnostic["message"] === "string" ? diagnostic["message"] : "";
  if (message === "") {
    return null;
  }
  const code = diagnostic["code"];
  return {
    line: range.startLine,
    column: range.startColumn,
    endLine: range.endLine,
    endColumn: range.endColumn,
    severity: severityOf(diagnostic["severity"]),
    message,
    code: typeof code === "string" || typeof code === "number" ? String(code) : undefined,
  };
}

function rangeToMarker(value: unknown): {
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
} | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const range = value as Partial<WireRange>;
  const start = range.start;
  const end = range.end;
  if (
    typeof start?.line !== "number" ||
    typeof start.character !== "number" ||
    typeof end?.line !== "number" ||
    typeof end.character !== "number"
  ) {
    return null;
  }
  const marker = {
    startLine: start.line + 1,
    startColumn: start.character + 1,
    endLine: end.line + 1,
    endColumn: end.character + 1,
  };
  // A reversed range would make Monaco underline nothing (or the whole rest
  // of the file, depending on the version). Snapping the end to the start is
  // the smallest fix that keeps the marker on the line it belongs to.
  if (marker.endLine < marker.startLine) {
    return { ...marker, endLine: marker.startLine, endColumn: marker.startColumn };
  }
  if (marker.endLine === marker.startLine && marker.endColumn < marker.startColumn) {
    return { ...marker, endColumn: marker.startColumn };
  }
  return marker;
}

/** LSP's `DiagnosticSeverity` (1..4) -> the IDE's three levels. `EditorMarker`
 * has no "hint": a hint is an informational squiggle, and the difference
 * between "you could name this better" and "this may be wrong" is not one an
 * alpha editor needs two colours for. */
function severityOf(value: unknown): EditorMarker["severity"] {
  switch (value) {
    case 1:
      return "error";
    case 2:
      return "warning";
    default:
      return "info";
  }
}

/** `Hover.contents` in any of the shapes the server could send:
 * `MarkedString::String`, a `MarkupContent`, or an array of either. loom-lsp
 * answers with the first; the others are handled so a server-side change to
 * `contentFormat` does not silently blank the hover. */
export function hoverText(contents: unknown): string {
  if (typeof contents === "string") {
    return contents;
  }
  if (Array.isArray(contents)) {
    return contents.map(hoverText).filter((part) => part !== "").join("\n\n");
  }
  if (typeof contents === "object" && contents !== null) {
    const value = (contents as Record<string, unknown>)["value"];
    return typeof value === "string" ? value : "";
  }
  return "";
}

/** `CompletionItem[] | CompletionList | null` -> a flat list. */
export function toCompletions(result: unknown): CompletionAnswer[] {
  const items = Array.isArray(result)
    ? result
    : Array.isArray((result as Record<string, unknown> | null)?.["items"])
      ? ((result as Record<string, unknown>)["items"] as unknown[])
      : [];
  const out: CompletionAnswer[] = [];
  for (const raw of items.slice(0, MAX_COMPLETIONS)) {
    if (typeof raw !== "object" || raw === null) {
      continue;
    }
    const item = raw as Record<string, unknown>;
    const label = typeof item["label"] === "string" ? item["label"] : null;
    if (label === null || label === "") {
      continue;
    }
    out.push({
      label,
      kind: typeof item["kind"] === "number" ? item["kind"] : null,
      detail: typeof item["detail"] === "string" ? item["detail"] : "",
      documentation: hoverText(item["documentation"]),
    });
  }
  return out;
}

/** `GotoDefinitionResponse`'s three shapes -> the first location, with its URI
 * left as the raw string to be checked by the caller. */
function firstLocation(result: unknown): { uri: unknown; range?: WireRange } | null {
  if (Array.isArray(result)) {
    const first = result[0];
    return typeof first === "object" && first !== null
      ? (first as { uri: unknown; range?: WireRange })
      : null;
  }
  if (typeof result !== "object" || result === null) {
    return null;
  }
  const location = result as Record<string, unknown>;
  // A `LocationLink` carries `targetUri`/`targetSelectionRange` instead.
  const uri = location["uri"] ?? location["targetUri"];
  const range = (location["range"] ?? location["targetSelectionRange"]) as WireRange | undefined;
  return typeof uri === "string" || uri === undefined ? { uri, range } : null;
}

const MAX_COMPLETIONS = 300;

function byteLength(text: string): number {
  // `TextEncoder` is in every target browser and in Node's globals, so this
  // is the exact byte count without a `Buffer` dependency.
  return new TextEncoder().encode(text).length;
}

function reason(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
