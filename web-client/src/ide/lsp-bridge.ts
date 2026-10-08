// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The IDE-facing half of live analysis (OBI-180 M-IDE-4/M-IDE-5).
 *
 * The controller knows a builder opened a file, typed in it, and switched
 * away. The session knows how to talk to `loom-lsp`. This module is where one
 * becomes the other, and the three things it decides are all policy, not
 * protocol:
 *
 * 1. **Only the visible buffer is synced.** `loom-lsp`'s analysis is a fresh
 *    compile of the file plus its inherit/import closure (`diagnostics.rs`),
 *    so keeping six inherited files open would be six compiles per keystroke
 *    burst for information the builder is not looking at. One document, one
 *    `didClose` when the buffer changes -- which also keeps the session well
 *    inside the server's 64-document cap (M-LSP-4) without relying on it.
 * 2. **Keystrokes are coalesced.** `debounceMs` is the *trailing* window in
 *    which typing still counts as one edit -- it slides with every keystroke,
 *    so no analysis is ever started against text that is being changed -- and
 *    `maxWaitMs` caps how long a continuously typing builder can go unheard.
 *    A full-sync `didChange` carries the whole buffer, so without coalescing a
 *    two-second burst of typing would be two seconds of compiles of text
 *    nobody will read -- and the server's queue is bounded at 16, where the
 *    answer to a stale analysis is cancellation, not patience.
 * 3. **A disconnect is not a diagnosis.** The server closes an idle session
 *    at 60 s by design, and the builder should see nothing at all when that
 *    happens: the markers on screen are still true of the text on screen, and
 *    the next keystroke reconnects. Only a session that *fails* to come back
 *    (`failed`, after the bounded attempts in `./lsp-session.ts`) says anything
 *    in the status line.
 *
 * Live diagnostics are delivered through the editor's own marker owner,
 * `"loom-lsp"`, which is why they never fight with the save path: a save's
 * compile result is the driver's authoritative answer about the file it just
 * wrote and lands under `"loom-ide"`. Monaco keeps the two sets separate, so a
 * builder sees the analyser's squiggles and the compiler's panel rows for what
 * they are.
 */

import type { EditorMarker } from "./editor-port.js";
import {
  type CompletionAnswer,
  type HoverAnswer,
  type LspSessionOptions,
  type SessionState,
  LspSession,
} from "./lsp-session.js";

/** The pieces of a session the bridge drives. `LspSession` satisfies it; a
 * test supplies an object that records calls instead of speaking JSON-RPC. */
export interface LspSync {
  openDocument(path: string, text: string): void;
  changeDocument(path: string, text: string): void;
  closeDocument(path: string): void;
  hover(path: string, line: number, column: number): Promise<HoverAnswer | null>;
  completion(path: string, line: number, column: number): Promise<CompletionAnswer[]>;
  definition?(path: string, line: number, column: number): Promise<unknown>;
  dispose(): void;
}

/** Builds a session and hands it the bridge's two callbacks. Production uses
 * `(handlers) => new LspSession({...})`; a test returns a recording fake. */
export type SessionMaker = (handlers: {
  onDiagnostics: (path: string, markers: EditorMarker[]) => void;
  onStateChange: (state: SessionState, detail: string) => void;
}) => LspSync;

/** The editor's marker sink. `path` is carried so an implementation can attach
 * markers to the model that owns them rather than whatever happens to be on
 * screen when a response lands. */
export type MarkerSink = (path: string, markers: EditorMarker[]) => void;

export interface LspBridgeOptions {
  createSession: SessionMaker;
  setMarkers: MarkerSink;
  /** Status line text, for the cases worth interrupting a builder for. */
  onStatus?: (message: string) => void;
  debounceMs?: number;
  maxWaitMs?: number;
  now?: () => number;
  setTimer?: (fn: () => void, ms: number) => ReturnType<typeof setTimeout>;
  clearTimer?: (timer: ReturnType<typeof setTimeout>) => void;
}

/** The window in which typing counts as one edit. 300 ms is below the interval
 * at which a fast typist produces characters, so a word is one analysis, and
 * far below the point where the delay is perceptible. */
const DEFAULT_DEBOUNCE_MS = 300;

/** How long a continuously-typing builder waits for a refresh. */
const DEFAULT_MAX_WAIT_MS = 2_000;

/** What the controller calls. Deliberately four methods and nothing else: the
 * controller must not be able to ask the analyser for a document it is not
 * showing. */
export interface LspHooks {
  documentOpened(path: string, text: string): void;
  documentChanged(path: string, text: string): void;
  documentClosed(path: string): void;
  dispose(): void;
}

export class LspBridge implements LspHooks {
  private readonly session: LspSync;
  private readonly debounceMs: number;
  private readonly maxWaitMs: number;
  private readonly now: () => number;
  private readonly setTimer: NonNullable<LspBridgeOptions["setTimer"]>;
  private readonly clearTimer: NonNullable<LspBridgeOptions["clearTimer"]>;
  private current: string | null = null;
  private pending: { path: string; text: string } | null = null;
  private pendingSince = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private disposed = false;

  constructor(private readonly options: LspBridgeOptions) {
    this.session = options.createSession({
      onDiagnostics: (path, markers) => {
        this.deliverDiagnostics(path, markers);
      },
      onStateChange: (state, detail) => {
        this.reportState(state, detail);
      },
    });
    this.debounceMs = options.debounceMs ?? DEFAULT_DEBOUNCE_MS;
    this.maxWaitMs = options.maxWaitMs ?? DEFAULT_MAX_WAIT_MS;
    this.now = options.now ?? (() => Date.now());
    this.setTimer = options.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
    this.clearTimer = options.clearTimer ?? ((timer) => clearTimeout(timer));
  }

  /** The read side of the seam, for `./lsp-monaco.ts`. */
  get providers(): {
    hover: (path: string, line: number, column: number) => Promise<HoverAnswer | null>;
    completion: (path: string, line: number, column: number) => Promise<CompletionAnswer[]>;
  } {
    return {
      hover: (path, line, column) => this.session.hover(path, line, column),
      completion: (path, line, column) => this.session.completion(path, line, column),
    };
  }

  /** A buffer became visible. The first analysis is not debounced -- a builder
   * who just opened a file wants the answer that already exists. */
  documentOpened(path: string, text: string): void {
    if (this.disposed) {
      return;
    }
    if (this.current !== null && this.current !== path) {
      this.discardPending();
      this.session.closeDocument(this.current);
    }
    this.current = path;
    // Whatever markers the previous view of this file left behind are not
    // facts about the text about to be analyzed. Clearing first means the
    // worst a stale set can do is a missing squiggle for one round trip,
    // never a squiggle that was already fixed.
    this.options.setMarkers(path, []);
    this.session.openDocument(path, text);
  }

  documentChanged(path: string, text: string): void {
    if (this.disposed || this.current !== path) {
      return;
    }
    const now = this.now();
    if (this.pending === null) {
      this.pendingSince = now;
    }
    this.pending = { path, text };
    if (now - this.pendingSince >= this.maxWaitMs) {
      // The window has been sliding for as long as we are willing to let it:
      // answer now, mid-burst, rather than sliding the deadline again.
      this.clearTimerIfNeeded();
      this.flush();
      return;
    }
    this.clearTimerIfNeeded();
    this.timer = this.setTimer(() => this.flush(), this.debounceMs);
  }

  documentClosed(path: string): void {
    if (this.current !== path) {
      return;
    }
    this.discardPending();
    this.current = null;
    this.options.setMarkers(path, []);
    this.session.closeDocument(path);
  }

  dispose(): void {
    this.disposed = true;
    this.discardPending();
    this.current = null;
    this.session.dispose();
  }

  /** A diagnostic arrived. Only for the buffer we are syncing -- the server
   * publishes per document, and a late frame for a file the builder switched
   * away from must not repaint the file they switched to. */
  private deliverDiagnostics(path: string, markers: EditorMarker[]): void {
    if (this.disposed || (this.current !== null && this.current !== path)) {
      return;
    }
    this.options.setMarkers(path, markers);
  }

  /** The status line belongs to the controller and is shared with the save
   * path, so the bridge says almost nothing in it. A close is *not* news: the
   * server hangs up on an idle session at 60 s on purpose, the next keystroke
   * reconnects, and the markers already on screen are still true of the text on
   * screen. Reporting "live analysis closed" would describe something that is
   * not broken. `failed` -- the retries are done, the squiggles really have
   * stopped -- is the one state worth the words. */
  private reportState(state: SessionState, detail: string): void {
    if (state === "failed") {
      this.options.onStatus?.(`Live analysis stopped: ${detail}`);
    }
  }

  private flush(): void {
    this.timer = null;
    const pending = this.pending;
    this.pending = null;
    this.pendingSince = 0;
    if (pending === null || this.disposed) {
      return;
    }
    this.session.changeDocument(pending.path, pending.text);
  }

  private discardPending(): void {
    this.pending = null;
    this.pendingSince = 0;
    this.clearTimerIfNeeded();
  }

  private clearTimerIfNeeded(): void {
    if (this.timer !== null) {
      this.clearTimer(this.timer);
      this.timer = null;
    }
  }
}

/** The normal production wiring, kept here so `./main.ts` is a mount file and
 * not a configuration file. */
export function bridgeForSession(
  sessionOptions: Omit<LspSessionOptions, "onDiagnostics" | "onStateChange">,
  bridgeOptions: Omit<LspBridgeOptions, "createSession">,
): LspBridge {
  return new LspBridge({
    ...bridgeOptions,
    createSession: (handlers) =>
      new LspSession({
        ...sessionOptions,
        onDiagnostics: handlers.onDiagnostics,
        onStateChange: handlers.onStateChange,
      }),
  });
}
