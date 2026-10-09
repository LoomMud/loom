// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The slice of Monaco the IDE uses, as an interface (OBI-180 M-IDE-2).
 *
 * `app.ts` -- the tree/save/compile controller -- talks to this, never
 * to `window.monaco`. Two reasons, both load-bearing:
 *
 *  1. **Testability.** The controller is the part with logic in it
 *     (preconditions, conflict handling, diagnostics routing). Coupling
 *     it to a live Monaco instance would mean a browser to test it, and
 *     the CI runner has none. `./app.test.ts` passes a 30-line fake
 *     implementing this interface and asserts the real behaviour.
 *  2. **Type-safety without bundling.** The page loads Monaco's *AMD*
 *     build (`./vendor/monaco/vs/loader.js` -> `vs/editor/editor.main`),
 *     because the CSP is `script-src 'self'` and the static bundle has
 *     no bundler step. Monaco's shipped `monaco.d.ts` declares an `IMonaco`
 *     namespace that is only reachable through an ESM import of the
 *     package, which we deliberately do not emit -- so this file
 *     restates, by hand, exactly the members `./editor.ts` touches.
 *     Anything not declared here cannot be used by accident.
 *
 * The shapes are matched against `monaco-editor` 0.57.0 (the pin in
 * `web-client/package.json`, MIT-licensed and self-hosted per M-IDE-3).
 */

export type MarkerSeverity = "error" | "warning" | "info";

/** The two marker owners in the IDE, and no others: `loom-ide` is the
 * result of a save-and-compile round trip, `loom-lsp` is the live
 * analyser's `publishDiagnostics`. A third owner would be a third
 * unread set of squiggles on the same line. */
export type MarkerOwner = "loom-ide" | "loom-lsp";

export interface EditorMarker {
  /** 1-based, as the compiler renders it (`loom-syntax`'s
   * `Diagnostic::render`), so no adjustment happens at the boundary. */
  line: number;
  /** 1-based character column. */
  column: number;
  endLine: number;
  endColumn: number;
  severity: MarkerSeverity;
  message: string;
  code?: string;
}

/** What the controller needs from whatever is showing the text. */
export interface EditorPort {
  /** Load `text` as the contents of `path`, replacing whatever model was
   * open. Must reset dirty state and markers. */
  openText(path: string, text: string): void;
  /** The buffer's current text (may differ from disk: unsaved edits). */
  currentText(): string;
  /** The path `openText` last loaded, or `null` when nothing is open. */
  currentPath(): string | null;
  /** Replace all markers this editor owns (a save/compile round trip's
   * result). `owner` is Monaco's marker namespace: the live analyser
   * (`./lsp-bridge.ts`) and the save path write to different ones so
   * neither can erase the other's squiggles, and a builder can tell
   * "what the driver thinks of the file on disk" apart from "what the
   * analyser thinks of the text on screen". Defaults to `"loom-ide"`. */
  setMarkers(markers: EditorMarker[], owner?: MarkerOwner): void;
  /** Scroll/reveal a 1-based line, for "click a diagnostic, go there". */
  revealLine(line: number): void;
  /** Focus the editor. */
  focus(): void;
  /** Register a handler for the save gesture (Ctrl/Cmd-S, and the Save
   * button, which the controller treats the same). Returns a disposer. */
  onSave(handler: () => void): () => void;
  /** Register a handler for buffer edits, for the dirty flag. */
  onChangeContent(handler: () => void): () => void;
  /** Dispose the underlying widget. */
  dispose(): void;
}

/**
 * The minimum the AMD global exposes. Declared as a plain interface with
 * methods returning `unknown`-ish shapes rather than `any`, so
 * `./editor.ts` is where every cast happens -- one place to audit when
 * the pin moves.
 */
export interface MonacoEnvironmentGlobal {
  /** `require.config({ paths: { vs } })` was called with this as the
   * base; `vs/base/worker/workerMain.js` is resolved relative to it. */
  getWorkerUrl?(workerId: string, label: string): string;
  getWorker?(workerId: string, label: string): Worker;
}
