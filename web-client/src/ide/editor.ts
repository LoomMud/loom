// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The Monaco-backed `EditorPort` (OBI-180 M-IDE-3/M-IDE-4). This is the
 * only module in the IDE that touches the AMD `monaco` global, so the
 * M-IDE-2 carve-outs -- what may render as markup, what may become a
 * link, what may load -- are auditable in one file.
 *
 * The editor is loaded from `./vendor/monaco/vs` (M-IDE-3: self-hosted,
 * no CDN), staged by `npm run vendor` from the exact `monaco-editor`
 * version `web-client/package.json` pins and the lockfile resolves. The
 * page boots it through `amd-boot.ts` because the CSP is
 * `script-src 'self'` and Monaco's AMD build is a classic script; there
 * is no bundler in this repo's web client, and adding one to get an ESM
 * Monaco would be a bigger supply-chain change than vendoring a
 * directory.
 */

import type { EditorMarker, EditorPort } from "./editor-port.js";
import { LPC_LANGUAGE, lpcLanguageConfiguration, lpcTokenizer } from "./lpc.js";
import { safeLinkUrls, sanitizeLinkUrl, VFS_SCHEME } from "./links.js";

/** The members of the AMD `monaco` global this module uses. Everything is
 * optional-typed and cast at the boundary in `createMonacoEditor`: the
 * alternative -- importing `monaco-editor`'s `monaco.d.ts` -- would make
 * the build depend on an ESM import of a package that is only ever loaded
 * as a classic script, and would let the code reference API that isn't
 * in the vendored `min/vs` bundle at all. */
export interface MonacoLike {
  editor: {
    create(dom: HTMLElement, options?: Record<string, unknown>): EditorLike;
  };
  Uri: { parse(value: string): unknown };
  MarkerSeverity: { Error: number; Warning: number; Info: number };
  languages: {
    register(language: { id: string }): void;
    setMonarchTokensProvider(id: string, rules: unknown): unknown;
    setLanguageConfiguration(id: string, config: unknown): unknown;
    registerDocumentLinkProvider(id: string, provider: unknown): unknown;
    registerCompletionItemProvider?(id: string, provider: unknown): unknown;
    registerHoverProvider?(id: string, provider: unknown): unknown;
    /** Monaco's own `CompletionItemKind` enum. Its numbering is Monaco's
     * (Method is 0, Text is 18) and shares nothing with LSP's, so the
     * mapping in `./lsp-monaco.ts` looks members up by name. */
    CompletionItemKind?: Record<string, number>;
  };
  KeyMod: { CtrlCmd: number; Alt: number };
  KeyCode: { KeyS: number };
}

export interface IDisposable {
  dispose(): void;
}

export interface TextModelLike {
  getValue(): string;
  setValue(value: string): void;
  uri: unknown;
  onDidChangeContent(handler: () => void): IDisposable;
  dispose(): void;
}

export interface EditorLike {
  getModel(): TextModelLike | null;
  setModel(model: TextModelLike): void;
  updateOptions(options: Record<string, unknown>): void;
  revealLineInCenter(line: number): void;
  focus(): void;
  layout(): void;
  dispose(): void;
  addCommand(keybinding: number, handler: () => void): void;
  onDidChangeModelContent(handler: () => void): IDisposable;
}

/** `IMarkdownString` as the vendored build expects it (M-IDE-2): both
 * flags are set explicitly, never left to a default that a version bump
 * could flip. `isTrusted: false` means Monaco renders the value as text
 * and refuses raw HTML; `supportHtml: false` is the belt to that. */
export function safeMarkdown(value: string): {
  value: string;
  isTrusted: false;
  supportHtml: false;
  supportThemeIcons: false;
} {
  return { value, isTrusted: false, supportHtml: false, supportThemeIcons: false };
}

const SEVERITY_TO_MONACO = {
  error: "Error",
  warning: "Warning",
  info: "Info",
} as const;

/** One open document, as the IDE models it. `loom-vfs:<path>` is the
 * model URI -- a scheme the browser cannot resolve, which is the point:
 * nothing about opening a mudlib file can reach the network or the real
 * filesystem, and `linkProvider` maps a click back onto a `/files` read
 * the driver authorises (M-IDE-2). */
export function modelUri(path: string): string {
  return `${VFS_SCHEME}${path}`;
}

export interface MonacoEditorOptions {
  monaco: MonacoLike;
  container: HTMLElement;
  /** Called when the save gesture fires; the controller owns the write. */
  onSave: () => void;
}

/** Register `loom-lpc` once per Monaco instance. Idempotent by
 * construction: the IDE creates exactly one editor and calls this before
 * the first model exists, and Monaco tolerates a re-registration of the
 * same id (last writer wins) rather than erroring. */
export function registerLpcLanguage(monaco: MonacoLike): void {
  monaco.languages.register({ id: LPC_LANGUAGE });
  monaco.languages.setMonarchTokensProvider(LPC_LANGUAGE, lpcTokenizer());
  monaco.languages.setLanguageConfiguration(LPC_LANGUAGE, lpcLanguageConfiguration());
  monaco.languages.registerDocumentLinkProvider(LPC_LANGUAGE, linkProvider());
}

/**
 * M-IDE-2's link rule, enforced where links are made: scan the document
 * for URL-looking text, keep only what [`sanitizeLinkUrl`] accepts, and
 * hand Monaco a provider over exactly those ranges. Monaco's *built-in*
 * link detection is turned off in the editor options (`links: false`),
 * so this is the only path by which a clickable link enters the view --
 * a `javascript:` URL in a builder's doc comment produces no link at all.
 */
function linkProvider(): unknown {
  return {
    provideLinks(model: { getLineCount(): number; getLineContent(n: number): string }) {
      const links: unknown[] = [];
      for (let line = 1; line <= model.getLineCount(); line += 1) {
        const content = model.getLineContent(line);
        for (const url of safeLinkUrls(content)) {
          const column = content.indexOf(url);
          if (column < 0) {
            continue;
          }
          links.push({
            range: {
              startLineNumber: line,
              startColumn: column + 1,
              endLineNumber: line,
              endColumn: column + 1 + url.length,
            },
            url,
          });
        }
      }
      return { links };
    },
  };
}

/** `monaco.editor.createModel(value, language, uri)` -- separated so the
 * cast to the untyped AMD surface happens once. */
function createModel(monaco: MonacoLike, text: string, path: string): TextModelLike {
  const factory = monaco.editor as unknown as {
    createModel(value: string, language: string | undefined, uri: unknown): TextModelLike;
  };
  return factory.createModel(text, LPC_LANGUAGE, monaco.Uri.parse(modelUri(path)));
}

/** Create the widget and return the port the controller drives. */
export function createMonacoEditor(options: MonacoEditorOptions): EditorPort {
  const { monaco, container } = options;
  registerLpcLanguage(monaco);

  const editor = monaco.editor.create(container, {
    value: "",
    language: LPC_LANGUAGE,
    automaticLayout: true,
    // M-IDE-2: the built-in document-link scanner is off; links come only
    // from `linkProvider` above.
    links: false,
    // Alpha scale: the minimap and the sticky scrollbars cost layout work
    // on the main thread for no benefit in a tree this shallow.
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    renderWhitespace: "selection",
    tabSize: 2,
    readOnly: false,
    wordWrap: "off",
    contextmenu: true,
    // Never let a suggestion/hover's markup become HTML (M-IDE-2).
    hover: { enabled: true, above: true },
    quickSuggestions: { other: true, comments: false, strings: false },
  });

  // One Ctrl/S binding for the widget's lifetime, dispatched through a
  // mutable handler: Monaco's `addCommand` has no per-binding disposer, so
  // calling it again per `onSave()` registration would stack bindings and
  // fire the save once per re-registration.
  let saveHandler: () => void = options.onSave;
  editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
    saveHandler();
  });

  let path: string | null = null;
  const contentSubscriptions: IDisposable[] = [];

  return {
    openText(nextPath, text) {
      const previous = editor.getModel();
      // One model per open document: `setModel` on a freshly created model
      // with the new `loom-vfs:` URI is what makes the title, the
      // markers' ownership, and a future multi-tab IDE all fall out of the
      // same path. The old model is disposed rather than left reference-
      // counted -- Monaco keeps every model it has ever created alive
      // otherwise, and an 8-hour editing session would grow without
      // bound.
      const next = createModel(monaco, text, nextPath);
      editor.setModel(next);
      if (previous !== null) {
        previous.dispose();
      }
      path = nextPath;
    },
    currentText() {
      return editor.getModel()?.getValue() ?? "";
    },
    currentPath() {
      return path;
    },
    setMarkers(markers, owner = "loom-ide") {
      const model = editor.getModel();
      if (model === null) {
        return;
      }
      const severity = monaco.MarkerSeverity;
      (monaco.editor as unknown as {
        setModelMarkers(uri: unknown, owner: string, markers: unknown[]): void;
      }).setModelMarkers(model.uri, owner, markers.map((marker) => markerToMonaco(marker, severity)));
      editor.layout();
    },
    revealLine(line) {
      editor.revealLineInCenter(line);
    },
    focus() {
      editor.focus();
    },
    onSave(handler) {
      saveHandler = handler;
      return () => {
        saveHandler = options.onSave;
      };
    },
    onChangeContent(handler) {
      const subscription = editor.onDidChangeModelContent(handler);
      contentSubscriptions.push(subscription);
      return () => subscription.dispose();
    },
    dispose() {
      for (const subscription of contentSubscriptions) {
        subscription.dispose();
      }
      editor.dispose();
    },
  };
}

function markerToMonaco(
  marker: EditorMarker,
  severity: MonacoLike["MarkerSeverity"],
): Record<string, unknown> {
  return {
    startLineNumber: marker.line,
    startColumn: marker.column,
    endLineNumber: marker.endLine,
    endColumn: marker.endColumn,
    message: marker.code !== null ? `${marker.message} [${marker.code}]` : marker.message,
    severity: severity[SEVERITY_TO_MONACO[marker.severity]],
    code: marker.code ?? undefined,
  };
}

/** `sanitizeLinkUrl` re-exported for `./app.ts`'s click handling, so the
 * allow-list is imported from one module rather than re-derived. */
export { sanitizeLinkUrl };
