// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Monaco's hover and completion, answered by `loom-lsp` (OBI-180 spec
 * M-IDE-2/M-LSP-5).
 *
 * Two rules shape this file more than the API does.
 *
 * **Nothing here may become markup.** A hover's body is a driver-side string
 * built partly from builder text -- an efun signature, a function declared in a
 * file someone else wrote, and through `codeDescription`-style fields anything
 * a doc comment can hold. It goes through `./editor.ts`'s `safeMarkdown`, which
 * sets `isTrusted: false` and `supportHtml: false` explicitly, so Monaco renders
 * it as text. That is the same rule the vendored worker already falls under, and
 * it is why the value is built here rather than handed to Monaco as a bare
 * string: a bare string is an `IMarkdownString` with the defaults, and the
 * defaults are what a future Monaco version is free to change.
 *
 * **A provider that cannot answer must return nothing, not throw.** Monaco calls
 * these from inside its own async request pipeline, where a rejection becomes an
 * error notification to the builder. `loom-lsp` being unreachable, busy, or
 * mid-reconnect is a momentary condition with a momentary answer: no hover, no
 * suggestions, and the status line (`./lsp-bridge.ts`) already carries the
 * reason if it is worth saying.
 *
 * The one asymmetry with a normal LSP client is *which* document a request is
 * about. The IDE shows one buffer, whose Monaco model URI is `loom-vfs:/path`
 * (the scheme's one-slash form, which is what a model URI is), while the wire URI
 * is `loom-vfs:///path.wf` (three slashes, an empty authority -- see
 * `./lsp-uri.ts`). Deriving the request's path from the model the provider was
 * handed, rather than from whatever the bridge last opened, is what keeps a
 * response about file A from being reported at a position in file B.
 */

import type { IDisposable, MonacoLike } from "./editor.js";
import { safeMarkdown } from "./editor.js";
import { VFS_SCHEME } from "./links.js";
import type { CompletionAnswer, HoverAnswer } from "./lsp-session.js";
import { LPC_LANGUAGE } from "./lpc.js";
import { isMudlibFilePath } from "./lsp-uri.js";

/** What the providers need: the two read-only questions the analyser answers.
 * Satisfied by `LspBridge.providers`. */
export interface LspAsk {
  hover(path: string, line: number, column: number): Promise<HoverAnswer | null>;
  completion(path: string, line: number, column: number): Promise<CompletionAnswer[]>;
}

/** A position as Monaco hands it to a provider: 1-based, the same convention
 * `EditorMarker` uses. */
interface MonacoPosition {
  lineNumber: number;
  column: number;
}

interface MonacoModel {
  uri: { path?: string; scheme?: string; toString?(): string };
}

/** LSP's `CompletionItemKind` (1..25, `textDocument/completion`) -> the name of
 * the Monaco enum member that means the same thing. loom-lsp emits `Function`
 * (3), `Event` (23), `Method` (2), `Field` (5) and `Constant` (21); the rest of
 * the table is here so a capability the server starts using is not a mystery
 * box in the widget. */
const LSP_KIND_TO_MONACO_NAME: Record<number, string> = {
  1: "Text",
  2: "Method",
  3: "Function",
  4: "Constructor",
  5: "Field",
  6: "Variable",
  7: "Class",
  8: "Interface",
  9: "Module",
  10: "Property",
  11: "Unit",
  12: "Value",
  13: "Enum",
  14: "Keyword",
  15: "Snippet",
  16: "Color",
  17: "File",
  18: "Reference",
  19: "Folder",
  20: "EnumMember",
  21: "Constant",
  22: "Struct",
  23: "Event",
  24: "Operator",
  25: "TypeParameter",
};

/** The mudlib file path a model URI names, or `null`. Accepts both the
 * one-slash model form and the three-slash wire form, because both are the same
 * path to a URI parser and a future change to `modelUri` must not silently
 * disable live analysis. */
export function pathFromModelUri(model: MonacoModel): string | null {
  const path =
    typeof model.uri.path === "string"
      ? model.uri.path
      : typeof model.uri.toString === "function"
        ? stripScheme(model.uri.toString())
        : null;
  if (path === null) {
    return null;
  }
  const scheme = typeof model.uri.scheme === "string" ? model.uri.scheme : null;
  if (scheme !== null && scheme !== VFS_SCHEME.slice(0, -1)) {
    return null;
  }
  return isMudlibFilePath(path) ? path : null;
}

function stripScheme(value: string): string | null {
  return value.startsWith(VFS_SCHEME) ? value.slice(VFS_SCHEME.length) : null;
}

/** Range in Monaco's 1-based terms, from the session's already-converted
 * answer. */
function toMonacoRange(range: HoverAnswer["range"]): Record<string, number> | null {
  if (range === null) {
    return null;
  }
  return {
    startLineNumber: range.startLine,
    startColumn: range.startColumn,
    endLineNumber: range.endLine,
    endColumn: range.endColumn,
  };
}

/**
 * Register the hover and completion providers for `loom-lpc`. Returns
 * disposables; Monaco's language features outlive one editor (they are
 * registered per language id, per Monaco instance), so a caller that throws
 * away the editor without disposing these would leave a provider pointing at a
 * dead session -- which is the failure mode where a builder's hover silently
 * stops working after a sign-out.
 */
export function registerLspProviders(monaco: MonacoLike, ask: LspAsk): IDisposable[] {
  const disposables: IDisposable[] = [];
  const { languages } = monaco;
  // Capability checks, not guesses: `./editor.ts`'s `MonacoLike` types every
  // language-feature entry as optional because the AMD global is not audited
  // per call site, and a vendored build that lacks one should lose that
  // feature, not the IDE.
  if (typeof languages.registerHoverProvider === "function") {
    const hover = languages.registerHoverProvider(LPC_LANGUAGE, {
      async provideHover(model: MonacoModel, position: MonacoPosition) {
        const path = pathFromModelUri(model);
        if (path === null) {
          return null;
        }
        const answer = await ask.hover(path, position.lineNumber, position.column);
        if (answer === null) {
          return null;
        }
        const contents = [safeMarkdown(answer.text)];
        const range = toMonacoRange(answer.range);
        return range === null ? { contents } : { contents, range };
      },
    });
    if (isDisposable(hover)) {
      disposables.push(hover);
    }
  }

  if (typeof languages.registerCompletionItemProvider === "function") {
    const completion = languages.registerCompletionItemProvider(LPC_LANGUAGE, {
      // loom-lsp advertises exactly one trigger character, and completion at
      // any other position is Monaco's own word-based suggestion path -- this
      // adds the analyser's list where the builder typed a dot.
      triggerCharacters: ["."],
      provideCompletionItems(model: MonacoModel, position: MonacoPosition) {
        const path = pathFromModelUri(model);
        if (path === null) {
          return { suggestions: [] };
        }
        return ask
          .completion(path, position.lineNumber, position.column)
          .then((items) => ({
            suggestions: items.map((item) => completionItem(monaco, item)),
          }));
      },
    });
    if (isDisposable(completion)) {
      disposables.push(completion);
    }
  }
  return disposables;
}

function completionItem(monaco: MonacoLike, item: CompletionAnswer): Record<string, unknown> {
  const kinds = monaco.languages.CompletionItemKind ?? {};
  const name = item.kind === null ? "Text" : (LSP_KIND_TO_MONACO_NAME[item.kind] ?? "Text");
  // A missing enum member falls back to `Text` explicitly. Monaco's own
  // numbering starts at Method = 0, so an `undefined` kind would render as
  // the first icon in the list rather than a generic one.
  const kind = typeof kinds[name] === "number" ? kinds[name] : 18;
  const suggestion: Record<string, unknown> = {
    label: item.label,
    kind,
    // LSP's item carries no `insertText`, so the label is what gets inserted --
    // stated rather than left to Monaco's fallback, which resolves a `label`
    // that is an object (`CompletionItemLabel`) differently.
    insertText: item.label,
  };
  if (item.detail !== "") {
    suggestion["detail"] = item.detail;
  }
  if (item.documentation !== "") {
    // A plain string, not a `MarkupContent`: Monaco renders a string
    // documentation as text, and this is the one field of a completion item a
    // builder's own doc comment can fill (M-IDE-2).
    suggestion["documentation"] = item.documentation;
  }
  return suggestion;
}

function isDisposable(value: unknown): value is IDisposable {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { dispose?: unknown }).dispose === "function"
  );
}
