// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import test from "node:test";
import assert from "node:assert/strict";

import type { MonacoLike } from "./editor.js";
import type { CompletionAnswer, HoverAnswer } from "./lsp-session.js";
import { pathFromModelUri, registerLspProviders } from "./lsp-monaco.js";

/** The three members of the AMD global the providers touch, faked. `kinds` is
 * Monaco's *own* numbering, which starts at Method = 0 -- using LSP's number
 * as Monaco's would put the wrong icon on every suggestion. */
function fakeMonaco(options: { kinds?: Record<string, number> | null } = {}) {
  const kinds = options.kinds === null ? undefined : (options.kinds ?? { Function: 1, Text: 18, Event: 10 });
  const hoverProviders: { provideHover(model: unknown, position: unknown): unknown }[] = [];
  const completionProviders: {
    triggerCharacters?: string[];
    provideCompletionItems(model: unknown, position: unknown): unknown;
  }[] = [];
  const monaco = {
    languages: {
      register: () => ({ dispose() {} }),
      setMonarchTokensProvider: () => ({ dispose() {} }),
      setLanguageConfiguration: () => ({ dispose() {} }),
      registerDocumentLinkProvider: () => ({ dispose() {} }),
      CompletionItemKind: kinds,
      registerHoverProvider: (_language: string, provider: (typeof hoverProviders)[number]) => {
        hoverProviders.push(provider);
        return { dispose() {} };
      },
      registerCompletionItemProvider: (
        _language: string,
        provider: (typeof completionProviders)[number],
      ) => {
        completionProviders.push(provider);
        return { dispose() {} };
      },
    },
  } as unknown as MonacoLike;
  return { monaco, hoverProviders, completionProviders };
}

function model(path: string, scheme = "loom-vfs") {
  return { uri: { scheme, path } };
}

function uriOnly(value: string) {
  return { uri: { toString: () => value } };
}

function harness(answer: Partial<{ hover: HoverAnswer | null; completion: CompletionAnswer[] }> = {}) {
  const asked: string[] = [];
  const ask = {
    hover(path: string, line: number, column: number): Promise<HoverAnswer | null> {
      asked.push(`hover ${path} ${line} ${column}`);
      return Promise.resolve(answer.hover ?? null);
    },
    completion(path: string, line: number, column: number): Promise<CompletionAnswer[]> {
      asked.push(`completion ${path} ${line} ${column}`);
      return Promise.resolve(answer.completion ?? []);
    },
  };
  return { ask, asked };
}

test("a model URI maps to the file path the analyser is asked about", () => {
  // The IDE's model URI is `loom-vfs:/std/room.wf` (one slash, because that is
  // what a model URI is); the wire form is three slashes. Both name the same
  // file, and a provider that derived the path from the wrong one would ask
  // about a document nobody opened.
  assert.equal(pathFromModelUri(model("/std/room.wf")), "/std/room.wf");
  assert.equal(pathFromModelUri(uriOnly("loom-vfs:/a.wf")), "/a.wf");
  assert.equal(pathFromModelUri(model("/etc/passwd.wf", "file")), null);
  assert.equal(pathFromModelUri(model("/std/../x.wf")), null);
  assert.equal(pathFromModelUri(model("/std/room.txt")), null);
});

test("hover renders as untrusted, html-free markdown", async () => {
  // M-IDE-2 in the one place the analyser's text reaches the screen. A hover
  // body is built partly from builder text, so `isTrusted`/`supportHtml` being
  // false is not a style preference.
  const { monaco, hoverProviders } = fakeMonaco();
  const { ask } = harness({
    hover: {
      text: "# [click me](javascript:alert(1))",
      range: { startLine: 3, startColumn: 1, endLine: 3, endColumn: 8 },
    },
  });
  registerLspProviders(monaco, ask);
  const result = (await hoverProviders[0]?.provideHover(model("/a.wf"), {
    lineNumber: 3,
    column: 5,
  })) as { contents: Record<string, unknown>[]; range?: Record<string, number> };
  assert.ok(result, "a hover answer must be returned, not swallowed");
  const [contents] = result.contents;
  assert.equal(contents?.["value"], "# [click me](javascript:alert(1))");
  assert.equal(contents?.["isTrusted"], false);
  assert.equal(contents?.["supportHtml"], false);
  assert.equal(contents?.["supportThemeIcons"], false);
  assert.deepEqual(result.range, {
    startLineNumber: 3,
    startColumn: 1,
    endLineNumber: 3,
    endColumn: 8,
  });
});

test("no hover means no result, and nothing is asked of a foreign model", async () => {
  const { monaco, hoverProviders } = fakeMonaco();
  const { ask, asked } = harness();
  registerLspProviders(monaco, ask);
  assert.equal(await hoverProviders[0]?.provideHover(model("/other.txt"), { lineNumber: 1, column: 1 }), null);
  assert.equal(asked.length, 0, "a model that is not a mudlib file is not analyzed");
  assert.equal(await hoverProviders[0]?.provideHover(model("/a.wf"), { lineNumber: 1, column: 1 }), null);
  assert.deepEqual(asked, ["hover /a.wf 1 1"]);
});

test("completion items carry Monaco's kind, the label as insertText, and text documentation", async () => {
  const { monaco, completionProviders } = fakeMonaco();
  const { ask } = harness({
    completion: [
      { label: "foo", kind: 3, detail: "int foo()", documentation: "Returns one." },
      { label: "bar", kind: null, detail: "", documentation: "" },
      { label: "weird", kind: 999, detail: "", documentation: "" }, // a kind loom-lsp does not send today
    ],
  });
  registerLspProviders(monaco, ask);
  const list = (await completionProviders[0]?.provideCompletionItems(model("/a.wf"), {
    lineNumber: 2,
    column: 4,
  })) as { suggestions: Record<string, unknown>[] };
  assert.deepEqual(list.suggestions, [
    { label: "foo", kind: 1, insertText: "foo", detail: "int foo()", documentation: "Returns one." },
    // `kind: null` and an unknown number both land on `Text`, not on 0 --
    // Monaco's 0 is `Method`, so an unmapped value would be a wrong icon on
    // every other suggestion in the list.
    { label: "bar", kind: 18, insertText: "bar" },
    { label: "weird", kind: 18, insertText: "weird" },
  ]);
  assert.deepEqual(completionProviders[0]?.triggerCharacters, ["."], "the server's one trigger");
});

test("a build without the language features loses the feature, not the editor", () => {
  // `MonacoLike` types every registration as optional because the AMD global
  // is not audited per call site. A missing member must mean "no hover", not a
  // throw during mount -- which is the difference between a degraded IDE and a
  // blank pane.
  const bare = {
    languages: {
      register: () => ({}),
      setMonarchTokensProvider: () => ({}),
      setLanguageConfiguration: () => ({}),
      registerDocumentLinkProvider: () => ({}),
    },
  } as unknown as MonacoLike;
  const { ask } = harness();
  assert.deepEqual(registerLspProviders(bare, ask), []);

  const { monaco } = fakeMonaco({ kinds: null });
  const disposables = registerLspProviders(monaco, ask);
  assert.equal(disposables.length, 2);
  for (const disposable of disposables) {
    assert.doesNotThrow(() => disposable.dispose());
  }
});

test("a provider that is asked for nothing returns the empty shape Monaco wants", async () => {
  const { monaco, completionProviders } = fakeMonaco();
  const { ask, asked } = harness({ completion: [] });
  registerLspProviders(monaco, ask);
  const empty = await completionProviders[0]?.provideCompletionItems(model("/nope.txt"), {
    lineNumber: 1,
    column: 1,
  });
  assert.deepEqual(empty, { suggestions: [] });
  const answer = await completionProviders[0]?.provideCompletionItems(model("/a.wf"), {
    lineNumber: 1,
    column: 1,
  });
  assert.deepEqual(answer, { suggestions: [] });
  assert.deepEqual(asked, ["completion /a.wf 1 1"]);
});
