// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import test from "node:test";
import assert from "node:assert/strict";

import {
  createMonacoEditor,
  modelUri,
  registerLpcLanguage,
  safeMarkdown,
  type IDisposable,
  type MonacoLike,
  type TextModelLike,
} from "./editor.js";
import { LPC_LANGUAGE } from "./lpc.js";

/** A stand-in for the AMD `monaco` global, recording what `./editor.ts`
 * asked of it. `editor.test.ts` is the only place the M-IDE-2 option set
 * can be asserted without a browser: the flags are data, and a regression
 * that drops one is a data diff, not a screenshot. */
class FakeMonaco implements Partial<MonacoLike> {
  readonly registrations: string[] = [];
  readonly providers: { document?: unknown } = {};
  readonly calls: string[] = [];
  created: FakeEditor[] = [];
  MarkerSeverity = { Error: 8, Warning: 4, Info: 2 };
  KeyMod = { CtrlCmd: 2048, Alt: 512 };
  KeyCode = { KeyS: 49 };
  Uri = { parse: (value: string) => ({ toString: () => value, value }) };

  editor = {
    create: (_dom: HTMLElement, options?: Record<string, unknown>) => {
      this.calls.push(`create:${JSON.stringify(options ?? {})}`);
      const editor = new FakeEditor(this, options ?? {});
      this.created.push(editor);
      return editor;
    },
    createModel: (value: string, language: string | undefined, uri: unknown) => {
      this.calls.push(`createModel:${language}:${String((uri as { value?: string }).value ?? uri)}`);
      return new FakeModel(value, String((uri as { value?: string }).value ?? uri), this);
    },
    setModelMarkers: (uri: unknown, owner: string, markers: unknown[]) => {
      this.calls.push(`setModelMarkers:${owner}:${String((uri as { value?: string }).value ?? uri)}`);
      (this as unknown as { lastMarkers: unknown[] }).lastMarkers = markers;
    },
  } as unknown as MonacoLike["editor"];

  languages = {
    register: (language: { id: string }) => {
      this.registrations.push(language.id);
    },
    setMonarchTokensProvider: (id: string) => {
      this.calls.push(`tokens:${id}`);
      return { dispose: () => {} } as never;
    },
    setLanguageConfiguration: (id: string) => {
      this.calls.push(`config:${id}`);
      return { dispose: () => {} } as never;
    },
    registerDocumentLinkProvider: (_id: string, provider: unknown) => {
      this.providers.document = provider;
      this.calls.push("links-provider");
      return {} as never;
    },
  } as unknown as MonacoLike["languages"];
}

class FakeModel {
  disposed = false;
  constructor(
    private value: string,
    readonly uri: string,
    private readonly owner: FakeMonaco,
  ) {}
  getValue(): string {
    return this.value;
  }
  setValue(value: string): void {
    this.value = value;
  }
  getLineCount(): number {
    return this.value.split("\n").length;
  }
  getLineContent(line: number): string {
    return this.value.split("\n")[line - 1] ?? "";
  }
  onDidChangeContent(): IDisposable {
    return { dispose: () => {} };
  }
  dispose(): void {
    this.disposed = true;
    this.owner.calls.push(`disposeModel:${this.uri}`);
  }
}

class FakeEditor {
  model: TextModelLike | null = null;
  commands: (() => void)[] = [];
  revealed: number[] = [];
  disposed = false;
  layoutCount = 0;

  constructor(
    private readonly monaco: FakeMonaco,
    readonly options: Record<string, unknown>,
  ) {}

  getModel(): TextModelLike | null {
    return this.model;
  }
  setModel(model: TextModelLike): void {
    this.model = model;
  }
  updateOptions(options: Record<string, unknown>): void {
    Object.assign(this.options, options);
  }
  addCommand(_binding: number, handler: () => void): void {
    this.commands.push(handler);
  }
  onDidChangeContent(): IDisposable {
    return { dispose: () => {} };
  }
  revealLineInCenter(line: number): void {
    this.revealed.push(line);
  }
  focus(): void {}
  layout(): void {
    this.layoutCount += 1;
  }
  dispose(): void {
    this.disposed = true;
  }
}

function editor(): FakeEditor {
  const monaco = new FakeMonaco();
  const port = createMonacoEditor({
    monaco: monaco as unknown as MonacoLike,
    container: {} as HTMLElement,
    onSave: () => {},
  });
  port.openText("/cmds/kill.c", "int f() {}");
  void port;
  const created = monaco.created[0];
  assert.ok(created);
  return created;
}

function monacoWithPort(): { monaco: FakeMonaco; port: ReturnType<typeof createMonacoEditor> } {
  const monaco = new FakeMonaco();
  const port = createMonacoEditor({
    monaco: monaco as unknown as MonacoLike,
    container: {} as HTMLElement,
    onSave: () => {},
  });
  return { monaco, port };
}

test("the language is registered before the first model, under loom-lpc", () => {
  const monaco = new FakeMonaco();
  registerLpcLanguage(monaco as unknown as MonacoLike);
  assert.deepEqual(monaco.registrations, [LPC_LANGUAGE]);
  assert.deepEqual(monaco.calls, [`tokens:${LPC_LANGUAGE}`, `config:${LPC_LANGUAGE}`, "links-provider"]);
});

test("models are addressed by a loom-vfs URI, never a file: or https: one", () => {
  assert.equal(modelUri("/cmds/kill.c"), "loom-vfs:/cmds/kill.c");
  const { monaco, port } = monacoWithPort();
  port.openText("/cmds/kill.c", "int f() {}");
  assert.ok(
    monaco.calls.some((c) => c === `createModel:loom-lpc:loom-vfs:/cmds/kill.c`),
    monaco.calls.join("\n"),
  );
});

test("M-IDE-2: the editor is created with Monaco's own link scanner off", () => {
  const created = editor();
  assert.equal(created.options.links, false);
  assert.equal(created.options.language, LPC_LANGUAGE);
  assert.equal(created.options.readOnly, false);
});

test("M-IDE-2: markdown Monaco could render is untrusted and html-free at both flags", () => {
  const markdown = safeMarkdown("see [x](https://www.example.com)");
  assert.equal(markdown.isTrusted, false);
  assert.equal(markdown.supportHtml, false);
  assert.equal(markdown.supportThemeIcons, false);
  assert.equal(markdown.value, "see [x](https://www.example.com)");
});

test("markers are 1-based in and out, with Monaco's numeric severity", () => {
  const { monaco, port } = monacoWithPort();
  port.openText("/a.c", "line one\nline two");
  port.setMarkers([
    { line: 12, column: 9, endLine: 12, endColumn: 12, severity: "error", message: "unknown efun", code: "W0201" },
    { line: 2, column: 1, endLine: 2, endColumn: 4, severity: "warning", message: "unused" },
  ]);
  const markers = (monaco as unknown as { lastMarkers: Record<string, unknown>[] }).lastMarkers;
  assert.equal(markers.length, 2);
  assert.deepEqual(
    [markers[0]!.startLineNumber, markers[0]!.startColumn, markers[0]!.endColumn],
    [12, 9, 12],
  );
  assert.equal(markers[0]!.severity, 8);
  assert.equal(markers[1]!.severity, 4);
  assert.match(String(markers[0]!.message), /unknown efun \[W0201\]/);
});

test("Ctrl/Cmd-S runs the controller's save, and re-registering does not stack", () => {
  const monaco = new FakeMonaco();
  let saves = 0;
  const port = createMonacoEditor({
    monaco: monaco as unknown as MonacoLike,
    container: {} as HTMLElement,
    onSave: () => {
      saves += 1;
    },
  });
  const created = monaco.created[0]!;
  assert.equal(created.commands.length, 1);
  created.commands[0]!();
  assert.equal(saves, 1);

  // A second registration (a re-mount, a test harness) replaces the
  // handler instead of adding a second binding that would fire twice.
  let other = 0;
  port.onSave(() => {
    other += 1;
  });
  created.commands[0]!();
  created.commands[0]!();
  assert.equal(saves, 1);
  assert.equal(other, 2);
});

test("re-opening a file disposes the previous model instead of leaking it", () => {
  const monaco = new FakeMonaco();
  const port = createMonacoEditor({
    monaco: monaco as unknown as MonacoLike,
    container: {} as HTMLElement,
    onSave: () => {},
  });
  port.openText("/a.c", "one");
  port.openText("/b.c", "two");
  assert.ok(
    monaco.calls.some((c) => c === "disposeModel:loom-vfs:/a.c"),
    monaco.calls.join("\n"),
  );
  assert.equal(port.currentPath(), "/b.c");
  assert.equal(port.currentText(), "two");
});

test("revealLine and focus reach the widget", () => {
  const monaco = new FakeMonaco();
  const port = createMonacoEditor({
    monaco: monaco as unknown as MonacoLike,
    container: {} as HTMLElement,
    onSave: () => {},
  });
  port.openText("/a.c", "x");
  port.revealLine(7);
  port.focus();
  port.dispose();
  const created = monaco.created[0]!;
  assert.deepEqual(created.revealed, [7]);
  assert.equal(created.disposed, true);
});

test("the document link provider only ever offers allow-listed urls", () => {
  const monaco = new FakeMonaco();
  registerLpcLanguage(monaco as unknown as MonacoLike);
  const provider = monaco.providers.document as {
    provideLinks(model: unknown): { links: { url: string; range: unknown }[] };
  };
  const model = new FakeModel(
    [
      "// see [docs](https://www.example.com/d)",
      "// evil [x](javascript:alert(1)) and [y](data:text/html,<b>)",
      "// local loom-vfs:/adm/room.c",
    ].join("\n"),
    "loom-vfs:/a.c",
    monaco,
  ) as unknown as TextModelLike;
  const urls = provider.provideLinks(model).links.map((l) => l.url);
  assert.deepEqual(urls, ["https://www.example.com/d", "loom-vfs:/adm/room.c"]);
});
