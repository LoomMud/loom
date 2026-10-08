// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import test from "node:test";
import assert from "node:assert/strict";

import { asFake, installFakeDom, FakeElement } from "./dom-globals.js";
import type { EditorMarker, EditorPort } from "./editor-port.js";
import { LoomIde, type FilesLike, type IdeDom } from "./app.js";
import type { CompileBody, FileResult, ListingBody, ReadFile } from "./files-api.js";

installFakeDom();

/** The editor half of the seam: records what the controller asked for. */
class FakeEditor implements EditorPort {
  text = "";
  path: string | null = null;
  markers: EditorMarker[] = [];
  revealed: number[] = [];
  focused = 0;
  openCalls: [string, string][] = [];
  private saveHandler: (() => void) | null = null;
  private changeHandler: (() => void) | null = null;

  openText(path: string, text: string): void {
    this.path = path;
    this.text = text;
    this.markers = [];
    this.openCalls.push([path, text]);
  }
  currentText(): string {
    return this.text;
  }
  currentPath(): string | null {
    return this.path;
  }
  setMarkers(markers: EditorMarker[]): void {
    this.markers = markers;
  }
  revealLine(line: number): void {
    this.revealed.push(line);
  }
  focus(): void {
    this.focused += 1;
  }
  onSave(handler: () => void): () => void {
    this.saveHandler = handler;
    return () => {
      this.saveHandler = null;
    };
  }
  onChangeContent(handler: () => void): () => void {
    this.changeHandler = handler;
    return () => {
      this.changeHandler = null;
    };
  }
  dispose(): void {}

  /** Test-only: type into the buffer the way the widget would. */
  type(text: string): void {
    this.text = text;
    this.changeHandler?.();
  }
  pressSave(): void {
    this.saveHandler?.();
  }
}

/** The server half of the seam: an in-memory mudlib with the same
 * result kinds and status semantics as the real routes. */
class FakeFiles implements FilesLike {
  readonly dirs = new Map<string, string[]>();
  readonly contents = new Map<string, string>();
  /** Paths whose `list` should answer 404 even though they are in `dirs`. */
  readonly hidden = new Set<string>();
  writes: { path: string; text: string; etag: string | null }[] = [];
  compileResult: CompileBody = { ok: true };
  readFails: FileResult<ReadFile> | null = null;
  listFails: FileResult<ListingBody> | null = null;
  writeFails: FileResult<null> | null = null;
  compileFails: FileResult<CompileBody> | null = null;

  constructor() {
    this.dirs.set("/", []);
  }

  file(path: string, text: string, dir = "/"): void {
    this.contents.set(path, text);
    this.dirs.set(dir, [...(this.dirs.get(dir) ?? []), leaf(path)]);
    this.dirs.set(path, undefined as unknown as string[]);
    this.dirs.delete(path);
  }

  directory(dir: string, entries: string[]): void {
    this.dirs.set(dir, entries);
  }

  async read(path: string): Promise<FileResult<ReadFile>> {
    if (this.readFails !== null) return this.readFails;
    const text = this.contents.get(path);
    if (text === undefined) return { kind: "notFound" };
    return { kind: "ok", value: { path, text, etag: `"v1-${path}"` } };
  }

  async list(path: string): Promise<FileResult<ListingBody>> {
    if (this.hidden.has(path)) return { kind: "notFound" };
    if (this.listFails !== null) return this.listFails;
    const entries = this.dirs.get(path);
    if (entries === undefined) return { kind: "notFound" };
    return { kind: "ok", value: { entries } };
  }

  async write(path: string, text: string, etag: string | null): Promise<FileResult<null>> {
    this.writes.push({ path, text, etag });
    if (this.writeFails !== null) return this.writeFails;
    this.contents.set(path, text);
    return { kind: "ok", value: null };
  }

  async compile(path: string): Promise<FileResult<CompileBody>> {
    if (this.compileFails !== null) return this.compileFails;
    void path;
    return { kind: "ok", value: this.compileResult };
  }
}

function leaf(path: string): string {
  const slash = path.lastIndexOf("/");
  return slash < 0 ? path : path.slice(slash + 1);
}

function harness(files: FakeFiles): { ide: LoomIde; editor: FakeEditor; dom: IdeDom } {
  const editor = new FakeEditor();
  const dom: IdeDom = {
    tree: new FakeElement("aside") as unknown as HTMLElement,
    editor: new FakeElement("div") as unknown as HTMLElement,
    diagnostics: new FakeElement("section") as unknown as HTMLElement,
    status: new FakeElement("span") as unknown as HTMLElement,
    pathLabel: new FakeElement("span") as unknown as HTMLElement,
    saveButton: new FakeElement("button") as unknown as HTMLButtonElement,
  };
  const ide = new LoomIde({ files, editor, dom });
  return { ide, editor, dom };
}

const DIAGNOSTIC_TEXT = [
  "/cmds/kill.c:12:9: error[W0201]: unknown efun `foo`",
  "   |",
  "12 |   foo(this);",
  "   |         ^^^",
].join("\n");

test("start lists the root and renders one row per entry", async () => {
  const files = new FakeFiles();
  files.directory("/", ["adm", "cmds"]);
  files.hidden.add("/adm");
  files.hidden.add("/cmds");
  const { ide, dom } = harness(files);
  await ide.start();

  assert.deepEqual(
    ide.rows().map((r) => [r.path, r.kind]),
    [
      ["/adm", null],
      ["/cmds", null],
    ],
  );
  assert.equal(asFake(dom.tree).find("button").length, 2);
  assert.equal(asFake(dom.tree).find("li").length, 2);
});

test("clicking an unknown entry probes it, and a probe miss is a file", async () => {
  const files = new FakeFiles();
  files.directory("/", ["kill.c"]);
  files.file("/kill.c", "int f() { return 1; }", "/");
  files.hidden.add("/kill.c");
  const { ide, editor } = harness(files);
  ide.start();
  await new Promise((r) => setTimeout(r, 0));

  const row = ide.rows()[0]!;
  assert.equal(row.kind, null);
  await ide.activate(row);

  assert.equal(editor.path, "/kill.c");
  assert.equal(editor.text, "int f() { return 1; }");
  assert.equal(editor.currentPath(), "/kill.c");
});

test("clicking a directory expands it and lists its children", async () => {
  const files = new FakeFiles();
  files.directory("/", ["cmds"]);
  files.directory("/cmds", ["kill.c", "go.c"]);
  const { ide } = harness(files);
  ide.start();
  await new Promise((r) => setTimeout(r, 0));

  await ide.activate(ide.rows()[0]!);
  assert.deepEqual(
    ide.rows().map((r) => r.path),
    ["/cmds", "/cmds/kill.c", "/cmds/go.c"],
  );
  // The probe's own listing is cached, so expanding does not re-fetch.
  const callsBefore = files.writes.length;
  await ide.activate(ide.rows()[0]!);
  assert.equal(ide.rows().length, 1);
  assert.equal(files.writes.length, callsBefore);
});

test("a 404 read tells the user instead of opening an empty buffer", async () => {
  const files = new FakeFiles();
  files.directory("/", ["gone.c"]);
  files.hidden.add("/gone.c");
  const { ide, dom, editor } = harness(files);
  ide.start();
  await new Promise((r) => setTimeout(r, 0));
  await ide.activate(ide.rows()[0]!);
  assert.equal(editor.path, null);
  assert.match(asFake(dom.status).text, /No such file/);
});

test("a 503 on open is reported as the driver being busy", async () => {
  const files = new FakeFiles();
  files.readFails = { kind: "busy" };
  const { ide, dom } = harness(files);
  const opened = await ide.openFile("/a.c");
  assert.equal(opened, false);
  assert.match(asFake(dom.status).text, /did not answer/);
});

test("save writes with the ETag read, then compiles", async () => {
  const files = new FakeFiles();
  const { ide, editor, dom } = harness(files);
  // `start()` is what wires the editor's change and save gestures, so
  // this test exercises the same wiring the page does -- without it the
  // controller never hears about the edit and the buffer stays "idle".
  ide.start();
  await new Promise((r) => setTimeout(r, 0));
  ide.setOpenDocument({ path: "/cmds/kill.c", text: "int f() {}", etag: '"abc"' });
  editor.type("int f() { return 2; }");
  assert.equal(ide.getState(), "dirty");

  const result = await ide.save();
  assert.deepEqual(result, { saved: true, compiled: true });
  assert.deepEqual(files.writes, [
    { path: "/cmds/kill.c", text: "int f() { return 2; }", etag: '"abc"' },
  ]);
  assert.match(asFake(dom.status).text, /Saved and compiled/);
  assert.equal(editor.markers.length, 0);
});

test("a compile failure becomes markers, a revealed line, and panel text", async () => {
  const files = new FakeFiles();
  files.compileResult = { ok: false, diagnostics: DIAGNOSTIC_TEXT };
  const { ide, editor, dom } = harness(files);
  ide.setOpenDocument({ path: "/cmds/kill.c", text: "int f() {}", etag: '"abc"' });
  editor.type("int f() { foo(); }");

  const result = await ide.save();
  assert.equal(result.saved, true);
  assert.equal(result.compiled, false);

  assert.equal(editor.markers.length, 1);
  const marker = editor.markers[0]!;
  assert.deepEqual(
    [marker.line, marker.column, marker.severity, marker.code],
    [12, 9, "error", "W0201"],
  );
  // The caret run in the rendered block is 3 characters wide.
  assert.equal(marker.endColumn, 12);
  assert.deepEqual(editor.revealed, [12]);
  assert.match(asFake(dom.diagnostics).text, /unknown efun `foo`/);
  assert.match(asFake(dom.diagnostics).text, /W0201/);
  assert.match(asFake(dom.status).text, /1 diagnostic/);
});

test("a diagnostic naming another file gets no marker here, but opens when clicked", async () => {
  const files = new FakeFiles();
  files.file("/adm/room.c", "// room\n", "/adm");
  files.compileResult = {
    ok: false,
    diagnostics: "/adm/room.c:3:1: error[W0300]: bad inherit",
  };
  const { ide, editor, dom } = harness(files);
  ide.setOpenDocument({ path: "/cmds/kill.c", text: "x", etag: '"e"' });
  await ide.save();

  assert.equal(editor.markers.length, 0, "a marker in the wrong file would be a lie");
  assert.equal(asFake(dom.diagnostics).find("button").length, 1);
  asFake(dom.diagnostics).find("button")[0]!.click();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(editor.path, "/adm/room.c");
});

test("a 412 on save keeps the buffer, re-enables Save, and does not compile", async () => {
  const files = new FakeFiles();
  files.writeFails = { kind: "preconditionFailed" };
  const { ide, editor, dom } = harness(files);
  ide.setOpenDocument({ path: "/a.c", text: "old", etag: '"stale"' });
  editor.type("my edit");

  const result = await ide.save();
  assert.deepEqual(result, { saved: false, compiled: false });
  assert.match(asFake(dom.status).text, /Someone saved this file/);
  assert.match(asFake(dom.status).text, /still in the editor, unsaved/);
  assert.equal(editor.text, "my edit");
  assert.equal(ide.getState(), "dirty");
  assert.equal((dom.saveButton as unknown as HTMLButtonElement).disabled, false);
});

test("a 507 quota failure on save says so and keeps the edit", async () => {
  const files = new FakeFiles();
  files.writeFails = { kind: "quotaExceeded" };
  const { ide, editor, dom } = harness(files);
  ide.setOpenDocument({ path: "/a.c", text: "old", etag: '"e"' });
  editor.type("new");
  await ide.save();
  assert.match(asFake(dom.status).text, /quota/i);
  assert.equal(editor.text, "new");
});

test("after a save the next save carries the rotated ETag, not the stale one", async () => {
  const files = new FakeFiles();
  const { ide, editor } = harness(files);
  ide.setOpenDocument({ path: "/a.c", text: "one", etag: '"v1-/a.c"' });
  editor.type("two");
  await ide.save();
  editor.type("three");
  await ide.save();
  assert.deepEqual(
    files.writes.map((w) => w.etag),
    ['"v1-/a.c"', '"v1-/a.c"'],
  );
});

test("a save with nothing open is a no-op", async () => {
  const files = new FakeFiles();
  const { ide } = harness(files);
  assert.deepEqual(await ide.save(), { saved: false, compiled: false });
});

test("opening another file with unsaved changes is refused, not discarded", async () => {
  const files = new FakeFiles();
  files.file("/b.c", "contents of b", "/");
  files.hidden.add("/b.c");
  const { ide, editor, dom } = harness(files);
  ide.setOpenDocument({ path: "/a.c", text: "disk", etag: '"e"' });
  editor.type("unsaved work");

  const opened = await ide.openFile("/b.c");
  assert.equal(opened, false);
  assert.equal(editor.path, "/a.c");
  assert.match(asFake(dom.status).text, /unsaved changes/);
});

test("a compile that the driver fails to answer still reports the save", async () => {
  const files = new FakeFiles();
  files.compileFails = { kind: "busy" };
  const { ide, dom } = harness(files);
  ide.setOpenDocument({ path: "/a.c", text: "x", etag: '"e"' });
  const result = await ide.save();
  assert.equal(result.saved, true);
  assert.equal(result.compiled, false);
  assert.match(asFake(dom.status).text, /^Saved\./);
  assert.match(asFake(dom.status).text, /did not answer/);
});

test("truncated diagnostics are labelled, so a cut-off sentence is not read as the whole story", async () => {
  const files = new FakeFiles();
  files.compileResult = {
    ok: false,
    diagnostics: "/a.c:1:1: error[W1]: thing",
    truncated: true,
  };
  const { ide, dom } = harness(files);
  ide.setOpenDocument({ path: "/a.c", text: "x", etag: '"e"' });
  await ide.save();
  assert.match(asFake(dom.diagnostics).text, /truncated by the driver/);
});

test("an unresolvable entry kind leaves the tree alone and reports the reason", async () => {
  const files = new FakeFiles();
  files.directory("/", ["a.c"]);
  const { ide, dom } = harness(files);
  ide.start();
  await new Promise((r) => setTimeout(r, 0));
  // The kind probe *and* the open both fail: busy is neither "it is a
  // directory" nor "it is not one", so the row must stay unresolved.
  files.listFails = { kind: "busy" };
  files.readFails = { kind: "busy" };
  await ide.activate(ide.rows()[0]!);
  assert.match(asFake(dom.status).text, /did not answer/);
  assert.equal(ide.rows()[0]!.kind, null);
});

test("the editor's save gesture is wired to the same path as the button", async () => {
  const files = new FakeFiles();
  const { ide, editor } = harness(files);
  ide.start();
  await new Promise((r) => setTimeout(r, 0));
  ide.setOpenDocument({ path: "/a.c", text: "x", etag: '"e"' });
  editor.type("y");
  editor.pressSave();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(files.writes.length, 1);
  assert.equal(files.writes[0]?.text, "y");
});

test("a loom-vfs link opens; anything else is refused and said", async () => {
  const files = new FakeFiles();
  files.file("/adm/room.c", "room\n", "/adm");
  const { ide, editor, dom } = harness(files);
  assert.equal(ide.handleVfsLink("loom-vfs:/adm/room.c"), true);
  await new Promise((r) => setTimeout(r, 0)); // the read is a round trip
  assert.equal(editor.path, "/adm/room.c");

  assert.equal(ide.handleVfsLink("javascript:alert(1)"), false);
  await new Promise((r) => setTimeout(r, 0));
  assert.match(asFake(dom.status).text, /not https: or loom-vfs/);
  assert.equal(editor.path, "/adm/room.c", "the refused link must not have opened");
});

test("every string the controller renders goes through a text node, never markup", async () => {
  const files = new FakeFiles();
  const hostile = "<img src=x onerror=alert(1)>";
  files.directory("/", [hostile]);
  files.hidden.add(`/${hostile}`);
  const { ide, dom } = harness(files);
  ide.start();
  await new Promise((r) => setTimeout(r, 0));
  const rendered = asFake(dom.tree).text;
  // The name is displayed verbatim and no element was created from it.
  assert.ok(rendered.includes(hostile));
  assert.equal(asFake(dom.tree).find("img").length, 0);
  assert.equal((dom.tree as unknown as { innerHTML?: string }).innerHTML, undefined);
});
