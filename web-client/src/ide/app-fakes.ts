// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The seams `./app.test.ts` and `./lsp-integration.test.ts` drive the
 * controller through: an in-memory mudlib that answers with the same
 * `FileResult` kinds as the real routes, and an editor that records calls
 * instead of mounting Monaco.
 *
 * This is a plain module, not a `*.test.ts`, because the test runner's glob
 * (`node --test dist/ide/*.test.js`) would otherwise execute it a second time
 * as a test file, and because the fakes are shared: an integration test that
 * wants the whole stack -- controller, bridge, session, fake server -- needs
 * the same two seams as the unit tests.
 */

import { installFakeDom } from "./dom-globals.js";
import type { EditorMarker, EditorPort, MarkerOwner } from "./editor-port.js";
import { LoomIde, type FilesLike, type IdeDom, type IdeOptions } from "./app.js";
import type { CompileBody, FileResult, ListingBody, ReadFile } from "./files-api.js";

installFakeDom();

/** The editor half of the seam: records what the controller asked for. */
export class FakeEditor implements EditorPort {
  text = "";
  path: string | null = null;
  /** Every marker the editor was told about, in the order it was told. */
  markers: EditorMarker[] = [];
  revealed: number[] = [];
  focused = 0;
  openCalls: [string, string][] = [];
  /** Monaco namespaces markers by *(model, owner)*, and so does this fake.
   * Without that, the live analyser and the save path would look like they
   * overwrite each other -- which is the exact behaviour `./lsp-bridge.ts`
   * claims not to have, and the one thing a reviewer cannot check from the
   * production code alone. */
  private readonly byOwner = new Map<MarkerOwner, EditorMarker[]>();
  private saveHandler: (() => void) | null = null;
  private changeHandler: (() => void) | null = null;

  openText(path: string, text: string): void {
    this.path = path;
    this.text = text;
    // A new model in Monaco is a new marker namespace: nothing carries over.
    this.byOwner.clear();
    this.markers = [];
    this.openCalls.push([path, text]);
  }
  currentText(): string {
    return this.text;
  }
  currentPath(): string | null {
    return this.path;
  }
  setMarkers(markers: EditorMarker[], owner: MarkerOwner = "loom-ide"): void {
    this.byOwner.set(owner, markers);
    this.markers = [...this.byOwner.values()].flat();
  }
  markersFor(owner: MarkerOwner): EditorMarker[] {
    return this.byOwner.get(owner) ?? [];
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

/** The server half of the seam: an in-memory mudlib with the same result kinds
 * and status semantics as the real routes. */
export class FakeFiles implements FilesLike {
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

/** Mount the controller over the two seams. `options` is passed through
 * untouched, which is how the LSP integration test injects a real bridge; an
 * editor may be supplied ahead of time for the same reason, because production
 * (`./main.ts`) builds the editor *before* the bridge whose `setMarkers` closure
 * points at it. */
export function harnessIde(
  files: FakeFiles,
  options: Partial<IdeOptions> = {},
  provided: FakeEditor = new FakeEditor(),
): { ide: LoomIde; editor: FakeEditor; dom: IdeDom } {
  const editor = provided;
  const dom: IdeDom = {
    tree: document.createElement("aside"),
    editor: document.createElement("div"),
    diagnostics: document.createElement("section"),
    status: document.createElement("span"),
    pathLabel: document.createElement("span"),
    saveButton: document.createElement("button"),
  };
  const ide = new LoomIde({ files, editor, dom, ...options });
  return { ide, editor, dom };
}
