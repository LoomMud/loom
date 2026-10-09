// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The IDE controller (OBI-180 M-IDE-4/M-IDE-5): tree -> open -> edit ->
 * save -> compile -> diagnostics -> fix.
 *
 * Deliberately free of Monaco and of `fetch`: it drives an
 * [`EditorPort`](./editor-port.ts) and a
 * [`FilesApi`](./files-api.ts), both injected, so the whole save/compile
 * conflict path is testable under `node:test` with a 30-line fake editor
 * (see `./app.test.ts`). Rendering happens here through
 * `../admin/dom.ts`'s `el()` -- text nodes only, never an HTML sink
 * (M-IDE-2), which is the same rule the admin pages have been under since
 * OBI-235 and the reason a builder-controlled filename or compiler
 * message cannot execute anything.
 */

import { clear, el } from "../admin/dom.js";
import type { FileResult } from "./files-api.js";
import {
  describeResult,
  type CompileBody,
  type ListingBody,
  type ReadFile,
} from "./files-api.js";
import type { EditorMarker, EditorPort } from "./editor-port.js";
import type { LspHooks } from "./lsp-bridge.js";
import { FileTree, baseName, type TreeRow } from "./tree.js";
import { diagnosticsFor, formatDiagnostic, hasErrors, parseDiagnostics, TRUNCATION_NOTE, type ParsedDiagnostic } from "./compile.js";
import { sanitizeLinkUrl, vfsPathOf } from "./links.js";

/**
 * The four routes the controller uses, as a structural interface rather
 * than the `FilesApi` class: the tests in `./app.test.ts` drive the whole
 * save/compile/conflict path with an in-memory fake, and an IDE whose
 * controller could only be built against a live HTTP client would have a
 * save path no one has tested.
 */
export interface FilesLike {
  read(path: string): Promise<FileResult<ReadFile>>;
  list(path: string): Promise<FileResult<ListingBody>>;
  write(path: string, text: string, etag: string | null): Promise<FileResult<null>>;
  compile(path: string): Promise<FileResult<CompileBody>>;
}

export interface IdeDom {
  tree: HTMLElement;
  editor: HTMLElement;
  diagnostics: HTMLElement;
  status: HTMLElement;
  pathLabel: HTMLElement;
  saveButton: HTMLButtonElement;
}

export interface IdeOptions {
  files: FilesLike;
  editor: EditorPort;
  dom: IdeDom;
  /** Mudlib directory the tree opens at. `/` shows everything the signed
   * in uid may read; the server, not the client, decides what that is
   * (M-FS-2/M-FS-3). */
  root?: string;
  /** The live analyser (`./lsp-bridge.ts`), when the page has one. Absent
   * is a normal configuration, not an error: a page served over an origin
   * that cannot hold a WebSocket (`./lsp-transport.ts`) has no `/lsp`, and
   * the save-compile path in this controller is the analysis that still
   * works. */
  lsp?: LspHooks;
}

/** What the controller is doing, for the status line. A single label
 * rather than a spinner: an alpha tool's user needs to know *which*
 * round trip is hanging, since the answer distinguishes "the driver is
 * busy" from "your network is down". */
export type IdeState = "idle" | "loading" | "saving" | "compiling" | "dirty" | "saved";

interface OpenDocument {
  path: string;
  etag: string;
  /** The text as loaded from disk, for the dirty check. */
  diskText: string;
}

export class LoomIde {
  private readonly tree: FileTree;
  private open: OpenDocument | null = null;
  private state: IdeState = "idle";
  private lastDiagnostics: ParsedDiagnostic[] = [];
  private readonly disposers: (() => void)[] = [];

  constructor(private readonly options: IdeOptions) {
    this.tree = new FileTree(options.root ?? "/");
  }

  /** Wire the editor's gestures to the controller. Separate from the
   * constructor because the Monaco widget is created asynchronously (its
   * AMD module loads after the page's own module runs). */
  start(): void {
    this.disposers.push(
      this.options.editor.onSave(() => {
        void this.save();
      }),
      this.options.editor.onChangeContent(() => {
        const text = this.options.editor.currentText();
        if (this.open !== null && text !== this.open.diskText) {
          this.setState("dirty");
        } else if (this.state === "dirty") {
          this.setState("saved");
        }
        // The analyser sees the same edit the dirty flag does. It is the
        // buffer's *current* text either way -- handing it a different string
        // would mean the diagnostics on screen describe text the builder is
        // not looking at.
        if (this.open !== null) {
          this.options.lsp?.documentChanged(this.open.path, text);
        }
      }),
    );
    this.options.dom.saveButton.addEventListener("click", () => {
      void this.save();
    });
    this.renderTree();
    void this.listDirectory(this.tree.rootPath);
  }

  dispose(): void {
    for (const dispose of this.disposers) {
      dispose();
    }
    // Before the editor goes away: `didClose` is a message that has to reach
    // the server while the session it belongs to still exists.
    if (this.open !== null) {
      this.options.lsp?.documentClosed(this.open.path);
    }
    this.options.lsp?.dispose();
    this.options.editor.dispose();
  }

  /** The tree's current rows -- exposed for tests and for the debug
   * console, never for the DOM to mutate. */
  rows(): TreeRow[] {
    return this.tree.rows();
  }

  getState(): IdeState {
    return this.state;
  }

  /** The most recent compile's diagnostics, in source order. */
  diagnostics(): ParsedDiagnostic[] {
    return this.lastDiagnostics;
  }

  /**
   * One click on a tree row: resolve what it is if we do not know, then
   * expand it (directory) or open it (file). The kind resolution costs a
   * request the first time only -- see `./tree.ts`'s header comment for
   * why the listing cannot tell us.
   */
  async activate(row: TreeRow): Promise<void> {
    let kind = row.kind;
    if (kind === null) {
      this.setState("loading");
      const probe = await this.options.files.list(row.path);
      if (probe.kind === "ok") {
        kind = "dir";
        this.tree.setKind(row.path, "dir");
        this.tree.setListing(row.path, probe.value.entries, probe.value.truncated === true);
      } else if (isProbeMiss(probe)) {
        kind = "file";
        this.tree.setKind(row.path, "file");
      } else {
        this.setStatus(describeResult(probe));
        this.setState("idle");
        this.renderTree();
        return;
      }
    }

    if (kind === "dir") {
      if (this.tree.isExpanded(row.path)) {
        this.tree.collapse(row.path);
      } else {
        this.tree.expand(row.path);
        if (!this.tree.hasListing(row.path)) {
          this.setState("loading");
          const listing = await this.options.files.list(row.path);
          if (listing.kind === "ok") {
            this.tree.setListing(row.path, listing.value.entries, listing.value.truncated === true);
          } else {
            this.setStatus(describeResult(listing));
          }
        }
      }
      this.setState("idle");
      this.renderTree();
      return;
    }

    await this.openFile(row.path);
  }

  /** `GET /api/v1/files/content` -> the editor. A file that is already
   * open with unsaved changes is refused rather than silently discarded:
   * the builder's buffer is the thing they cannot recover. */
  async openFile(path: string): Promise<boolean> {
    if (this.isDirty()) {
      this.setStatus(`Not opened ${baseName(path)}: ${baseName(this.open?.path ?? "")} has unsaved changes.`);
      return false;
    }
    this.setState("loading");
    const result = await this.options.files.read(path);
    if (result.kind !== "ok") {
      this.setStatus(describeResult(result));
      this.setState("idle");
      return false;
    }
    this.setOpenDocument(result.value);
    this.setState("idle");
    return true;
  }

  /**
   * Adopt a read file as the buffer. For the initial mount, the tree's
   * click, and the tests alike.
   *
   * The two marker owners are cleared in the order their sources think: the
   * save path's own (`loom-ide`, immediately, because the file on disk is now
   * this text and the previous compile said nothing about it), then the
   * analyser's, as part of handing it the buffer (`./lsp-bridge.ts`).
   */
  setOpenDocument(file: ReadFile): void {
    const previous = this.open;
    this.open = { path: file.path, etag: file.etag, diskText: file.text };
    this.options.editor.openText(file.path, file.text);
    this.options.editor.setMarkers([]);
    if (previous !== null && previous.path !== file.path) {
      this.options.lsp?.documentClosed(previous.path);
    }
    this.lastDiagnostics = [];
    this.options.dom.saveButton.disabled = false;
    this.options.dom.pathLabel.textContent = file.path;
    this.renderDiagnostics([]);
    this.setStatus(`Opened ${file.path}`);
    this.options.lsp?.documentOpened(file.path, file.text);
    this.options.editor.focus();
  }

  /**
   * Save, then compile (M-IDE-5's loop in one method).
   *
   * The write carries the ETag read with the file (M-FS-6). A
   * `preconditionFailed` means someone else saved in the meantime: the
   * buffer is *not* overwritten and the builder is told, because the
   * driver has no merge tool and a lost edit is the worst outcome this UI
   * can produce. `409`/`503` are reported the same way -- unsaved state
   * preserved, the Save button still enabled.
   */
  async save(): Promise<{ saved: boolean; compiled: boolean }> {
    const document = this.open;
    if (document === null) {
      return { saved: false, compiled: false };
    }
    const text = this.options.editor.currentText();
    this.setState("saving");
    this.options.dom.saveButton.disabled = true;
    const written = await this.options.files.write(document.path, text, document.etag);
    if (written.kind === "preconditionFailed" || written.kind === "conflict") {
      this.setStatus(`${describeResult(written)} Your changes are still in the editor, unsaved.`);
      this.options.dom.saveButton.disabled = false;
      this.setState("dirty");
      return { saved: false, compiled: false };
    }
    if (written.kind !== "ok") {
      this.setStatus(describeResult(written));
      this.options.dom.saveButton.disabled = false;
      this.setState("dirty");
      return { saved: false, compiled: false };
    }

    // The write rotated the file's digest; re-read so the next save's
    // `If-Match` is current. A stale ETag here would turn a successful
    // save into a `412` on the *next* one.
    const reread = await this.options.files.read(document.path);
    const etag = reread.kind === "ok" ? reread.value.etag : document.etag;
    this.open = { ...document, etag, diskText: text };
    this.setState("compiling");
    const compiled = await this.options.files.compile(document.path);
    if (compiled.kind !== "ok") {
      this.setStatus(`Saved. ${describeResult(compiled)}`);
      this.setState("saved");
      return { saved: true, compiled: false };
    }
    const body = compiled.value;
    const diagnostics = parseDiagnostics(body.diagnostics ?? "");
    this.applyDiagnostics(document.path, diagnostics, body.truncated === true);
    this.setState("saved");
    this.setStatus(
      body.ok
        ? `Saved and compiled: ${document.path}`
        : `Saved. ${diagnostics.length} diagnostic(s): ${document.path}`,
    );
    return { saved: true, compiled: body.ok };
  }

  /**
   * Push the diagnostics into the editor as markers and into the panel as
   * rows. Only diagnostics that name the open file (or no file at all)
   * become markers -- a recompile that fails in an inherited file shows in
   * the panel, and clicking its path opens that file, but painting a
   * marker at line 12 of the wrong file would be a lie.
   */
  applyDiagnostics(path: string, diagnostics: ParsedDiagnostic[], truncated: boolean): void {
    this.lastDiagnostics = diagnostics;
    const mine = diagnosticsFor(diagnostics, path);
    const markers: EditorMarker[] = [];
    for (const diagnostic of mine) {
      if (diagnostic.line === null) {
        continue;
      }
      const column = diagnostic.column ?? 1;
      markers.push({
        line: diagnostic.line,
        column,
        // The compiler renders a caret for the span's width but does not
        // put its end in the header line, so the marker underlines to the
        // end of the message's own column run -- one character minimum.
        endLine: diagnostic.line,
        endColumn: column + Math.max(1, caretWidth(diagnostic)),
        severity: diagnostic.severity,
        message: diagnostic.message,
        code: diagnostic.code ?? undefined,
      });
    }
    this.options.editor.setMarkers(markers);
    this.renderDiagnostics(diagnostics, truncated);
    const first = markers[0];
    if (first !== undefined) {
      this.options.editor.revealLine(first.line);
    }
  }

  private isDirty(): boolean {
    return this.open !== null && this.options.editor.currentText() !== this.open.diskText;
  }

  private setStatus(message: string): void {
    this.options.dom.status.textContent = message;
  }

  private setState(state: IdeState): void {
    this.state = state;
    if (this.open !== null) {
      this.options.dom.saveButton.disabled = state === "saving" || state === "compiling" || !this.isDirty();
    }
  }

  /** The tree is re-rendered wholesale from `rows()` after each
   * transition. A mudlib listing is at most `MAX_LIST_ENTRIES` rows per
   * directory and the visible set is what the user expanded, so a
   * rebuild is cheaper and much harder to get wrong than diffing. */
  private renderTree(): void {
    const container = this.options.dom.tree;
    clear(container);
    container.append(
      el("div", { class: "ide-tree-root" }, [this.tree.rootPath]),
      this.listContainer(this.tree.rows()),
    );
  }

  private listContainer(rows: TreeRow[]): HTMLElement {
    const list = el("ul", { class: "ide-tree", role: "tree" });
    for (const row of rows) {
      const button = el(
        "button",
        {
          type: "button",
          class: `ide-tree-row ide-depth-${row.depth}${row.kind === "dir" ? " ide-dir" : ""}`,
          "data-path": row.path,
          "aria-expanded": row.kind === "dir" ? String(row.expanded) : "false",
        },
        [`${row.kind === "dir" ? (row.expanded ? "\u25be " : "\u25b8 ") : "\u2022 "}${row.name}`],
      ) as HTMLButtonElement;
      button.addEventListener("click", () => {
        void this.activate(row);
      });
      const items: HTMLElement[] = [el("li", { role: "treeitem" }, [button])];
      if (row.truncated) {
        items.push(el("li", { class: "ide-tree-note" }, ["(listing truncated by the driver)"]));
      }
      list.append(...items);
    }
    return list;
  }

  /**
   * The diagnostics panel: one row per diagnostic, each a button that
   * either reveals the line in the open file or, when the diagnostic
   * names a *different* file, opens that file. The path text is only ever
   * a `textContent` string; the clickable route is decided by
   * [`vfsPathOf`]/[`sanitizeLinkUrl`] so a crafted `path:` value in
   * compiler output cannot turn the panel into an off-origin link
   * (M-IDE-2).
   */
  private renderDiagnostics(diagnostics: ParsedDiagnostic[], truncated = false): void {
    const container = this.options.dom.diagnostics;
    clear(container);
    container.append(el("h2", {}, [hasErrors(diagnostics) ? "Errors" : "Diagnostics"]));
    if (diagnostics.length === 0) {
      container.append(el("p", { class: "ide-empty" }, ["No diagnostics."]));
      if (truncated) {
        container.append(el("p", { class: "ide-note" }, [TRUNCATION_NOTE]));
      }
      return;
    }
    const list = el("ul", { class: "ide-diagnostics" });
    for (const diagnostic of diagnostics) {
      const button = el("button", { type: "button", class: `ide-diagnostic sev-${diagnostic.severity}` }, [
        formatDiagnostic(diagnostic),
      ]) as HTMLButtonElement;
      const targetPath = diagnostic.path !== null ? vfsPathOf(`loom-vfs:${diagnostic.path}`) : null;
      const sameFile = this.open !== null && targetPath === this.open.path;
      button.disabled = targetPath === null && diagnostic.line === null;
      button.addEventListener("click", () => {
        if (diagnostic.line !== null && (sameFile || targetPath === null)) {
          this.options.editor.revealLine(diagnostic.line);
          this.options.editor.focus();
          return;
        }
        if (targetPath !== null && !sameFile) {
          void this.openFile(targetPath);
        }
      });
      list.append(el("li", {}, [button]));
    }
    container.append(list);
    if (truncated) {
      container.append(el("p", { class: "ide-note" }, [TRUNCATION_NOTE]));
    }
  }

  /** A `loom-vfs:` link inside the editor (a doc comment's
   * `loom-vfs:/adm/room.c`) opens that file; anything the allow-list
   * rejects is ignored rather than half-handled. */
  handleVfsLink(rawUrl: string): boolean {
    const safe = sanitizeLinkUrl(rawUrl);
    if (safe === null) {
      this.setStatus("Refused a link that was not https: or loom-vfs:.");
      return false;
    }
    const path = vfsPathOf(safe);
    if (path === null) {
      return false;
    }
    void this.openFile(path);
    return true;
  }

  /** Fetch and cache a directory's children. Used for the root at
   * startup, where there is no click to probe on, and for any directory
   * whose listing the tree has never seen. */
  private async listDirectory(path: string): Promise<void> {
    const listing = await this.options.files.list(path);
    if (listing.kind === "ok") {
      this.tree.setListing(path, listing.value.entries, listing.value.truncated === true);
      // The children's kinds stay unresolved until clicked. Probing every
      // entry up front would turn opening the IDE into one world-thread
      // file operation per entry in the mudlib root -- a real cost on the
      // thread that runs the game, for information the builder usually
      // never looks at. A click probes once and caches (`./tree.ts`).
      this.renderTree();
      return;
    }
    this.setStatus(describeResult(listing));
    this.renderTree();
  }
}

/**
 * A `404` on a `list` probe means "not a readable directory", which
 * for the tree's purposes means "not a directory" (M-FS-3 collapses
 * missing, refused, and file-not-directory into the same not-found shape
 * on purpose -- the IDE must not be able to distinguish them either, and
 * a `404` on the *read* that follows tells the user what they may not
 * do). Anything else -- `503`, `401` -- is not a negative answer about
 * the entry's type, and the caller reports it instead of guessing.
 */
function isProbeMiss(result: Exclude<FileResult<unknown>, { kind: "ok" }>): boolean {
  return result.kind === "notFound";
}

/** The caret width `Diagnostic::render` drew under the source line, which
 * the header line does not carry. Falls back to 1 when the diagnostic had
 * no caret block (a driver message, a truncated body). */
function caretWidth(diagnostic: ParsedDiagnostic): number {
  for (const line of diagnostic.context) {
    const caret = line.indexOf("^");
    if (caret >= 0) {
      return line.length - caret;
    }
  }
  return 1;
}
