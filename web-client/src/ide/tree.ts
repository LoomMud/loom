// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The IDE's file-tree model (OBI-180 M-IDE-4). Pure data and transitions:
 * no DOM, no `fetch`, no Monaco, so it is testable under plain
 * `node:test` and the rendering in `./app.ts` stays a thin projection of
 * `rows()`.
 *
 * ## Why a click can cost one extra request
 *
 * `GET /api/v1/files/list` (OBI-116/M-FS-3, PR #117) answers with bare
 * entry *names* -- files and subdirectories both, sorted, dotfiles
 * dropped -- and carries no `file_type`, because the server never
 * `stat`ed anything to build it. So the client cannot tell a directory
 * from a file from the listing alone.
 *
 * Two ways out, and this takes the cheap one:
 *
 *  - **Ask the server to include the type.** That means a `stat` per
 *    entry on the world thread inside `World::list_dir`, a changed
 *    `ListDirResponse` shape, and a cross-crate interface change (a
 *    `loom-vm`/`loom-http` seam) -- a call for the CTO, not for an IDE
 *    client to make unilaterally.
 *  - **Probe on expand** (what this does): `list?path=<child>` returns
 *    `200` for a directory and `404` for a file (`list_dir` on a
 *    non-directory is the same "not found" shape as a missing one,
 *    M-FS-3), and `content?path=<child>` returns `200` for a file. One
 *    round trip per *first* click on each entry, cached in `kinds`
 *    afterwards, with no server change and no new world-thread cost.
 *
 * A `null` kind renders as a plain row with no chevron; the first click
 * resolves it. That is deliberate: guessing "not `.c`, so a directory"
 * would mis-render `/builders/ann/notes` (a file) or `/cmds/adm` (a
 * directory), and a wrong guess in a tree is a dead end the user has to
 * debug, not just an extra request.
 */

/** What an entry is, once resolved (see the header comment for why this
 * is not known from the listing). */
export type EntryKind = "dir" | "file";

/** An entry name the server could not faithfully round-trip:
 * `loom-vm`'s `list_dir` builds names with `to_string_lossy`, so a
 * non-UTF-8 filename arrives with U+FFFD substitutions in it
 * (`scripts`/review note on PR #117: skip these when the tree client
 * lands). Such a name is not the real path -- `valid_read` and the
 * resolver reject non-UTF-8 anyway -- so opening it could only ever
 * 404. Dropping it keeps the tree honest about what can be opened. */
export const LOSSY_NAME_MARKER = "\uFFFD";

/** A name we will not join onto a path: empty, `.`/`..`, or anything
 * containing a separator. The server's resolver rejects these too
 * (`M-FS-2`), so this is defence in depth for a *display* model, not a
 * security boundary -- a crafted listing can't read a file the uid
 * can't read, but it could otherwise render a row whose path looks like
 * `/a/b/c/d` while clicking it asks for something else entirely. */
export function isShowableName(name: string): boolean {
  if (name.length === 0) return false;
  // Dotfiles are dropped rather than displayed. The driver already
  // filters them out of a listing (`World::list_dir` in OBI-117), so this
  // is the client-side half of the same rule: a name that only exists to
  // hide something (`.git/`, `.ssh/`, `.#*` lock files) has no business
  // in a builder's file tree, and if a future listing route stops
  // filtering, the tree should not start offering them.
  if (name.startsWith(".")) return false;
  if (name.includes("/")) return false;
  if (name.includes(LOSSY_NAME_MARKER)) return false;
  // A control character in a filename is a spoofing vector: it can make
  // `/room` + NUL + `.c` render as `/room.c` while the driver reads a
  // different name. Compared by code point rather than with a regex
  // literal, because `no-control-regex` (which is on, and should stay on
  // for the rest of this tree) is exactly the rule a literal here would
  // have to argue its way out of.
  for (const character of name) {
    const code = character.codePointAt(0) ?? 0;
    if (code <= 0x1f || code === 0x7f) {
      return false;
    }
  }
  return true;
}

/** `joinPath("/cmds", "adm")` -> `/cmds/adm`; `joinPath("/", "adm.c")`
 * -> `/adm.c`. Always an absolute mudlib path, never `//`. */
export function joinPath(dirPath: string, name: string): string {
  return dirPath.endsWith("/") ? `${dirPath}${name}` : `${dirPath}/${name}`;
}

/** The last segment of a mudlib path, for a title bar. */
export function baseName(path: string): string {
  const trimmed = path.endsWith("/") && path !== "/" ? path.slice(0, -1) : path;
  if (trimmed === "/") {
    return "/";
  }
  const slash = trimmed.lastIndexOf("/");
  return slash === -1 ? trimmed : trimmed.slice(slash + 1);
}

/** One row of the flattened, visible tree. */
export interface TreeRow {
  /** Absolute mudlib path. */
  path: string;
  /** Bare entry name (never contains a separator). */
  name: string;
  /** Indent depth: `/`'s children are 0. */
  depth: number;
  /** `null` until probed (see the header comment). */
  kind: EntryKind | null;
  /** Only meaningful for a resolved `dir`. */
  expanded: boolean;
  /** This directory's listing was cut at `MAX_LIST_ENTRIES`. */
  truncated: boolean;
  /** True when a resolved directory has not been listed yet. */
  needsListing: boolean;
}

/** A directory's cached listing. `entries` are the showable names only;
 * `truncated` remembers the server's flag for the row that said "there
 * are more". */
interface Listing {
  names: string[];
  truncated: boolean;
}

export const ROOT_PATH = "/";

/**
 * The tree's state and the only transitions `app.ts` may apply to it.
 * Every mutation is followed by a `rows()` re-projection; the model never
 * touches the DOM, and `rows()` output is fully determined by
 * `(listings, kinds, expanded)`, which is what makes the tests below
 * meaningful.
 */
export class FileTree {
  private readonly listings = new Map<string, Listing>();
  private readonly kinds = new Map<string, EntryKind>();
  private readonly expanded = new Set<string>();

  constructor(private readonly root: string = ROOT_PATH) {
    this.expanded.add(root);
  }

  get rootPath(): string {
    return this.root;
  }

  /** Record `GET list?path=dir`'s answer. Names the client will not
   * display (see `isShowableName`) are dropped here, once, rather than
   * at every projection. */
  setListing(dirPath: string, entries: string[], truncated = false): void {
    this.listings.set(dirPath, {
      names: entries.filter(isShowableName),
      truncated,
    });
    // Whatever we thought we knew about the children is stale: an entry
    // can be renamed or removed under us between two listings.
    for (const [path] of this.kinds) {
      if (parentOf(path) === dirPath) this.kinds.delete(path);
    }
  }

  hasListing(dirPath: string): boolean {
    return this.listings.has(dirPath);
  }

  /** Record a probe's answer. Called with `"dir"` when
   * `list?path=<p>` gave 200, `"file"` when it gave 404 and
   * `content?path=<p>` gave 200. */
  setKind(path: string, kind: EntryKind): void {
    this.kinds.set(path, kind);
  }

  kindOf(path: string): EntryKind | null {
    return this.kinds.get(path) ?? null;
  }

  /** Mark a directory as open. Does not fetch anything -- the caller
   * checks `needsListing` on the resulting row and issues the list. */
  expand(dirPath: string): void {
    this.expanded.add(dirPath);
  }

  collapse(dirPath: string): void {
    this.expanded.delete(dirPath);
  }

  isExpanded(dirPath: string): boolean {
    return this.expanded.has(dirPath);
  }

  /** Forget a directory's children (called when a file is created or
   * deleted out from under the tree so the next expand re-lists). */
  invalidate(dirPath: string): void {
    this.listings.delete(dirPath);
  }

  /** The visible rows, depth-first, in the server's sorted order. The
   * root itself is not a row -- it is always expanded and has no parent
   * to show. */
  rows(): TreeRow[] {
    const out: TreeRow[] = [];
    this.collect(this.root, 0, out, new Set());
    return out;
  }

  private collect(
    dirPath: string,
    depth: number,
    out: TreeRow[],
    visiting: Set<string>,
  ): void {
    // A self-referential listing would loop forever. `setListing` stores
    // whatever the server named, and a symlinked directory inside the
    // mudlib (`/cmds/link` -> `/cmds`) is legitimate on disk, so this is
    // a real cycle the walk has to survive, not a hypothetical one.
    if (visiting.has(dirPath)) return;
    const listing = this.listings.get(dirPath);
    if (listing === undefined) return;
    visiting.add(dirPath);
    for (const name of listing.names) {
      const path = joinPath(dirPath, name);
      const kind = this.kinds.get(path) ?? null;
      const isDir = kind === "dir";
      const isOpen = isDir && this.expanded.has(path);
      out.push({
        path,
        name,
        depth,
        kind,
        expanded: isOpen,
        truncated: isDir ? (this.listings.get(path)?.truncated ?? false) : false,
        needsListing: isDir && !this.listings.has(path),
      });
      if (isOpen) {
        this.collect(path, depth + 1, out, visiting);
      }
    }
    visiting.delete(dirPath);
  }
}

/** `/a/b/c` -> `/a/b`; `/adm.c` -> `/`. */
export function parentOf(path: string): string {
  const trimmed = path.endsWith("/") && path !== "/" ? path.slice(0, -1) : path;
  const slash = trimmed.lastIndexOf("/");
  if (slash <= 0) return "/";
  return trimmed.slice(0, slash);
}
