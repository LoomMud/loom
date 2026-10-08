// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The IDE's client for the merged `/api/v1/files/*` routes (OBI-180
 * M-IDE-4/M-IDE-5, server side OBI-115/OBI-116/OBI-119: PRs #115, #117,
 * #119).
 *
 * Auth is delegated to [`AdminApi.requestRaw`](../admin/api.ts) rather
 * than reimplemented here: the files routes accept the same staff access
 * token `/api/v1/admin/*` does, and the 10-minute-expiry silent refresh
 * (OBI-297) is exactly the kind of logic that must live in one place.
 *
 * Every method returns a *discriminated result* instead of throwing on
 * a non-2xx, because for these routes the status is the information:
 * a `412` on a write means "someone else saved, resolve the conflict", a
 * `404` on a listing means "that is not a directory, it may be a file", a
 * `503` means the world thread did not answer inside the deadline and the
 * editor should keep the unsaved buffer. Throwing would push every
 * caller into a `try`/`catch` that inspects a status code anyway.
 */

import type { AdminApi } from "../admin/api.js";

/** `GET /api/v1/files/list?path=`'s body (`ListDirResponse` in
 * `loom-http`'s `files.rs`): bare entry names, sorted, dotfiles already
 * dropped server-side, `truncated` when the directory held more than
 * `World::MAX_LIST_ENTRIES` of them. */
export interface ListingBody {
  entries: string[];
  truncated?: boolean;
}

/** `POST /api/v1/files/compile?path=`'s body (`CompileResponse`). */
export interface CompileBody {
  ok: boolean;
  diagnostics?: string;
  truncated?: boolean;
}

export type FileResult<T> =
  | { kind: "ok"; value: T }
  | { kind: "unauthorized" }
  | { kind: "notFound" }
  | { kind: "conflict" }
  | { kind: "preconditionFailed" }
  | { kind: "rateLimited" }
  | { kind: "tooLarge" }
  | { kind: "quotaExceeded" }
  | { kind: "busy" }
  | { kind: "error"; status: number; body: string };

/** The status codes these four routes can return, named once (the
 * server-side mapping is `status_for_file_op_error` plus each handler's
 * own early returns in `crates/loom-http/src/files.rs`). */
export function classifyStatus(status: number): FileResult<never>["kind"] {
  switch (status) {
    case 200:
    case 201:
    case 204:
      return "ok";
    case 401:
      return "unauthorized";
    case 404:
      return "notFound";
    case 409:
      return "conflict";
    case 412:
      return "preconditionFailed";
    case 413:
      return "tooLarge";
    case 429:
      return "rateLimited";
    case 503:
      return "busy";
    case 507:
      return "quotaExceeded";
    default:
      return "error";
  }
}

function result<T>(response: { status: number; body: string }, onOk: () => T): FileResult<T> {
  const kind = classifyStatus(response.status);
  if (kind === "ok") {
    return { kind: "ok", value: onOk() };
  }
  if (kind === "error") {
    return { kind: "error", status: response.status, body: response.body };
  }
  return { kind };
}

/** The files the IDE opens are LPC sources a builder wrote; a body that
 * is not valid UTF-8 is a driver bug (M-FS-1 reads text), and `""` for a
 * legitimately empty file is indistinguishable from that at this layer,
 * so this only guards the JSON routes' malformed bodies. */
function parseJson<T>(body: string, fallback: T): T {
  if (body.length === 0) {
    return fallback;
  }
  try {
    return JSON.parse(body) as T;
  } catch {
    return fallback;
  }
}

/** `loom-http`'s `GET /api/v1/files/content` answers with an `ETag` that
 * is a quoted SHA-256 digest; a write must echo it back in `If-Match`
 * (M-FS-6). An empty string means the response had no ETag at all -- a
 * caller that then writes with `If-None-Match: *` will get a `412` if the
 * file exists, which is the correct outcome, not a silent clobber. */
export interface ReadFile {
  path: string;
  text: string;
  etag: string;
}

export class FilesApi {
  constructor(
    private readonly http: Pick<AdminApi, "requestRaw">,
    private readonly baseUrl = "",
  ) {}

  private query(path: string, route: string): string {
    return `${this.baseUrl}${route}?path=${encodeURIComponent(path)}`;
  }

  /** `GET /api/v1/files/content?path=` (M-FS-1/M-FS-4). The body is
   * served as `text/plain; charset=utf-8` with `X-Content-Type-Options:
   * nosniff`, a sandboxed CSP and `Content-Disposition: attachment` --
   * none of which a `fetch` from this origin cares about, but all of
   * which are why the IDE can display a file's contents without ever
   * letting those contents be interpreted as a document (T-FS-1). */
  async read(path: string): Promise<FileResult<ReadFile>> {
    const response = await this.http.requestRaw(this.query(path, "/api/v1/files/content"));
    return result(response, () => ({
      path,
      text: response.body,
      etag: response.headers.get("etag") ?? "",
    }));
  }

  /** `GET /api/v1/files/list?path=` (M-FS-3). */
  async list(path: string): Promise<FileResult<ListingBody>> {
    const response = await this.http.requestRaw(this.query(path, "/api/v1/files/list"));
    return result(response, () => parseJson<ListingBody>(response.body, { entries: [] }));
  }

  /** `PUT /api/v1/files/content?path=` with a mandatory precondition
   * (M-FS-6): `If-Match` for an existing file, `If-None-Match: *` to
   * create one that must not already exist. The server compares against
   * the *current* disk contents inside the world-thread operation, so a
   * `preconditionFailed` here means another builder saved between this
   * client's read and its write -- the IDE must show both versions, not
   * overwrite. */
  async write(path: string, text: string, etag: string | null): Promise<FileResult<null>> {
    const headers: Record<string, string> = { "Content-Type": "text/plain; charset=utf-8" };
    if (etag === null) {
      headers["If-None-Match"] = "*";
    } else {
      headers["If-Match"] = etag;
    }
    const response = await this.http.requestRaw(this.query(path, "/api/v1/files/content"), {
      method: "PUT",
      headers,
      body: text,
    });
    return result(response, () => null);
  }

  /** `POST /api/v1/files/compile?path=` (M-FS-5): queue a recompile of
   * the object at `path` and return the compiler's diagnostics. A
   * successful *response* with `ok: false` is a compile failure -- the
   * common case in an IDE, so it is not an error result. */
  async compile(path: string): Promise<FileResult<CompileBody>> {
    const response = await this.http.requestRaw(this.query(path, "/api/v1/files/compile"), {
      method: "POST",
    });
    return result(response, () =>
      parseJson<CompileBody>(response.body, { ok: false, diagnostics: "" }),
    );
  }

  /** Sign-out, so the IDE can revoke the session it is riding on without
   * the admin module's UI. */
  async logout(): Promise<void> {
    await this.http.requestRaw(`${this.baseUrl}/auth/logout`, {
      method: "POST",
      headers: { "X-Loom-Auth": "1" },
      credentials: "same-origin",
    });
  }
}

/** A one-line description of a non-`ok` result, for the status bar and
 * the diagnostics panel. Server-side messages are never leaked raw into
 * the DOM here -- the caller renders this string through
 * `textContent`-only helpers (`src/admin/dom.ts`). */
/** One sentence a status line can show for a failed file operation.
 * `ok` results have nothing to say (the caller already knows the call
 * worked), so the type only accepts the failure arms -- the switch is
 * exhaustive and a new status kind fails the build here instead of
 * falling through to `undefined` in a UI. */
export function describeResult(res: Exclude<FileResult<unknown>, { kind: "ok" }>): string {
  switch (res.kind) {
    case "unauthorized":
      return "Signed out -- sign in again.";
    case "notFound":
      return "No such file or directory (or you may not read it).";
    case "conflict":
      return "The driver superseded this request.";
    case "preconditionFailed":
      return "Someone saved this file since you opened it.";
    case "rateLimited":
      return "Too many writes -- wait a moment and save again.";
    case "tooLarge":
      return "This file is over the 1 MiB write limit.";
    case "quotaExceeded":
      return "Builder disk quota exceeded.";
    case "busy":
      return "The driver did not answer in time; your changes are still unsaved.";
    case "error":
      return `Driver returned HTTP ${res.status}.`;
  }
}
