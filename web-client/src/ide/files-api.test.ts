// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import test from "node:test";
import assert from "node:assert/strict";

import { classifyStatus, describeResult, FilesApi } from "./files-api.js";
import type { FileResult } from "./files-api.js";
import type { RawResponse } from "../admin/api.js";

/** Narrow a result for the assertions that want the failure arm.
 * `describeResult` takes only failures (there is nothing to say about a
 * call that worked), so a test asserting on a failure's wording has to
 * prove the arm first -- the same discipline the app code follows. */
function expectFailure<T>(result: FileResult<T>): Exclude<FileResult<T>, { kind: "ok" }> {
  assert.notEqual(result.kind, "ok");
  return result as Exclude<FileResult<T>, { kind: "ok" }>;
}

/** The fake `AdminApi.requestRaw` the file client is built on: records
 * what it was asked for and answers with whatever the test queued. */
class FakeHttp {
  readonly calls: { path: string; init?: RequestInit }[] = [];
  readonly queue: RawResponse[] = [];

  constructor(private readonly headers: Record<string, string> = {}) {}

  push(status: number, body = "", headers: Record<string, string> = {}): void {
    this.queue.push({
      status,
      ok: status >= 200 && status < 300,
      headers: new Headers({ ...this.headers, ...headers }),
      body,
    });
  }

  async requestRaw(path: string, init?: RequestInit): Promise<RawResponse> {
    this.calls.push({ path, init });
    const next = this.queue.shift();
    if (next === undefined) {
      throw new Error(`FakeHttp: no queued response for ${path}`);
    }
    return next;
  }
}

test("a read carries the path percent-encoded and returns the ETag", async () => {
  const http = new FakeHttp();
  const api = new FilesApi(http);
  http.push(200, '#include <std.h>\n', { etag: '"abc123"' });

  const result = await api.read("/cmds/kill player.c");
  assert.equal(http.calls[0]?.path, "/api/v1/files/content?path=%2Fcmds%2Fkill%20player.c");
  assert.equal(result.kind, "ok");
  if (result.kind !== "ok") return;
  assert.equal(result.value.text, "#include <std.h>\n");
  assert.equal(result.value.etag, '"abc123"');
  assert.equal(result.value.path, "/cmds/kill player.c");
});

test("a read with no ETag header yields an empty one, not a guess", async () => {
  const http = new FakeHttp();
  const api = new FilesApi(http);
  http.push(200, "contents");
  const result = await api.read("/a.c");
  assert.equal(result.kind === "ok" && result.value.etag, "");
});

test("a listing parses entries and the truncated flag", async () => {
  const http = new FakeHttp();
  const api = new FilesApi(http);
  http.push(200, JSON.stringify({ entries: ["adm", "cmds"], truncated: true }));
  const result = await api.list("/");
  assert.equal(result.kind, "ok");
  if (result.kind !== "ok") return;
  assert.deepEqual(result.value.entries, ["adm", "cmds"]);
  assert.equal(result.value.truncated, true);
});

test("an update write sends If-Match; a create sends If-None-Match: *", async () => {
  const http = new FakeHttp();
  const api = new FilesApi(http);
  http.push(204);
  await api.write("/a.c", "int f() {}", '"etag-value"');
  const headers = http.calls[0]?.init?.headers as Record<string, string>;
  assert.equal(headers["If-Match"], '"etag-value"');
  assert.equal(headers["If-None-Match"], undefined);
  assert.equal(http.calls[0]?.init?.method, "PUT");
  assert.equal(http.calls[0]?.init?.body, "int f() {}");

  http.push(204);
  await api.write("/new.c", "int f() {}", null);
  const createHeaders = http.calls[1]?.init?.headers as Record<string, string>;
  assert.equal(createHeaders["If-None-Match"], "*");
  assert.equal(createHeaders["If-Match"], undefined);
});

test("a compile is a POST with no body and parses ok:false with diagnostics", async () => {
  const http = new FakeHttp();
  const api = new FilesApi(http);
  http.push(200, JSON.stringify({ ok: false, diagnostics: "/a.c:1:5: error[W0201]: bad\n" }));
  const result = await api.compile("/a.c");
  assert.equal(http.calls[0]?.init?.method, "POST");
  assert.equal(http.calls[0]?.init?.body, undefined);
  assert.equal(result.kind, "ok");
  if (result.kind !== "ok") return;
  assert.equal(result.value.ok, false);
  assert.match(result.value.diagnostics ?? "", /W0201/);
});

test("each status the routes can return classifies to its own result kind", async () => {
  assert.equal(classifyStatus(401), "unauthorized");
  assert.equal(classifyStatus(404), "notFound");
  assert.equal(classifyStatus(409), "conflict");
  assert.equal(classifyStatus(412), "preconditionFailed");
  assert.equal(classifyStatus(413), "tooLarge");
  assert.equal(classifyStatus(429), "rateLimited");
  assert.equal(classifyStatus(503), "busy");
  assert.equal(classifyStatus(507), "quotaExceeded");
  assert.equal(classifyStatus(500), "error");
  assert.equal(classifyStatus(200), "ok");
  assert.equal(classifyStatus(204), "ok");
});

test("a 412 on a write is a result, not an exception", async () => {
  const http = new FakeHttp();
  const api = new FilesApi(http);
  http.push(412, "");
  const result = await api.write("/a.c", "text", '"stale"');
  assert.deepEqual(result, { kind: "preconditionFailed" });
  assert.match(describeResult(expectFailure(result)), /Someone saved/);
});

test("a 503 says the buffer is still unsaved, in the message the user sees", async () => {
  const http = new FakeHttp();
  const api = new FilesApi(http);
  http.push(503, "");
  const result = await api.read("/a.c");
  assert.equal(result.kind, "busy");
  assert.match(describeResult(expectFailure(result)), /unsaved/);
});

test("a 500 keeps the status and body for the error path", async () => {
  const http = new FakeHttp();
  const api = new FilesApi(http);
  http.push(500, "boom");
  const result = await api.read("/a.c");
  assert.deepEqual(result, { kind: "error", status: 500, body: "boom" });
  assert.match(describeResult(expectFailure(result)), /HTTP 500/);
});

test("a malformed JSON body falls back instead of throwing", async () => {
  const http = new FakeHttp();
  const api = new FilesApi(http);
  http.push(200, "{not json");
  const listing = await api.list("/");
  assert.deepEqual(listing, { kind: "ok", value: { entries: [] } });

  http.push(200, "{not json");
  const compile = await api.compile("/a.c");
  assert.equal(compile.kind === "ok" && compile.value.ok, false);
});

test("sign-out posts the auth marker header the refresh and logout routes demand", async () => {
  const http = new FakeHttp();
  const api = new FilesApi(http);
  http.push(204);
  await api.logout();
  assert.equal(http.calls[0]?.path, "/auth/logout");
  assert.equal(http.calls[0]?.init?.method, "POST");
  assert.equal(http.calls[0]?.init?.credentials, "same-origin");
  const headers = http.calls[0]?.init?.headers as Record<string, string>;
  assert.equal(headers["X-Loom-Auth"], "1");
});
