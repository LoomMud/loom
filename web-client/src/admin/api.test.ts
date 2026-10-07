// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { AdminApi, AdminApiError, NoAccessTokenError, describeError, objectVarsPath } from "./api.js";

type FetchCall = { input: string; init: RequestInit | undefined };

/** Installs a fake `global.fetch` for the duration of one test and
 * records every call's URL + `RequestInit` so assertions can check
 * headers/credentials/method without a real network or a DOM `fetch`
 * polyfill -- `node:test` runs these files under plain Node, which has
 * a real global `fetch`, so this is a deliberate stand-in, not a shim
 * for a missing API. */
function installFetch(
  handler: (call: FetchCall, callIndex: number) => { status: number; body?: unknown },
): { calls: FetchCall[]; restore: () => void } {
  const original = global.fetch;
  const calls: FetchCall[] = [];
  global.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const call = { input: String(input), init };
    calls.push(call);
    const { status, body } = handler(call, calls.length - 1);
    const text = body === undefined ? "" : JSON.stringify(body);
    return new Response(text, { status });
  }) as typeof fetch;
  return {
    calls,
    restore: () => {
      global.fetch = original;
    },
  };
}

let restoreFetch: (() => void) | undefined;

afterEach(() => {
  restoreFetch?.();
  restoreFetch = undefined;
});

test("describeError: no token", () => {
  assert.equal(describeError(new NoAccessTokenError()), "not signed in");
});

test("describeError: 401 is a session-expired message", () => {
  assert.equal(describeError(new AdminApiError(401, null)), "session expired -- please sign in again");
});

test("describeError: 403 step_up_required is a step-up message", () => {
  assert.equal(
    describeError(new AdminApiError(403, { error: "step_up_required" })),
    "step-up re-authentication required",
  );
});

test("describeError: plain 403 is forbidden", () => {
  assert.equal(describeError(new AdminApiError(403, { error: "forbidden" })), "forbidden");
});

test("describeError: 503 is service unavailable", () => {
  assert.equal(describeError(new AdminApiError(503, null)), "service unavailable");
});

test("describeError: other status codes fall back to a generic message", () => {
  assert.equal(describeError(new AdminApiError(500, null)), "request failed (HTTP 500)");
});

test("describeError: a plain Error uses its own message", () => {
  assert.equal(describeError(new Error("network down")), "network down");
});

test("describeError: anything else is unknown", () => {
  assert.equal(describeError("oops"), "unknown error");
});

test("objectVarsPath percent-encodes each segment and neuters dot segments", () => {
  assert.equal(objectVarsPath("/domains/shire/bag_end"), "/api/v1/admin/objects/domains/shire/bag_end/vars");
  assert.equal(objectVarsPath("/a?b#c"), "/api/v1/admin/objects/a%3Fb%23c/vars");
  assert.equal(objectVarsPath("/../../audit"), "/api/v1/admin/objects/%2E%2E/%2E%2E/audit/vars");
});

test("request: a 401 triggers one silent refresh, then retries the original call", async () => {
  let token = "stale-token";
  const { calls, restore } = installFetch((call, index) => {
    if (index === 0) {
      assert.equal(call.input, "/api/v1/admin/who");
      return { status: 401 };
    }
    if (index === 1) {
      assert.equal(call.input, "/auth/refresh");
      return { status: 200, body: { access_token: "fresh-token", access_expires_at: 123 } };
    }
    assert.equal(call.input, "/api/v1/admin/who");
    return { status: 200, body: [] };
  });
  restoreFetch = restore;

  const api = new AdminApi({
    baseUrl: "",
    getAccessToken: () => token,
    setAccessToken: (t) => {
      token = t;
    },
  });
  const result = await api.who();
  assert.deepEqual(result, []);
  assert.equal(calls.length, 3);
  assert.equal(token, "fresh-token");
  const retryAuth = calls[2]?.init?.headers as Record<string, string>;
  assert.equal(retryAuth.Authorization, "Bearer fresh-token");
});

test("request: a second 401 after a successful refresh surfaces as AdminApiError", async () => {
  const { calls, restore } = installFetch((_call, index) => {
    if (index === 1) {
      return { status: 200, body: { access_token: "fresh-token" } };
    }
    return { status: 401, body: { error: "invalid" } };
  });
  restoreFetch = restore;

  const api = new AdminApi({
    baseUrl: "",
    getAccessToken: () => "token",
    setAccessToken: () => {},
  });
  await assert.rejects(() => api.who(), AdminApiError);
  assert.equal(calls.length, 3);
});

test("request: a refresh that itself fails does not retry, and the original 401 surfaces", async () => {
  const { calls, restore } = installFetch((_call, index) => (index === 1 ? { status: 401 } : { status: 401 }));
  restoreFetch = restore;

  const api = new AdminApi({
    baseUrl: "",
    getAccessToken: () => "token",
    setAccessToken: () => {},
  });
  await assert.rejects(() => api.who(), AdminApiError);
  // One original attempt, one failed refresh, no second retry.
  assert.equal(calls.length, 2);
});

test("refresh: sends credentials same-origin and the X-Loom-Auth header, never a refresh token", async () => {
  const { calls, restore } = installFetch(() => ({
    status: 200,
    body: { access_token: "fresh-token", access_expires_at: 999 },
  }));
  restoreFetch = restore;

  let stored: string | null = null;
  const api = new AdminApi({
    baseUrl: "",
    getAccessToken: () => null,
    setAccessToken: (t) => {
      stored = t;
    },
  });
  const ok = await api.refresh();
  assert.equal(ok, true);
  assert.equal(stored, "fresh-token");
  assert.equal(calls.length, 1);
  const call = calls[0];
  assert.equal(call?.input, "/auth/refresh");
  assert.equal(call?.init?.method, "POST");
  assert.equal(call?.init?.credentials, "same-origin");
  assert.equal((call?.init?.headers as Record<string, string>)["X-Loom-Auth"], "1");
  // The body must never carry anything named like a refresh token.
  assert.equal(call?.init?.body, undefined);
});

test("refresh: a non-OK response resolves to false and never calls setAccessToken", async () => {
  const { restore } = installFetch(() => ({ status: 401 }));
  restoreFetch = restore;

  let called = false;
  const api = new AdminApi({
    baseUrl: "",
    getAccessToken: () => null,
    setAccessToken: () => {
      called = true;
    },
  });
  assert.equal(await api.refresh(), false);
  assert.equal(called, false);
});

test("logout: sends credentials same-origin and the X-Loom-Auth header", async () => {
  const { calls, restore } = installFetch(() => ({ status: 204 }));
  restoreFetch = restore;

  const api = new AdminApi({
    baseUrl: "",
    getAccessToken: () => null,
    setAccessToken: () => {},
  });
  await api.logout();
  assert.equal(calls.length, 1);
  const call = calls[0];
  assert.equal(call?.input, "/auth/logout");
  assert.equal(call?.init?.method, "POST");
  assert.equal(call?.init?.credentials, "same-origin");
  assert.equal((call?.init?.headers as Record<string, string>)["X-Loom-Auth"], "1");
});

test("logout: a network failure resolves (never throws)", async () => {
  const original = global.fetch;
  global.fetch = (async () => {
    throw new Error("network down");
  }) as typeof fetch;
  restoreFetch = () => {
    global.fetch = original;
  };

  const api = new AdminApi({
    baseUrl: "",
    getAccessToken: () => null,
    setAccessToken: () => {},
  });
  await api.logout();
});
