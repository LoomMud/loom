// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { test } from "node:test";

import { AdminApiError, NoAccessTokenError, describeError } from "./api.js";

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
