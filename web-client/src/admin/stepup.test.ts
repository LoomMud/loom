// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { test } from "node:test";

import { decodeAccessToken, isStepUpFresh, STEP_UP_WINDOW_SECS } from "./stepup.js";

function fakeToken(claims: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return `${header}.${payload}.sig`;
}

test("decodeAccessToken reads sub/tier/mfa_at out of a well-formed token", () => {
  const token = fakeToken({ sub: "lead", tier: 3, mfa_at: 1000, exp: 2000 });
  const claims = decodeAccessToken(token);
  assert.equal(claims?.sub, "lead");
  assert.equal(claims?.tier, 3);
  assert.equal(claims?.mfa_at, 1000);
});

test("decodeAccessToken returns null for a malformed token", () => {
  assert.equal(decodeAccessToken("not-a-jwt"), null);
  assert.equal(decodeAccessToken("a.b"), null);
});

test("decodeAccessToken returns null when the payload isn't an object with sub/tier", () => {
  const badPayload = Buffer.from(JSON.stringify([1, 2, 3])).toString("base64url");
  assert.equal(decodeAccessToken(`h.${badPayload}.s`), null);
});

test("isStepUpFresh is true exactly at the window boundary", () => {
  const token = fakeToken({ sub: "lead", tier: 3, mfa_at: 1000, exp: 999999 });
  assert.equal(isStepUpFresh(token, 1000 + STEP_UP_WINDOW_SECS), true);
  assert.equal(isStepUpFresh(token, 1000 + STEP_UP_WINDOW_SECS + 1), false);
});

test("isStepUpFresh is false with no token, no mfa_at, or a malformed token", () => {
  assert.equal(isStepUpFresh(null), false);
  assert.equal(isStepUpFresh(fakeToken({ sub: "lead", tier: 1, mfa_at: null, exp: 999999 })), false);
  assert.equal(isStepUpFresh("garbage"), false);
});
