// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  encodeClientEnvelope,
  gmcpEnvelope,
  lineEnvelope,
  parseServerEnvelope,
} from "./protocol.js";

test("parses a line envelope", () => {
  const parsed = parseServerEnvelope(JSON.stringify({ type: "line", text: "hi\n" }));
  assert.deepEqual(parsed, { type: "line", text: "hi\n" });
});

test("parses a gmcp envelope", () => {
  const parsed = parseServerEnvelope(
    JSON.stringify({ type: "gmcp", package: "Char.Vitals", payload: { hp: 10 } }),
  );
  assert.deepEqual(parsed, {
    type: "gmcp",
    package: "Char.Vitals",
    payload: { hp: 10 },
  });
});

test("gmcp envelope with no payload defaults to null", () => {
  const parsed = parseServerEnvelope(JSON.stringify({ type: "gmcp", package: "Core.Ping" }));
  assert.deepEqual(parsed, { type: "gmcp", package: "Core.Ping", payload: null });
});

test("drops malformed JSON", () => {
  assert.equal(parseServerEnvelope("not json"), null);
});

test("drops an envelope with an unknown type", () => {
  assert.equal(parseServerEnvelope(JSON.stringify({ type: "ping" })), null);
});

test("drops a non-object JSON value", () => {
  assert.equal(parseServerEnvelope("42"), null);
});

test("encodes a line envelope for the wire", () => {
  assert.equal(encodeClientEnvelope(lineEnvelope("look")), JSON.stringify({ type: "line", text: "look" }));
});

test("encodes a gmcp envelope for the wire", () => {
  assert.equal(
    encodeClientEnvelope(gmcpEnvelope("Core.Hello", { client: "web", version: "1.0" })),
    JSON.stringify({ type: "gmcp", package: "Core.Hello", payload: { client: "web", version: "1.0" } }),
  );
});
