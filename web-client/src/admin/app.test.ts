// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { test } from "node:test";

import { pageFromHash } from "./app.js";

test("pageFromHash recognizes every known page", () => {
  assert.equal(pageFromHash("#/who"), "who");
  assert.equal(pageFromHash("#/objects"), "objects");
  assert.equal(pageFromHash("#/errors"), "errors");
  assert.equal(pageFromHash("#/roles"), "roles");
  assert.equal(pageFromHash("#/audit"), "audit");
  assert.equal(pageFromHash("#/broadcast"), "broadcast");
});

test("pageFromHash defaults to who for an empty or unknown hash", () => {
  assert.equal(pageFromHash(""), "who");
  assert.equal(pageFromHash("#/"), "who");
  assert.equal(pageFromHash("#/nonsense"), "who");
});
