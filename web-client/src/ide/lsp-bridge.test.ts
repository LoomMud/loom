// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import test from "node:test";
import assert from "node:assert/strict";

import type { EditorMarker } from "./editor-port.js";
import { LspBridge, type LspSync, type SessionMaker } from "./lsp-bridge.js";
import type { HoverAnswer, SessionState } from "./lsp-session.js";

/** The session the bridge drives, reduced to recorded calls. */
class FakeSync implements LspSync {
  readonly calls: string[] = [];
  openDocument(path: string, text: string): void {
    this.calls.push(`open ${path} ${text}`);
  }
  changeDocument(path: string, text: string): void {
    this.calls.push(`change ${path} ${text}`);
  }
  closeDocument(path: string): void {
    this.calls.push(`close ${path}`);
  }
  hover(): Promise<HoverAnswer | null> {
    this.calls.push("hover");
    return Promise.resolve(null);
  }
  completion(): Promise<never[]> {
    this.calls.push("completion");
    return Promise.resolve([]);
  }
  dispose(): void {
    this.calls.push("dispose");
  }
}

function harness(
  options: {
    debounceMs?: number;
    maxWaitMs?: number;
    sync?: FakeSync;
  } = {},
) {
  const sync = options.sync ?? new FakeSync();
  let handlers: {
    onDiagnostics: (path: string, markers: EditorMarker[]) => void;
    onStateChange: (state: SessionState, detail: string) => void;
  } | null = null;
  const createSession: SessionMaker = (h) => {
    handlers = h;
    return sync;
  };

  const markers: [string, EditorMarker[]][] = [];
  const status: string[] = [];
  /** Virtual time: the debounce is the behaviour under test, so a real timer
   * would make the test slow, and a `setTimeout` spy makes it exact. */
  let clock = 0;
  const timers: { at: number; fn: () => void; cancelled: boolean }[] = [];

  const bridge = new LspBridge({
    createSession,
    debounceMs: options.debounceMs ?? 300,
    maxWaitMs: options.maxWaitMs ?? 2_000,
    now: () => clock,
    setTimer: (fn, ms) => {
      timers.push({ at: clock + ms, fn, cancelled: false });
      return (timers.length - 1) as unknown as ReturnType<typeof setTimeout>;
    },
    clearTimer: (timer) => {
      const entry = timers[timer as unknown as number];
      if (entry !== undefined) {
        entry.cancelled = true;
      }
    },
    setMarkers: (path, value) => {
      markers.push([path, value]);
    },
    onStatus: (message) => {
      status.push(message);
    },
  });

  /** Advance the clock and run every timer whose deadline has passed. */
  const advance = (ms: number): void => {
    const target = clock + ms;
    for (;;) {
      const due = timers
        .map((entry, index) => ({ entry, index }))
        .filter(({ entry }) => !entry.cancelled && entry.at <= target)
        .sort((a, b) => a.entry.at - b.entry.at)[0];
      if (due === undefined) {
        break;
      }
      clock = due.entry.at;
      due.entry.cancelled = true;
      due.entry.fn();
    }
    clock = target;
  };

  const diagnostics = (path: string, value: unknown[] = []): void => {
    (handlers as NonNullable<typeof handlers>).onDiagnostics(path, value as EditorMarker[]);
  };
  const state = (value: SessionState, detail: string): void => {
    (handlers as NonNullable<typeof handlers>).onStateChange(value, detail);
  };

  return { bridge, sync, markers, status, advance, diagnostics, state, timers };
}

const marker: EditorMarker = {
  line: 1,
  column: 1,
  endLine: 1,
  endColumn: 4,
  severity: "error",
  message: "expected ;",
};

test("opening a file syncs it immediately, with no debounce", () => {
  const { bridge, sync } = harness();
  bridge.documentOpened("/a.wf", "text");
  assert.deepEqual(sync.calls, ["open /a.wf text"]);
});

test("the analyser's markers are cleared before its first answer", () => {
  // The previous view of this file may have had squiggles; the worst a stale
  // set can do after this point is be missing for one round trip.
  const { bridge, markers } = harness();
  bridge.documentOpened("/a.wf", "text");
  assert.deepEqual(markers[0], ["/a.wf", []]);
});

test("keystrokes inside the window become one change", () => {
  const { bridge, sync, advance } = harness({ debounceMs: 300 });
  bridge.documentOpened("/a.wf", "");
  bridge.documentChanged("/a.wf", "i");
  bridge.documentChanged("/a.wf", "in");
  bridge.documentChanged("/a.wf", "int");
  advance(299);
  assert.deepEqual(sync.calls, ["open /a.wf "], "nothing is sent while typing");
  advance(1);
  assert.deepEqual(sync.calls.at(-1), "change /a.wf int");
  assert.equal(sync.calls.filter((call) => call.startsWith("change")).length, 1);
});

test("continuous typing is unheard for at most the max wait", () => {
  const { bridge, sync, advance } = harness({ debounceMs: 300, maxWaitMs: 2_000 });
  bridge.documentOpened("/a.wf", "");
  // One keystroke every 200 ms: the trailing window slides and never elapses,
  // so without `maxWaitMs` the analyser would not hear about this buffer for
  // 2.6 s *plus* 300 ms after the burst ended. The keystroke that crosses 2 s
  // is the one that forces the answer.
  for (let index = 1; index <= 12; index += 1) {
    bridge.documentChanged("/a.wf", "x".repeat(index));
    advance(200);
  }
  const during = sync.calls.filter((call) => call.startsWith("change"));
  assert.deepEqual(during, ["change /a.wf " + "x".repeat(11)], "one forced flush, mid-burst");
  advance(400);
  assert.equal(
    sync.calls.at(-1),
    "change /a.wf " + "x".repeat(12),
    "the window then closes on the final text",
  );
});

test("an edit to a buffer that is not on screen is ignored", () => {
  const { bridge, sync, advance } = harness();
  bridge.documentOpened("/a.wf", "a");
  bridge.documentChanged("/b.wf", "b");
  advance(5_000);
  assert.equal(sync.calls.some((call) => call.includes("/b.wf")), false);
});

test("switching files closes the old one and forgets its pending edit", () => {
  const { bridge, sync, advance } = harness();
  bridge.documentOpened("/a.wf", "a");
  bridge.documentChanged("/a.wf", "typing");
  bridge.documentOpened("/b.wf", "b");
  advance(5_000);
  assert.deepEqual(sync.calls, ["open /a.wf a", "close /a.wf", "open /b.wf b"]);
});

test("only the visible buffer is ever open, however many files are visited", () => {
  const { bridge, sync } = harness();
  for (const path of ["/a.wf", "/b.wf", "/c.wf", "/d.wf"]) {
    bridge.documentOpened(path, path);
  }
  const opens = sync.calls.filter((call) => call.startsWith("open")).length;
  const closes = sync.calls.filter((call) => call.startsWith("close")).length;
  assert.equal(opens, 4);
  assert.equal(closes, 3, "one document stays open; the rest were closed on the way");
});

test("closing a buffer stops its analysis", () => {
  const { bridge, sync, markers, advance } = harness();
  bridge.documentOpened("/a.wf", "a");
  bridge.documentChanged("/a.wf", "b");
  bridge.documentClosed("/a.wf");
  advance(5_000);
  assert.equal(sync.calls.includes("change /a.wf b"), false, "a dead buffer is not synced");
  assert.deepEqual(sync.calls.at(-1), "close /a.wf");
  assert.deepEqual(markers.at(-1), ["/a.wf", []], "its squiggles go with it");
});

test("diagnostics for another file never repaint this one", () => {
  const { bridge, markers, diagnostics } = harness();
  bridge.documentOpened("/a.wf", "a");
  markers.length = 0;
  diagnostics("/b.wf", [marker]);
  assert.equal(markers.length, 0);
  diagnostics("/a.wf", [marker]);
  assert.deepEqual(markers, [["/a.wf", [marker]]]);
});

test("an empty diagnostic list clears the squiggles", () => {
  // The "the builder fixed it" case, which has to be as loud as the error
  // case or the editor lies about the state of the file.
  const { bridge, markers, diagnostics } = harness();
  bridge.documentOpened("/a.wf", "a");
  diagnostics("/a.wf", [marker]);
  diagnostics("/a.wf", []);
  assert.deepEqual(markers.at(-1), ["/a.wf", []]);
});

test("an idle close says nothing; a failure says why", () => {
  const { bridge, status, state } = harness();
  bridge.documentOpened("/a.wf", "a");
  state("connecting", "connecting to loom-lsp");
  state("ready", "");
  state("closed", "the driver closed the live-analysis session");
  assert.deepEqual(status, [], "a 60 s idle close is designed behaviour, not news");

  state("failed", "could not reach /lsp (connection refused)");
  assert.deepEqual(status, ["Live analysis stopped: could not reach /lsp (connection refused)"]);
});

test("a session that was never ready and then closed stays quiet", () => {
  // A builder whose driver has no `/lsp` route should not be told about it on
  // every page load; that is `connecting` -> `closed`, not a working session
  // that was taken away.
  const { bridge, status, state } = harness();
  bridge.documentOpened("/a.wf", "a");
  state("connecting", "connecting to loom-lsp");
  state("closed", "could not reach /lsp (404)");
  assert.deepEqual(status, []);
});

test("dispose reaches the session and stops the timers", () => {
  const { bridge, sync, advance, timers } = harness();
  bridge.documentOpened("/a.wf", "a");
  bridge.documentChanged("/a.wf", "b");
  bridge.dispose();
  advance(5_000);
  assert.equal(sync.calls.includes("change /a.wf b"), false);
  assert.equal(sync.calls.at(-1), "dispose");
  assert.ok(timers.every((timer) => timer.cancelled));
  // A late event after dispose must not resurrect anything.
  bridge.documentChanged("/a.wf", "c");
  bridge.documentOpened("/d.wf", "d");
  assert.equal(sync.calls.at(-1), "dispose");
});

test("the providers ask the session, in the IDE's 1-based coordinates", async () => {
  const { bridge, sync } = harness();
  const hover = await bridge.providers.hover("/a.wf", 3, 7);
  assert.equal(hover, null);
  assert.deepEqual(await bridge.providers.completion("/a.wf", 3, 7), []);
  assert.deepEqual(sync.calls, ["hover", "completion"]);
});
