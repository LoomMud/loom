// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The whole client stack, wired the way `./main.ts` wires it: the IDE
 * controller, the policy bridge, the JSON-RPC session, and a fake `loom-lsp`
 * behind a fake socket.
 *
 * Each layer has its own unit test. This file exists for the claims that only
 * appear once the layers are connected -- that opening a file in the tree is
 * what puts `didOpen` on the wire, that the analyser's squiggles and the
 * compiler's squiggles occupy different namespaces in the same editor, and that
 * a builder who switches buffers leaves no open document behind on the driver.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { FakeEditor, FakeFiles, harnessIde } from "./app-fakes.js";
import { bridgeForSession } from "./lsp-bridge.js";
import { FakeLspServer } from "./lsp-fake.js";

const wait = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * The production wiring, with the browser's two globals replaced by fakes: the
 * socket is `FakeLspServer`'s (the transport's own `openWebSocket` adapter is
 * covered against a fake `WebSocket` global in `./lsp-transport.test.ts`) and
 * `fetchWsTicket` becomes a fixed ticket. Everything between the controller and
 * the wire is the real code.
 */
function stack(
  files: FakeFiles,
  server: FakeLspServer = new FakeLspServer(),
): { ide: ReturnType<typeof harnessIde>["ide"]; editor: FakeEditor; server: FakeLspServer; status: string[] } {
  const editor = new FakeEditor();
  const status: string[] = [];
  const bridge = bridgeForSession(
    {
      url: "wss://mud.example/lsp",
      openSocket: server.opener,
      getTicket: () => Promise.resolve("tk-1"),
      clientInfo: { name: "loom-ide-test", version: "0" },
    },
    {
      setMarkers: (_path, markers) => editor.setMarkers(markers, "loom-lsp"),
      onStatus: (message) => status.push(message),
      debounceMs: 20,
      maxWaitMs: 200,
    },
  );
  const { ide } = harnessIde(files, { lsp: bridge }, editor);
  return { ide, editor, server, status };
}

/** Open a mudlib file through the tree and let the handshake finish. */
async function openFile(
  ide: ReturnType<typeof stack>["ide"],
  path: string,
): Promise<void> {
  ide.start();
  await wait(10);
  const row = ide.rows().find((entry) => entry.path === path);
  assert.ok(row, `${path} is listed in the tree`);
  await ide.activate(row);
  await wait(30);
}

test("opening a file in the tree is what puts didOpen on the wire", async () => {
  const files = new FakeFiles();
  files.file("/room.wf", "object room;");
  const server = new FakeLspServer();
  const { ide, editor } = stack(files, server);
  await openFile(ide, "/room.wf");

  assert.equal(editor.currentPath(), "/room.wf");
  // The one-time ticket is spent on the very first frame, before any method:
  // that ordering is what D-TM4's server-side check assumes.
  assert.equal(server.frames[0]?.["auth"], "tk-1");
  assert.deepEqual(server.methods.slice(0, 3), [
    "initialize",
    "initialized",
    "textDocument/didOpen",
  ]);
  assert.deepEqual(server.opened, [
    { uri: "loom-vfs:///room.wf", text: "object room;", version: 1 },
  ]);
});

test("live diagnostics and save diagnostics occupy different namespaces", async () => {
  const files = new FakeFiles();
  files.file("/room.wf", "object room;");
  const server = new FakeLspServer();
  const { ide, editor } = stack(files, server);
  await openFile(ide, "/room.wf");

  // The analyser's answer, pushed unsolicited, becomes an editor marker and
  // nothing else. The diagnostics panel belongs to the save path: mixing a
  // keystroke's worth of noise into it would destroy what the builder is
  // reading while the driver's own answer is still on screen.
  server.publish("loom-vfs:///room.wf", [
    {
      range: { start: { line: 0, character: 7 }, end: { line: 0, character: 11 } },
      severity: 1,
      message: "expected ;",
      source: "loom-lsp",
      code: "W0201",
    },
  ]);
  await wait(10);
  assert.deepEqual(
    editor.markersFor("loom-lsp").map((marker) => [marker.line, marker.severity, marker.message]),
    [[1, "error", "expected ;"]],
  );
  assert.deepEqual(editor.markersFor("loom-ide"), []);

  // Now save into a compile failure: the driver's answer lands under the save
  // owner, and neither set erases the other.
  files.compileResult = {
    ok: false,
    diagnostics: "/room.wf:3:1: error[W0999]: bad type\n",
  };
  editor.pressSave();
  await wait(40);
  assert.ok(editor.markersFor("loom-ide").length > 0, "the save path painted its markers");
  assert.equal(
    editor.markersFor("loom-lsp").length,
    1,
    "the live marker survived the save: different owners, different answers",
  );
});

test("keystrokes reach the analyser as one debounced change", async () => {
  const files = new FakeFiles();
  files.file("/room.wf", "a");
  const server = new FakeLspServer();
  const { ide, editor } = stack(files, server);
  await openFile(ide, "/room.wf");
  server.changed.length = 0;

  editor.type("ab");
  editor.type("abc");
  editor.type("abcd");
  await wait(60);
  assert.deepEqual(
    server.changed.map((change) => change.text),
    ["abcd"],
    "three keystrokes, one full-sync frame",
  );
});

test("switching buffers closes the old document on the driver", async () => {
  const files = new FakeFiles();
  files.file("/room.wf", "object room;");
  files.file("/root.wf", "object root;");
  const server = new FakeLspServer();
  const { ide } = stack(files, server);
  ide.start();
  await wait(10);
  const first = ide.rows().find((entry) => entry.path === "/room.wf");
  const second = ide.rows().find((entry) => entry.path === "/root.wf");
  assert.ok(first && second);
  await ide.activate(first);
  await wait(30);
  await ide.activate(second);
  await wait(30);

  assert.deepEqual(server.closedUris, ["loom-vfs:///room.wf"]);
  assert.deepEqual(
    server.opened.map((open) => open.uri),
    ["loom-vfs:///room.wf", "loom-vfs:///root.wf"],
  );
  // Exactly one document stays open, not one per file the builder has clicked:
  // the server's cap is 64 per session, and a long session would meet it.
  assert.equal(server.opened.length - server.closedUris.length, 1);
});

test("a file the analyser cannot represent is opened without a sync", async () => {
  const files = new FakeFiles();
  // `.c` is not a program path the mudlib would resolve, so `loom-lsp` has no
  // document for it and the client must not invent one.
  files.file("/kill.c", "int f() { return 1; }");
  const server = new FakeLspServer();
  const { ide } = stack(files, server);
  await openFile(ide, "/kill.c");
  assert.equal(server.methods.includes("textDocument/didOpen"), false);
  assert.equal(server.connects, 0, "no socket was even opened for it");
});

test("a dead analyser never interrupts the save path", async () => {
  const files = new FakeFiles();
  files.file("/room.wf", "object room;");
  const server = new FakeLspServer({ refuseInitialize: true });
  const { ide, editor, status } = stack(files, server);
  await openFile(ide, "/room.wf");

  assert.equal(server.methods.includes("textDocument/didOpen"), false);
  // Live analysis is a convenience layer, not a dependency: the save-compile
  // round trip is the authoritative one and still runs.
  files.compileResult = { ok: true };
  editor.pressSave();
  await wait(40);
  assert.equal(files.writes.length, 1);
  assert.ok(status.length <= 1, `at most one line about it, saw ${status.length}`);
});

test("closing the IDE shuts the session down", async () => {
  const files = new FakeFiles();
  files.file("/room.wf", "object room;");
  const server = new FakeLspServer();
  const { ide } = stack(files, server);
  await openFile(ide, "/room.wf");
  ide.dispose();
  await wait(10);
  assert.ok(server.methods.includes("shutdown"), "the analyser is told to stop");
  assert.ok(server.methods.includes("exit"));
});
