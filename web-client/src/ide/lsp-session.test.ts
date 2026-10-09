// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import test from "node:test";
import assert from "node:assert/strict";

import type { EditorMarker } from "./editor-port.js";
import { FakeLspServer, settle } from "./lsp-fake.js";
import {
  LspSession,
  MAX_FAILED_CONNECTS,
  MAX_SYNC_BYTES,
  hoverText,
  toCompletions,
  toMarker,
  type SessionState,
} from "./lsp-session.js";

function harness(
  options: {
    server?: FakeLspServer;
    tickets?: string[];
    clientInfo?: { name: string; version: string };
  } = {},
) {
  const server = options.server ?? new FakeLspServer();
  const tickets = options.tickets ?? ["t1", "t2", "t3", "t4", "t5", "t6"];
  let ticketIndex = 0;
  const states: [SessionState, string][] = [];
  const diagnostics: [string, EditorMarker[]][] = [];
  const session = new LspSession({
    url: "wss://loom.test/lsp",
    openSocket: server.opener,
    getTicket: () => {
      const ticket = tickets[ticketIndex] ?? `t${ticketIndex}`;
      ticketIndex += 1;
      return Promise.resolve(ticket);
    },
    clientInfo: options.clientInfo,
    onDiagnostics: (path, markers) => {
      diagnostics.push([path, markers]);
    },
    onStateChange: (state, detail) => {
      states.push([state, detail]);
    },
  });
  return { server, session, states, diagnostics, ticketsUsed: () => ticketIndex };
}

test("the handshake is ticket, auth frame, initialize, initialized", async () => {
  const { server, session } = harness();
  session.openDocument("/std/room.wf", 'int foo() { return 1; }\n');
  await settle();

  // D-TM4: the first frame carries the ticket, and nothing else may precede
  // it -- `initialize_start` in the server accepts no other first message, so
  // an out-of-order client would be closed with no diagnostics ever arriving.
  assert.equal(server.authTickets.length, 1);
  assert.equal(server.authTickets[0], "t1");
  assert.equal(server.frames[0]?.["auth"], "t1");
  assert.equal(server.frames[1]?.["method"], "initialize");
  assert.equal(server.frames[2]?.["method"], "initialized");
  assert.equal(server.methods.slice(0, 2).join(","), "initialize,initialized");
  assert.equal(server.opened.length, 1);
  assert.equal(session.getState(), "ready");
});

test("one ticket per connect, and a fresh one on reconnect", async () => {
  const server = new FakeLspServer();
  const { session } = harness({ server, tickets: ["t1", "t2"] });
  session.openDocument("/a.wf", "x");
  await settle();
  server.hangUp(); // the 60 s idle close, a revoked tier, the session cap
  await settle();
  session.openDocument("/b.wf", "y");
  await settle();
  assert.deepEqual(server.authTickets, ["t1", "t2"]);
  assert.equal(server.connects, 2);
});

test("initialize sends no root and no workspace folders", async () => {
  const { server, session } = harness({ clientInfo: { name: "loom-ide", version: "test" } });
  session.openDocument("/a.wf", "x");
  await settle();
  const params = server.frames[1]?.["params"] as Record<string, unknown>;
  // M-LSP-2: a client-claimed root would be the way to make the server use an
  // ungated directory instead of the `ReadAuthorizer`. Asserting the nulls is
  // the cheapest guard against a future edit "helpfully" filling them in.
  assert.equal(params["rootUri"], null);
  assert.equal(params["workspaceFolders"], null);
  assert.equal(params["processId"], null);
  assert.deepEqual(params["clientInfo"], { name: "loom-ide", version: "test" });
});

test("the document URI on the wire is the three-slash loom-vfs form", async () => {
  const { server, session } = harness();
  session.openDocument("/std/room.wf", "int foo();\n");
  await settle();
  assert.equal(server.opened[0]?.uri, "loom-vfs:///std/room.wf");
  // `loom-lsp` looks up the language id only to pick the analyser; it must see
  // the id it registers, or diagnostics never arrive for an open document.
  const textDocument = (server.frames.find((f) => f["method"] === "textDocument/didOpen")?.[
    "params"
  ] as { textDocument: Record<string, unknown> }).textDocument;
  assert.equal(textDocument["languageId"], "loom-lpc");
  assert.equal(textDocument["version"], 1);
  assert.equal(textDocument["text"], "int foo();\n");
});

test("changes increment the version and full-sync the buffer", async () => {
  const { server, session } = harness();
  session.openDocument("/a.wf", "one");
  await settle();
  session.changeDocument("/a.wf", "two");
  await settle();
  session.changeDocument("/a.wf", "three");
  await settle();
  assert.deepEqual(
    server.changed.map((change) => [change.version, change.text]),
    [
      [2, "two"],
      [3, "three"],
    ],
  );
  assert.equal(server.opened.length, 1, "didOpen happens once per connection");
});

test("two edits before the next flush become one frame", async () => {
  // The session coalesces below the bridge's debounce: whatever the policy
  // layer decides, the server must not be asked to compile text that was on
  // screen for one microtask.
  const { server, session } = harness();
  session.openDocument("/a.wf", "one");
  await settle();
  session.changeDocument("/a.wf", "two");
  session.changeDocument("/a.wf", "three");
  await settle();
  assert.deepEqual(server.changed.map((change) => [change.version, change.text]), [[3, "three"]]);
});

test("re-opening an unchanged buffer does not trigger a recompile", async () => {
  const { server, session } = harness();
  session.openDocument("/a.wf", "same");
  await settle();
  session.openDocument("/a.wf", "same");
  session.changeDocument("/a.wf", "same");
  await settle();
  assert.equal(server.opened.length, 1);
  assert.equal(server.changed.length, 0, "a no-op edit must not be sent as a change");
});

test("a reconnect replays didOpen, not didChange", async () => {
  const server = new FakeLspServer();
  const { session } = harness({ server });
  session.openDocument("/a.wf", "v1");
  await settle();
  server.hangUp();
  await settle();
  session.openDocument("/a.wf", "v2");
  await settle();
  // The server's `Workspace` died with the session. A `didChange` for a
  // document it never opened would be dropped on the floor, and the builder
  // would see diagnostics frozen at a file that no longer exists there.
  assert.equal(server.opened.length, 2);
  assert.equal(server.changed.length, 0);
  assert.equal(server.opened[1]?.text, "v2");
  assert.equal(server.opened[1]?.version, 2);
});

test("closing a document releases the server's slot", async () => {
  const { server, session } = harness();
  session.openDocument("/a.wf", "x");
  await settle();
  session.closeDocument("/a.wf");
  await settle();
  assert.deepEqual(server.closedUris, ["loom-vfs:///a.wf"]);
  assert.equal(session.openDocuments(), 0);
});

test("a buffer over the sync limit is refused locally", async () => {
  const { server, session, states } = harness();
  const huge = "a".repeat(MAX_SYNC_BYTES + 1);
  session.openDocument("/huge.wf", huge);
  await settle();
  assert.equal(server.opened.length, 0, "the frame must never be written");
  assert.match(
    states.at(-1)?.[1] ?? "",
    /over the .* live-analysis limit/,
    "the builder is told why nothing is live",
  );
});

test("a path that is not a mudlib program is never synced", async () => {
  const { server, session, states } = harness();
  session.openDocument("/std/../etc/passwd.wf", "x");
  await settle();
  assert.equal(server.methods.includes("textDocument/didOpen"), false);
  // Saying so is the point: a buffer that is silently never analysed looks
  // exactly like a dead analyzer, and a builder who is told the reason can fix
  // the filename. `documentUri` refusing is not the end of the story.
  assert.match(
    states.map(([, detail]) => detail).join("\n"),
    /not a mudlib program path/,
    "the reason reaches the status callback",
  );
});

test("a failed ticket mints no socket and is retried lazily", async () => {
  const server = new FakeLspServer();
  let fail = true;
  const session = new LspSession({
    url: "wss://loom.test/lsp",
    openSocket: server.opener,
    getTicket: () => (fail ? Promise.reject(new Error("401")) : Promise.resolve("ok")),
    onStateChange: () => {},
  });
  session.openDocument("/a.wf", "x");
  await settle();
  assert.equal(server.connects, 0, "a socket must not open without a ticket");
  fail = false;
  session.openDocument("/a.wf", "x");
  await settle();
  assert.equal(server.connects, 1, "the next gesture retries");
});

test("consecutive failed handshakes park the session, and activity stays parked", async () => {
  const server = new FakeLspServer({ failConnect: true });
  const { session } = harness({ server });
  for (let attempt = 0; attempt < MAX_FAILED_CONNECTS; attempt += 1) {
    session.openDocument("/a.wf", "x");
    await settle();
  }
  assert.equal(session.getState(), "failed");
  assert.equal(server.connects, MAX_FAILED_CONNECTS);
  assert.match(session.getDetail(), new RegExp(`after ${MAX_FAILED_CONNECTS} attempts`));

  // A revocation looks exactly like an idle close on the wire (M-LSP-4), so
  // "reconnect lazily" has to be bounded or it becomes a loop against the
  // ticket endpoint. Ordinary activity must not feed it.
  session.changeDocument("/a.wf", "xy");
  await settle();
  assert.equal(server.connects, MAX_FAILED_CONNECTS, "a parked session stays parked");

  // Opening a *new* buffer is a deliberate gesture and gets exactly one more
  // try; it re-parks on the same failure rather than starting a counter anew.
  session.openDocument("/b.wf", "y");
  await settle();
  assert.equal(server.connects, MAX_FAILED_CONNECTS + 1);
  assert.equal(session.getState(), "closed");
});

test("a session that comes back after failures works again", async () => {
  const failing = new FakeLspServer({ failConnect: true });
  const first = harness({ server: failing });
  for (let attempt = 0; attempt < MAX_FAILED_CONNECTS; attempt += 1) {
    first.session.openDocument("/a.wf", "x");
    await settle();
  }
  assert.equal(first.session.getState(), "failed");

  const server = new FakeLspServer();
  const second = harness({ server });
  for (let attempt = 0; attempt < MAX_FAILED_CONNECTS; attempt += 1) {
    second.session.openDocument("/a.wf", "x");
    await settle();
  }
  assert.equal(second.session.getState(), "ready");
  assert.equal(server.opened.length, 1, "the buffer that survived the retries is synced");
});

test("a refused initialize is a connection failure, not a silent hang", async () => {
  const server = new FakeLspServer({ refuseInitialize: true });
  const { session } = harness({ server });
  session.openDocument("/a.wf", "x");
  await settle();
  assert.equal(session.getState(), "closed");
  assert.match(session.getDetail(), /refused the session/);
  assert.equal(server.methods.includes("textDocument/didOpen"), false);
});

test("publishDiagnostics becomes 1-based markers for the right file", async () => {
  const { server, session, diagnostics } = harness();
  session.openDocument("/std/room.wf", "int foo()\n");
  await settle();
  server.publish("loom-vfs:///std/room.wf", [
    {
      range: { start: { line: 0, character: 4 }, end: { line: 0, character: 7 } },
      severity: 1,
      code: "E_SYNTAX",
      message: "expected ;",
    },
    {
      // LSP's `DiagnosticSeverity` is optional and 4 is Hint; the IDE renders
      // both as the quietest level.
      range: { start: { line: 3, character: 0 }, end: { line: 3, character: 3 } },
      severity: 4,
      message: "consider naming this",
    },
    { message: "no range at all" }, // dropped: nothing to underline
    "not an object", // dropped
  ]);
  await settle();
  assert.equal(diagnostics.length, 1);
  const [path, markers] = diagnostics[0] as [string, EditorMarker[]];
  assert.equal(path, "/std/room.wf");
  assert.deepEqual(markers, [
    {
      line: 1,
      column: 5,
      endLine: 1,
      endColumn: 8,
      severity: "error",
      message: "expected ;",
      code: "E_SYNTAX",
    },
    {
      line: 4,
      column: 1,
      endLine: 4,
      endColumn: 4,
      severity: "info",
      message: "consider naming this",
      code: undefined,
    },
  ]);
});

test("a diagnostic for a host path is dropped", async () => {
  const { server, session, diagnostics } = harness();
  session.openDocument("/a.wf", "x");
  await settle();
  server.publish("file:///etc/passwd", [{ message: "pwning" }]);
  server.publish("https://evil/x.wf", []);
  await settle();
  assert.equal(diagnostics.length, 0);
});

test("markers from a reversed range are clamped, not inverted", () => {
  const marker = toMarker({
    range: { start: { line: 5, character: 5 }, end: { line: 2, character: 1 } },
    message: "backwards",
  });
  assert.ok(marker !== null);
  assert.ok(
    marker.endLine > marker.line || (marker.endLine === marker.line && marker.endColumn >= marker.column),
    `range must not run backwards: ${JSON.stringify(marker)}`,
  );
});

test("hover results are flattened from every shape the server may send", () => {
  assert.equal(hoverText("plain"), "plain");
  assert.equal(hoverText({ value: "marked", kind: "markdown" }), "marked");
  assert.equal(hoverText([{ value: "a" }, "b"]), "a\n\nb");
  assert.equal(hoverText(null), "");
  assert.equal(hoverText({ kind: "markdown" }), "");
});

test("completion accepts both the array and the CompletionList form", () => {
  const items = [{ label: "foo", kind: 3, detail: "int foo()", documentation: "Docs" }];
  assert.deepEqual(toCompletions(items), [
    { label: "foo", kind: 3, detail: "int foo()", documentation: "Docs" },
  ]);
  assert.deepEqual(toCompletions({ items, isIncomplete: true }), [
    { label: "foo", kind: 3, detail: "int foo()", documentation: "Docs" },
  ]);
  assert.deepEqual(toCompletions(null), []);
  assert.deepEqual(toCompletions({ items: [{ kind: 1 }] }), [], "an item with no label is useless");
  assert.deepEqual(
    toCompletions({ items: [{ label: "x", documentation: { value: "nested" } }] })[0]?.documentation,
    "nested",
  );
});

test("hover, completion and definition round-trip over the socket", async () => {
  const server = new FakeLspServer({
    respond: (method) => {
      if (method === "textDocument/hover") {
        return { contents: "int foo()", range: { start: { line: 0, character: 4 }, end: { line: 0, character: 7 } } };
      }
      if (method === "textDocument/completion") {
        return { items: [{ label: "foo", kind: 3 }] };
      }
      if (method === "textDocument/definition") {
        return { uri: "loom-vfs:///std/room.wf", range: { start: { line: 9, character: 2 }, end: { line: 9, character: 6 } } };
      }
      return undefined;
    },
  });
  const { session } = harness({ server });
  session.openDocument("/a.wf", "foo");
  await settle();

  const hover = await session.hover("/a.wf", 1, 5);
  assert.deepEqual(hover, {
    text: "int foo()",
    range: { startLine: 1, startColumn: 5, endLine: 1, endColumn: 8 },
  });

  const completions = await session.completion("/a.wf", 1, 5);
  assert.deepEqual(completions, [{ label: "foo", kind: 3, detail: "", documentation: "" }]);

  const definition = await session.definition("/a.wf", 1, 5);
  assert.deepEqual(definition, { path: "/std/room.wf", line: 10, column: 3 });

  // 1-based IDE coordinates go out as 0-based LSP ones.
  const positions = server.frames
    .map(
      (frame) =>
        (frame["params"] as { position?: { line: number; character: number } } | undefined)?.[
          "position"
        ],
    )
    .filter((position) => position !== undefined);
  assert.deepEqual(positions, [
    { line: 0, character: 4 },
    { line: 0, character: 4 },
    { line: 0, character: 4 },
  ]);
});

test("a definition target outside the mudlib is refused", async () => {
  const server = new FakeLspServer({
    respond: () => ({ uri: "file:///etc/passwd", range: null }),
  });
  const { session } = harness({ server });
  session.openDocument("/a.wf", "x");
  await settle();
  assert.equal(await session.definition("/a.wf", 1, 1), null);
});

test("an unanswerable request returns nothing rather than throwing", async () => {
  const { session } = harness();
  session.openDocument("/a.wf", "x");
  await settle();
  assert.equal(await session.hover("/a.wf", 1, 1), null);
  assert.deepEqual(await session.completion("/a.wf", 1, 1), []);
});

test("a bad position or path asks the server for nothing at all", async () => {
  const { server, session } = harness();
  session.openDocument("/a.wf", "x");
  await settle();
  const before = server.methods.length;
  assert.equal(await session.hover("/a.wf", 0, 1), null);
  assert.equal(await session.hover("/a.wf", 1.5, 1), null);
  assert.equal(await session.hover("/bad/../x.wf", 1, 1), null);
  assert.equal(server.methods.length, before, "a malformed request must not be sent");
});

test("dispose shuts down and does not report a lost session", async () => {
  const { server, session } = harness();
  session.openDocument("/a.wf", "x");
  await settle();
  session.dispose();
  await settle();
  assert.ok(server.methods.includes("shutdown"));
  assert.ok(server.methods.includes("exit"));
  assert.equal(server.last?.initiatedClose, true);
  // Nothing further is sent after a dispose: a late `didChange` from a
  // disconnected editor is how a closed tab keeps a session alive.
  const frames = server.frames.length;
  session.changeDocument("/a.wf", "y");
  await settle();
  assert.equal(server.frames.length, frames);
});
