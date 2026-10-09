// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import test from "node:test";
import assert from "node:assert/strict";

import { RpcError, RpcPeer, type RpcRequest } from "./lsp-jsonrpc.js";

/** A peer plus the frames it wrote and a timer the test drives by hand. */
function harness(options: { maxPending?: number; timeoutMs?: number } = {}) {
  const sent: Record<string, unknown>[] = [];
  const timers: { fn: () => void; ms: number; cancelled: boolean }[] = [];
  const peer = new RpcPeer(
    (text) => {
      sent.push(JSON.parse(text) as Record<string, unknown>);
    },
    {
      ...options,
      setTimer: (fn, ms) => {
        timers.push({ fn, ms, cancelled: false });
        return timers.length - 1 as unknown as ReturnType<typeof setTimeout>;
      },
      clearTimer: (timer) => {
        const index = timer as unknown as number;
        const entry = timers[index];
        if (entry !== undefined) {
          entry.cancelled = true;
        }
      },
    },
  );
  const fire = (index = 0): void => {
    const entry = timers[index];
    if (entry !== undefined && !entry.cancelled) {
      entry.fn();
    }
  };
  return { peer, sent, timers, fire };
}

/** Drain the promise callbacks attached to a request. */
async function settled(promise: Promise<unknown>): Promise<unknown> {
  return await promise.then(
    (value) => ({ ok: value }),
    (error: unknown) => ({ err: error }),
  );
}

test("a response resolves the request it belongs to", async () => {
  const { peer, sent } = harness();
  const first = peer.request("textDocument/hover", { a: 1 });
  const second = peer.request("textDocument/completion", { b: 2 });
  assert.equal(sent.length, 2);
  assert.equal(sent[0]?.["method"], "textDocument/hover");
  assert.deepEqual(sent[0]?.["params"], { a: 1 });
  assert.notEqual(sent[0]?.["id"], sent[1]?.["id"], "ids must be distinct");

  // Answering out of order is legal in JSON-RPC and must not cross wires --
  // this is the whole reason the peer exists separately from the session.
  peer.accept(JSON.stringify({ jsonrpc: "2.0", id: sent[1]?.["id"], result: "second" }));
  peer.accept(JSON.stringify({ jsonrpc: "2.0", id: sent[0]?.["id"], result: "first" }));
  assert.deepEqual(await settled(first.promise), { ok: "first" });
  assert.deepEqual(await settled(second.promise), { ok: "second" });
  assert.equal(peer.inFlight(), 0);
});

test("a JSON-RPC error rejects with the server's code and message", async () => {
  const { peer } = harness();
  const request = peer.request("textDocument/hover", {});
  peer.accept(
    JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      error: { code: -32800, message: "cancelled by the server" },
    }),
  );
  const outcome = await settled(request.promise);
  const error = (outcome as { err: RpcError }).err;
  assert.ok(error instanceof RpcError);
  assert.equal(error.kind, "server");
  assert.equal(error.code, -32800);
  assert.match(error.message, /cancelled by the server/);
});

test("a timeout rejects and sends $/cancelRequest", async () => {
  const { peer, sent, fire, timers } = harness({ timeoutMs: 1234 });
  const request = peer.request("textDocument/hover", {});
  assert.equal(timers[0]?.ms, 1234);
  fire(0);
  const error = (await settled(request.promise) as { err: RpcError }).err;
  assert.equal(error.kind, "timeout");
  const cancel = sent.at(-1);
  assert.equal(cancel?.["method"], "$/cancelRequest");
  assert.deepEqual(cancel?.["params"], { id: 1 });
  assert.equal(peer.inFlight(), 0, "a timed-out request must stop counting");
});

test("cancel() is the caller's own timeout, and also tells the server", async () => {
  const { peer, sent } = harness();
  const request = peer.request("textDocument/completion", {});
  request.cancel();
  const error = (await settled(request.promise) as { err: RpcError }).err;
  assert.equal(error.kind, "cancelled");
  assert.equal(sent.at(-1)?.["method"], "$/cancelRequest");
  // The server's late answer to a cancelled request is dropped, not thrown:
  // nothing is waiting for it.
  peer.accept(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "too late" }));
  assert.equal(peer.droppedFrames, 1);
});

test("in flight is bounded and the overflow never queues", async () => {
  const { peer } = harness({ maxPending: 2 });
  peer.request("a", {});
  peer.request("b", {});
  const overflow = peer.request("c", {});
  const error = (await settled(overflow.promise) as { err: RpcError }).err;
  assert.equal(error.kind, "busy");
  assert.equal(peer.inFlight(), 2, "the rejected request must not occupy a slot");
});

test("a malformed frame is dropped and counted, never thrown", () => {
  const { peer } = harness();
  peer.request("a", {});
  for (const frame of [
    "not json at all",
    "null",
    '"a string"',
    "[]",
    JSON.stringify({ jsonrpc: "1.0", id: 1, result: 1 }), // wrong version
    JSON.stringify({ jsonrpc: "2.0", id: "seven", result: 1 }), // id type we never issue
    JSON.stringify({ jsonrpc: "2.0", id: 99, result: 1 }), // answer to nothing
    JSON.stringify({ jsonrpc: "2.0", id: 1.5, result: 1 }), // non-integer id
  ]) {
    assert.doesNotThrow(() => peer.accept(frame), frame);
  }
  assert.equal(peer.droppedFrames, 8);
  assert.equal(peer.inFlight(), 1, "the real request is still outstanding");
});

test("an oversized frame is refused before it is parsed", () => {
  const { peer } = harness();
  // 5 MiB of text: past the server's own outbound ceiling, so it cannot be a
  // frame meant for us. `accept` must not even try to parse it.
  const huge = "x".repeat(5 * 1024 * 1024);
  peer.accept(huge);
  assert.equal(peer.droppedFrames, 1);
});

test("a notification reaches the handler exactly once", () => {
  const { peer } = harness();
  const seen: { method: string; params: unknown }[] = [];
  peer.onNotification((note) => {
    seen.push(note);
  });
  peer.accept(
    JSON.stringify({
      jsonrpc: "2.0",
      method: "textDocument/publishDiagnostics",
      params: { uri: "loom-vfs:///a.wf", diagnostics: [] },
    }),
  );
  peer.accept(JSON.stringify({ jsonrpc: "2.0", method: "window/logMessage" }));
  assert.deepEqual(seen.map((note) => note.method), [
    "textDocument/publishDiagnostics",
    "window/logMessage",
  ]);
});

test("a server-initiated request is refused, not executed", () => {
  // `loom-lsp` sends no requests. If one ever arrives, the answer is
  // MethodNotFound -- silently ignoring it would leave the server's own
  // dispatcher waiting on us.
  const { peer, sent } = harness();
  peer.accept(
    JSON.stringify({ jsonrpc: "2.0", id: 77, method: "workspace/applyEdit", params: {} }),
  );
  assert.equal(sent.length, 1);
  assert.equal(sent[0]?.["id"], 77);
  assert.equal((sent[0]?.["error"] as { code: number }).code, -32601);
});

test("closing rejects every outstanding request at once", async () => {
  const { peer, timers } = harness();
  const requests: RpcRequest[] = [peer.request("a", {}), peer.request("b", {})];
  peer.close();
  const outcomes = await Promise.all(requests.map((request) => settled(request.promise)));
  for (const outcome of outcomes) {
    assert.equal((outcome as { err: RpcError }).err.kind, "closed");
  }
  assert.equal(peer.inFlight(), 0);
  assert.ok(timers.every((timer) => timer.cancelled), "no timer may outlive the socket");
});

test("a request after close fails immediately instead of hanging", async () => {
  const { peer, sent } = harness();
  peer.close();
  const request = peer.request("a", {});
  const error = (await settled(request.promise) as { err: RpcError }).err;
  assert.equal(error.kind, "closed");
  assert.equal(sent.length, 0, "nothing may be written to a closed session");
  assert.equal(peer.notify("a", {}), false);
});
