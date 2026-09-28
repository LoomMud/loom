// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The JSON envelope spoken over `/ws` (see `loom-net/src/ws.rs` and
 * `loom-http/src/lib.rs` on the driver side, OBI-39). Both directions use
 * the same shape, tagged by `type`:
 *
 * - `{"type":"line","text":"..."}` -- a plain output/input line.
 * - `{"type":"gmcp","package":"Pkg.Msg","payload":{...}}` -- a GMCP frame,
 *   exactly like telnet's `IAC SB GMCP ... IAC SE` but as JSON instead of
 *   a subnegotiation body.
 */
export type ServerEnvelope =
  | { type: "line"; text: string }
  | { type: "gmcp"; package: string; payload: unknown };

export type ClientEnvelope =
  | { type: "line"; text: string }
  | { type: "gmcp"; package: string; payload: unknown };

/** Parses one incoming WS text frame. Returns `null` for anything that
 * isn't a well-formed envelope, rather than throwing: a malformed frame
 * from the server shouldn't be able to crash the client's message loop. */
export function parseServerEnvelope(raw: string): ServerEnvelope | null {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return null;
  }

  if (typeof value !== "object" || value === null) {
    return null;
  }
  const obj = value as Record<string, unknown>;

  if (obj.type === "line" && typeof obj.text === "string") {
    return { type: "line", text: obj.text };
  }
  if (obj.type === "gmcp" && typeof obj.package === "string") {
    return { type: "gmcp", package: obj.package, payload: obj.payload ?? null };
  }
  return null;
}

export function encodeClientEnvelope(envelope: ClientEnvelope): string {
  return JSON.stringify(envelope);
}

export function lineEnvelope(text: string): ClientEnvelope {
  return { type: "line", text };
}

export function gmcpEnvelope(pkg: string, payload: unknown): ClientEnvelope {
  return { type: "gmcp", package: pkg, payload };
}
