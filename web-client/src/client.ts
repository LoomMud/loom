// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import {
  encodeClientEnvelope,
  gmcpEnvelope,
  lineEnvelope,
  parseServerEnvelope,
} from "./protocol.js";

export type GmcpHandler = (payload: unknown) => void;

export interface LoomClientOptions {
  /** `ws://host:port/ws` or `wss://host:port/ws`. */
  url: string;
  /** Called for every output line from the world (`type: "line"`). */
  onLine: (text: string) => void;
  /** Called once the socket is open. */
  onOpen?: () => void;
  /** Called once the socket closes, for any reason. */
  onClose?: () => void;
}

/**
 * A thin wrapper over the browser `WebSocket` that speaks the `/ws` JSON
 * envelope (OBI-39): output lines go to `onLine`, GMCP frames are
 * dispatched to whichever handler registered for that `package` via
 * `onGmcp`, and `sendLine`/`sendGmcp` are the two things a caller can
 * send back. There is no reconnect/backoff logic here -- that is a
 * product decision for whatever page embeds this, not this seam.
 */
export class LoomClient {
  private socket: WebSocket;
  private readonly gmcpHandlers = new Map<string, GmcpHandler>();

  constructor(private readonly options: LoomClientOptions) {
    this.socket = new WebSocket(options.url);
    this.socket.addEventListener("open", () => this.options.onOpen?.());
    this.socket.addEventListener("close", () => this.options.onClose?.());
    this.socket.addEventListener("message", (event: MessageEvent) => {
      if (typeof event.data !== "string") {
        return;
      }
      const envelope = parseServerEnvelope(event.data);
      if (envelope === null) {
        return;
      }
      if (envelope.type === "line") {
        this.options.onLine(envelope.text);
      } else {
        this.gmcpHandlers.get(envelope.package)?.(envelope.payload);
      }
    });
  }

  /** Registers a handler for one GMCP `package.message` name (e.g.
   * `"Char.Vitals"`). Only one handler per package; a second call
   * replaces the first, matching how GMCP packages are meant to be used
   * (one owner per package on the client side). */
  onGmcp(pkg: string, handler: GmcpHandler): void {
    this.gmcpHandlers.set(pkg, handler);
  }

  sendLine(text: string): void {
    this.send(lineEnvelope(text));
  }

  sendGmcp(pkg: string, payload: unknown): void {
    this.send(gmcpEnvelope(pkg, payload));
  }

  close(): void {
    this.socket.close();
  }

  private send(envelope: ReturnType<typeof lineEnvelope>): void {
    if (this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(encodeClientEnvelope(envelope));
    }
  }
}
