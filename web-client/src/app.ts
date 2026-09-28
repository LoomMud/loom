// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import { LoomClient } from "./client.js";

/**
 * Wires a text pane + input line to a {@link LoomClient} (OBI-39's
 * "minimal web client"). Kept intentionally small: no styling, no
 * reconnect UI, no scrollback trimming -- just enough to prove the `/ws`
 * seam end to end from a browser tab.
 */
export function mountLoomClient(root: {
  pane: HTMLElement;
  input: HTMLInputElement;
  wsUrl: string;
}): LoomClient {
  const client = new LoomClient({
    url: root.wsUrl,
    onLine: (text) => {
      root.pane.append(text);
      root.pane.scrollTop = root.pane.scrollHeight;
    },
    onOpen: () => root.pane.append("-- connected --\n"),
    onClose: () => root.pane.append("\n-- disconnected --\n"),
  });

  root.input.addEventListener("keydown", (event: KeyboardEvent) => {
    if (event.key !== "Enter") {
      return;
    }
    const text = root.input.value;
    root.input.value = "";
    client.sendLine(text);
  });

  return client;
}
