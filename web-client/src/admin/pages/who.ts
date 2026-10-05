// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import type { AdminApi } from "../api.js";
import { describeError } from "../api.js";
import { clear, el, errorBanner, table } from "../dom.js";

/** `GET /api/v1/admin/who` (OBI-234): tier >= 2 (CTO review on PR #98:
 * a plain T1/builder token can no longer enumerate every connected
 * account). M-ADM-3: the response shape itself never carries an email
 * or an IP -- nothing to render here even if a page wanted to. A 403
 * for a sub-T2 caller renders through the same generic error banner as
 * every other admin page. */
export async function renderWhoPage(root: HTMLElement, api: AdminApi): Promise<void> {
  clear(root);
  root.append(el("h1", {}, ["Who's online"]));
  const body = el("div", {}, ["Loading…"]);
  root.append(body);
  try {
    const rows = await api.who();
    clear(body);
    body.append(
      table(
        [
          { label: "Connection", render: (r) => String(r.conn_id) },
          { label: "Account", render: (r) => r.account ?? "(not logged in)" },
          { label: "Connected at", render: (r) => r.connected_at },
          { label: "Idle (s)", render: (r) => String(r.idle_secs) },
        ],
        rows,
        "no live connections",
      ),
    );
  } catch (err) {
    clear(body);
    body.append(errorBanner(describeError(err)));
  }
}
