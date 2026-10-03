// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import type { AdminApi } from "../api.js";
import { describeError } from "../api.js";
import { clear, el, errorBanner, table } from "../dom.js";

/** `GET /api/v1/admin/audit` (OBI-185 slice 1): every admin-audited
 * action, newest first. Every field is rendered as plain text -- the
 * `detail` column in particular can contain whatever string a caller
 * supplied (a `reason`, a path, ...), so it goes through the same
 * text-node path as everything else here, never `innerHTML`. */
export async function renderAuditPage(root: HTMLElement, api: AdminApi): Promise<void> {
  clear(root);
  root.append(el("h1", {}, ["Audit log"]));
  const body = el("div", {}, ["Loading…"]);
  root.append(body);
  try {
    const rows = await api.auditRecent();
    clear(body);
    body.append(
      table(
        [
          { label: "At", render: (r) => r.at },
          { label: "Kind", render: (r) => r.kind },
          { label: "Caller", render: (r) => r.caller ?? "-" },
          { label: "Verdict", render: (r) => r.verdict },
          { label: "Detail", render: (r) => r.detail ?? "" },
        ],
        rows,
        "no audit entries",
      ),
    );
  } catch (err) {
    clear(body);
    body.append(errorBanner(describeError(err)));
  }
}
