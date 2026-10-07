// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import type { AdminApi } from "../api.js";
import { describeError } from "../api.js";
import { clear, el, errorBanner, table } from "../dom.js";

/** `GET /api/v1/admin/errors` (OBI-235): the grouped runtime-error
 * inbox, T3+. `message`/`redacted` are already capped and
 * `/secure`-redacted server-side (M-ERR-1) -- this page renders exactly
 * what it's given, as plain text, never re-deciding what a caller is
 * allowed to see. */
export async function renderErrorsPage(root: HTMLElement, api: AdminApi): Promise<void> {
  clear(root);
  root.append(el("h1", {}, ["Runtime errors"]));

  const filterInput = el("input", {
    type: "text",
    placeholder: "filter by program prefix, e.g. /domains/shire",
  }) as HTMLInputElement;
  const filterButton = el("button", { type: "button" }, ["Filter"]);
  root.append(el("div", { class: "errors-filter" }, [filterInput, filterButton]));

  const body = el("div", {}, ["Loading…"]);
  root.append(body);

  const load = async (programPrefix?: string) => {
    clear(body);
    body.append(el("p", {}, ["Loading…"]));
    try {
      const rows = await api.errors(programPrefix);
      clear(body);
      body.append(
        table(
          [
            { label: "Program", render: (r) => r.program },
            { label: "Function", render: (r) => r.function },
            { label: "Line", render: (r) => (r.line === null ? "?" : String(r.line)) },
            { label: "Message", render: (r) => (r.redacted ? "<redacted>" : r.message) },
            { label: "Count", render: (r) => String(r.count) },
            {
              label: "Last seen",
              render: (r) => new Date(r.last_seen_unix_ms).toISOString(),
            },
          ],
          rows,
          "no recorded errors",
        ),
      );
    } catch (err) {
      clear(body);
      body.append(errorBanner(describeError(err)));
    }
  };

  filterButton.addEventListener("click", () => {
    const value = filterInput.value.trim();
    void load(value.length > 0 ? value : undefined);
  });

  await load();
}
