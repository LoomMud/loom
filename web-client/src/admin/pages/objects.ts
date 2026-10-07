// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import type { AdminApi } from "../api.js";
import { describeError } from "../api.js";
import { clear, el, errorBanner } from "../dom.js";

/** `GET /api/v1/admin/objects` + `GET /api/v1/admin/objects/:path/vars`
 * (OBI-234): the object list is already `valid_read`-filtered on the
 * world side -- this page never re-filters or widens it. Clicking a row
 * loads that object's variables inline below the table. */
export async function renderObjectsPage(root: HTMLElement, api: AdminApi): Promise<void> {
  clear(root);
  root.append(el("h1", {}, ["Objects"]));
  const body = el("div", {}, ["Loading…"]);
  const varsPane = el("div", { class: "object-vars" }, []);
  root.append(body, varsPane);
  try {
    const rows = await api.objects();
    clear(body);
    if (rows.length === 0) {
      body.append(el("p", {}, ["no readable objects"]));
      return;
    }
    const tbody = el(
      "tbody",
      {},
      rows.map((row) => {
        const link = el("button", { type: "button", class: "object-link" }, [row.path]);
        link.addEventListener("click", () => void loadVars(varsPane, api, row.path));
        return el("tr", {}, [el("td", {}, [link]), el("td", {}, [row.euid])]);
      }),
    );
    const thead = el("tr", {}, [el("th", {}, ["Path"]), el("th", {}, ["euid"])]);
    body.append(el("table", {}, [el("thead", {}, [thead]), tbody]));
  } catch (err) {
    clear(body);
    body.append(errorBanner(describeError(err)));
  }
}

async function loadVars(varsPane: HTMLElement, api: AdminApi, path: string): Promise<void> {
  clear(varsPane);
  varsPane.append(el("h2", {}, [path]), el("p", {}, ["Loading variables…"]));
  try {
    const vars = await api.objectVars(path);
    clear(varsPane);
    const tbody = el(
      "tbody",
      {},
      vars.vars.map((v) => el("tr", {}, [el("td", {}, [v.name]), el("td", {}, [v.value])])),
    );
    const thead = el("tr", {}, [el("th", {}, ["Name"]), el("th", {}, ["Value"])]);
    const tableEl =
      vars.vars.length === 0
        ? el("p", {}, ["no variables"])
        : el("table", {}, [el("thead", {}, [thead]), tbody]);
    varsPane.append(el("h2", {}, [vars.path]), tableEl);
  } catch (err) {
    clear(varsPane);
    varsPane.append(el("h2", {}, [path]), errorBanner(describeError(err)));
  }
}
