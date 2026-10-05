// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import type { AdminApi } from "../api.js";
import { describeError } from "../api.js";
import { clear, el, errorBanner } from "../dom.js";
import { ensureStepUp } from "../stepup-modal.js";
import type { TokenStore } from "../tokenstore.js";

/** `POST /api/v1/admin/broadcast` (OBI-233, stubbed against the
 * documented request/response shape -- see `api.ts`'s `BroadcastRequest`
 * doc comment: this page works unchanged once that endpoint lands, and
 * fails with a plain `describeError` banner -- most likely `404` today
 * -- until it does). Step-up-gated the same way role changes are
 * (M-ADM-2): a broadcast only ever goes out world-wide, so it gets the
 * same re-auth prompt. */
export function renderBroadcastPage(
  root: HTMLElement,
  api: AdminApi,
  tokens: TokenStore,
  modalRoot: HTMLElement,
): void {
  clear(root);
  root.append(el("h1", {}, ["Broadcast"]));

  const textInput = el("textarea", { rows: "4", placeholder: "message to every connected player" }) as HTMLTextAreaElement;
  const submit = el("button", { type: "submit" }, ["Send"]);
  const status = el("p", { class: "broadcast-status" }, []);

  const form = el(
    "form",
    {},
    [el("label", {}, ["Message", textInput]), submit, status],
  ) as HTMLFormElement;

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    clear(status);
    void (async () => {
      const steppedUp = await ensureStepUp(modalRoot, api, tokens);
      if (!steppedUp) {
        status.append(errorBanner("step-up cancelled -- broadcast not sent"));
        return;
      }
      try {
        await api.broadcast({ text: textInput.value });
        clear(status);
        status.append(el("span", { class: "broadcast-success" }, ["broadcast sent"]));
        textInput.value = "";
      } catch (err) {
        clear(status);
        status.append(errorBanner(describeError(err)));
      }
    })();
  });

  root.append(form);
}
