// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import type { AdminApi } from "../api.js";
import { describeError } from "../api.js";
import { clear, el, errorBanner } from "../dom.js";
import { ensureStepUp } from "../stepup-modal.js";
import type { TokenStore } from "../tokenstore.js";

/** `POST /api/v1/admin/roles/tier` (M-ADM-1/M-ADM-2): a role/tier change
 * is step-up-gated client-side (`ensureStepUp`, mirroring the server's
 * `mfa_at` check, M-ADM-2) before the request is ever sent. There is no
 * `actor` field in the form -- the server always takes the actor from
 * the bearer token's own `sub` (M-ADM-1); nothing here could override
 * that even by accident. */
export function renderRolesPage(
  root: HTMLElement,
  api: AdminApi,
  tokens: TokenStore,
  modalRoot: HTMLElement,
): void {
  clear(root);
  root.append(el("h1", {}, ["Role management"]));

  const targetInput = el("input", { type: "text", placeholder: "target uid" }) as HTMLInputElement;
  const tierInput = el("input", { type: "number", min: "1", max: "5" }) as HTMLInputElement;
  const reasonInput = el("input", { type: "text", placeholder: "reason (required)" }) as HTMLInputElement;
  const submit = el("button", { type: "submit" }, ["Apply"]);
  const status = el("p", { class: "roles-status" }, []);

  const form = el(
    "form",
    {},
    [
      el("label", {}, ["Target uid", targetInput]),
      el("label", {}, ["New tier", tierInput]),
      el("label", {}, ["Reason", reasonInput]),
      submit,
      status,
    ],
  ) as HTMLFormElement;

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    clear(status);
    void (async () => {
      // M-ADM-2: step-up first -- the actual request only fires once
      // the user has either confirmed a fresh re-auth or already had
      // one. A cancelled step-up aborts the submission entirely.
      const steppedUp = await ensureStepUp(modalRoot, api, tokens);
      if (!steppedUp) {
        status.append(errorBanner("step-up cancelled -- change not applied"));
        return;
      }
      try {
        await api.setTier({
          target_uid: targetInput.value,
          new_tier: Number(tierInput.value),
          reason: reasonInput.value,
        });
        clear(status);
        status.append(el("span", { class: "roles-success" }, ["tier updated"]));
      } catch (err) {
        clear(status);
        status.append(errorBanner(describeError(err)));
      }
    })();
  });

  root.append(form);
}
