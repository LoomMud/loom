// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import { AdminApi, describeError } from "./api.js";
import { el, clear, errorBanner } from "./dom.js";
import { decodeAccessToken, isStepUpFresh } from "./stepup.js";
import type { TokenStore } from "./tokenstore.js";

/**
 * M-ADM-2, UI half: `ensureStepUp` is the one function every
 * step-up-gated action (role/tier change, a grant, another user's TOTP
 * reset, broadcast) calls *before* making its real request. If the
 * current token is already fresh (`isStepUpFresh`), it resolves
 * immediately without showing anything -- the modal only ever appears
 * when a re-auth is actually needed, never as a blanket "enter your
 * password every time" nag.
 *
 * This is UX, not the security boundary: the server re-checks `mfa_at`
 * itself on every gated endpoint regardless of what this function
 * decided, so a bug here can make the UI annoying but never bypasses
 * the real check.
 */
export async function ensureStepUp(
  modalRoot: HTMLElement,
  api: AdminApi,
  tokens: TokenStore,
): Promise<boolean> {
  if (isStepUpFresh(tokens.get())) {
    return true;
  }
  return showStepUpModal(modalRoot, api, tokens);
}

function showStepUpModal(
  modalRoot: HTMLElement,
  api: AdminApi,
  tokens: TokenStore,
): Promise<boolean> {
  return new Promise((resolve) => {
    const claims = decodeAccessToken(tokens.get() ?? "");
    const username = claims?.sub ?? "";

    const passwordInput = el("input", {
      type: "password",
      name: "password",
      autocomplete: "current-password",
    }) as HTMLInputElement;
    const totpInput = el("input", {
      type: "text",
      name: "totp_code",
      inputmode: "numeric",
      autocomplete: "one-time-code",
      placeholder: "6-digit code",
    }) as HTMLInputElement;
    const status = el("p", { class: "step-up-status" }, []);

    const finish = (ok: boolean) => {
      clear(modalRoot);
      modalRoot.classList.remove("open");
      resolve(ok);
    };

    const submit = el("button", { type: "submit" }, ["Confirm"]);
    const cancel = el("button", { type: "button" }, ["Cancel"]);
    cancel.addEventListener("click", () => finish(false));

    const form = el(
      "form",
      { class: "step-up-form" },
      [
        el("h2", {}, ["Re-authenticate to continue"]),
        el("p", {}, [`Confirm it's you, ${username}, before this action is applied.`]),
        el("label", {}, ["Password", passwordInput]),
        el("label", {}, ["Authenticator code", totpInput]),
        status,
        el("div", { class: "step-up-actions" }, [submit, cancel]),
      ],
    ) as HTMLFormElement;

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      clear(status);
      void (async () => {
        try {
          const result = await api.reauth(username, passwordInput.value, totpInput.value);
          tokens.set(result.access_token);
          finish(true);
        } catch (err) {
          status.append(errorBanner(describeError(err)));
        }
      })();
    });

    clear(modalRoot);
    modalRoot.classList.add("open");
    modalRoot.append(form);
  });
}
