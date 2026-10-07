// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import type { AdminApi } from "../api.js";
import { describeError } from "../api.js";
import { clear, el, errorBanner } from "../dom.js";
import type { TokenStore } from "../tokenstore.js";

/** Staff sign-in (`POST /auth/login`, OBI-174). Shown whenever the
 * token store is empty. Stores the access token and the *username* (the
 * step-up modal needs the username; the token only carries the uid).
 * The refresh token itself is never stored here, or anywhere in JS
 * (OBI-198): it only ever travels as the `__Host-loom_rt` HttpOnly
 * cookie the server set on this response, which `AdminApi.refresh`
 * (OBI-297) rides on for silent re-auth before the 10-minute access
 * token expires. */
export function renderSignInPage(
  root: HTMLElement,
  api: AdminApi,
  tokens: TokenStore,
  onSignedIn: () => void,
): void {
  clear(root);
  root.append(el("h1", {}, ["Staff sign-in"]));

  const userInput = el("input", { type: "text", name: "username", autocomplete: "username" }) as HTMLInputElement;
  const passInput = el("input", {
    type: "password",
    name: "password",
    autocomplete: "current-password",
  }) as HTMLInputElement;
  const totpInput = el("input", {
    type: "text",
    name: "totp_code",
    inputmode: "numeric",
    autocomplete: "one-time-code",
    placeholder: "6-digit code (T3+)",
  }) as HTMLInputElement;
  const status = el("p", { class: "signin-status" }, []);

  const form = el("form", { class: "signin-form" }, [
    el("label", {}, ["Username", userInput]),
    el("label", {}, ["Password", passInput]),
    el("label", {}, ["Authenticator code", totpInput]),
    el("button", { type: "submit" }, ["Sign in"]),
    status,
  ]) as HTMLFormElement;

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    clear(status);
    const username = userInput.value.trim();
    void (async () => {
      try {
        const result = await api.login(username, passInput.value, totpInput.value.trim());
        tokens.set(result.access_token);
        tokens.setUsername(username);
        onSignedIn();
      } catch (err) {
        status.append(errorBanner(describeError(err)));
      }
    })();
  });

  root.append(form);
}
