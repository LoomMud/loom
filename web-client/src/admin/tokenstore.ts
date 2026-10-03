// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The access-token store every admin page reads/writes through -- kept
 * as one small seam (not each page touching storage directly) so
 * step-up (`./stepup.ts` + `ensureStepUp`) has exactly one place to swap
 * in a freshly minted token after a successful re-auth.
 *
 * Also remembers the *username* the session signed in with: the access
 * token's `sub` is the staff **uid**, while `/auth/login` resolves by
 * **username** (`staff_uid_for_username`), so step-up cannot re-derive
 * the login name from the token.
 *
 * Backed by `sessionStorage` (not `localStorage`) in `admin.html`: an
 * admin bearer token should not outlive the tab it was minted in.
 */
export interface TokenStore {
  get(): string | null;
  set(token: string): void;
  username(): string | null;
  setUsername(username: string): void;
  clear(): void;
}

const TOKEN_KEY = "loom_admin_access_token";
const USERNAME_KEY = "loom_admin_username";

export function storageTokenStore(storage: Storage): TokenStore {
  return {
    get: () => storage.getItem(TOKEN_KEY),
    set: (token: string) => storage.setItem(TOKEN_KEY, token),
    username: () => storage.getItem(USERNAME_KEY),
    setUsername: (username: string) => storage.setItem(USERNAME_KEY, username),
    clear: () => {
      storage.removeItem(TOKEN_KEY);
      storage.removeItem(USERNAME_KEY);
    },
  };
}
