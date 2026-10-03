// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The access-token store every admin page reads/writes through -- kept
 * as one small seam (not each page touching `localStorage` directly) so
 * step-up (`./stepup.ts` + `ensureStepUp` below) has exactly one place
 * to swap in a freshly minted token after a successful re-auth.
 */
export interface TokenStore {
  get(): string | null;
  set(token: string): void;
}

const STORAGE_KEY = "loom_admin_access_token";

export function localStorageTokenStore(storage: Storage): TokenStore {
  return {
    get: () => storage.getItem(STORAGE_KEY),
    set: (token: string) => storage.setItem(STORAGE_KEY, token),
  };
}
