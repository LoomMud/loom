// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * M-ADM-2 (client side): before submitting a role change, a grant,
 * another user's TOTP reset, or a broadcast, the UI must itself demand
 * re-authentication if the current access token's `mfa_at` isn't fresh
 * -- *mirroring* `AuthService::has_fresh_step_up`'s server-side check
 * (`loom-http/src/auth/mod.rs`, `STEP_UP_WINDOW_SECS` = 5 minutes), not
 * replacing it. The server always re-checks `mfa_at` itself
 * (`AdminError::StepUpRequired` is a real, independent `403`); this
 * module exists purely so staff aren't surprised by that `403` after
 * filling in a whole form -- a UX nicety, never the security boundary.
 *
 * **Decoding, not verifying.** This module reads the access token's
 * claims by base64url-decoding its payload segment -- it never checks
 * the signature (it has no key to check it with, and doesn't need one:
 * a forged token would simply fail against the real check server-side).
 * Treat anything read here as "what the UI believes", never as proof of
 * anything.
 */

/** Mirrors `loom-http`'s `STEP_UP_WINDOW_SECS` (`auth/mod.rs`). Kept as
 * a separate constant here (not imported -- there is no shared package
 * between the Rust driver and this TypeScript client) so a future change
 * to the server's window is a conscious, grep-able two-place edit, not a
 * silent client/server drift. */
export const STEP_UP_WINDOW_SECS = 5 * 60;

export interface AccessTokenClaims {
  sub: string;
  tier: number;
  mfa_at: number | null;
  exp: number;
  [key: string]: unknown;
}

/** Decodes a JWT's claims (middle segment) without any signature check.
 * Returns `null` for anything that doesn't parse as `header.payload.sig`
 * with a JSON payload -- callers must treat that as "assume stale /
 * assume no step-up", never as "assume fresh". */
export function decodeAccessToken(token: string): AccessTokenClaims | null {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[1] === undefined) {
    return null;
  }
  try {
    const payload = parts[1]
      .replace(/-/g, "+")
      .replace(/_/g, "/");
    const padded = payload + "=".repeat((4 - (payload.length % 4)) % 4);
    const json = atob(padded);
    const claims = JSON.parse(json);
    if (
      typeof claims !== "object" ||
      claims === null ||
      typeof claims.sub !== "string" ||
      typeof claims.tier !== "number"
    ) {
      return null;
    }
    return claims as AccessTokenClaims;
  } catch {
    return null;
  }
}

/** `true` only if `token` decodes and its `mfa_at` is within
 * `STEP_UP_WINDOW_SECS` of `nowUnixSecs` (defaults to `Date.now()`).
 * Anything that fails to decode, or has no `mfa_at` at all, is **not**
 * fresh -- never fail open. */
export function isStepUpFresh(
  token: string | null,
  nowUnixSecs: number = Math.floor(Date.now() / 1000),
): boolean {
  if (token === null) {
    return false;
  }
  const claims = decodeAccessToken(token);
  if (claims === null || claims.mfa_at === null || claims.mfa_at === undefined) {
    return false;
  }
  return nowUnixSecs - claims.mfa_at <= STEP_UP_WINDOW_SECS;
}
