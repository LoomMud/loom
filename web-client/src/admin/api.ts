// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A thin, auth-aware `fetch` wrapper for `/api/v1/admin/*` and the
 * `/auth/login` step-up round-trip (OBI-235, P2-O2). Kept deliberately
 * dumb: no caching, no retries, no reconnect logic -- every page module
 * under `pages/` calls one of these methods and renders whatever comes
 * back (or the error) through the DOM-safe helpers in `./dom.ts`, never
 * through a string-templated HTML sink (M-IDE-1/M-IDE-2).
 *
 * **Token storage is the caller's problem.** This module takes a
 * `getToken()`/`setToken()` pair rather than owning `localStorage`
 * itself, so step-up (re-`/auth/login` with a TOTP code, see
 * `./stepup.ts`) can swap in a freshly minted access token without this
 * module needing to know *how* the embedding page persists it.
 */

export interface AdminApiOptions {
  /** e.g. `""` for same-origin, or a full origin for local dev against a
   * driver on a different port. */
  baseUrl: string;
  getAccessToken: () => string | null;
  /** Called with the rotated access token after a successful silent
   * refresh (`./tokenstore.ts`'s `TokenStore.set`, OBI-297) -- this
   * module never persists a token itself, it only ever hands a fresh one
   * back to whatever store the embedding page uses. */
  setAccessToken: (token: string) => void;
}

/** `/auth/refresh` and `/auth/logout` both require this header (OBI-198,
 * M-AUTH-6) alongside an allow-listed `Origin` -- it forces a CORS
 * preflight, so a cross-origin page can never fire either route "for
 * free" the way a plain `<form>` POST or `<img>` tag can. */
const STAFF_AUTH_HEADER = "X-Loom-Auth";

/** `navigator.locks` (Web Locks API) resource name `refresh()` holds for
 * the duration of one round trip (CTO review on PR #121, OBI-297).
 * `__Host-loom_rt` is a cookie, so it is shared by every tab/window on
 * this origin -- two tabs duplicated from one another start with the
 * *same* access token and the *same* `exp`, so their proactive-refresh
 * timers (`app.ts`'s `scheduleProactiveRefresh`) fire in the same tick,
 * and both would otherwise present the same refresh cookie. The server
 * treats a second presentation of an already-rotated refresh token as
 * theft (`session_rotate`'s reuse-detection branch): it revokes the
 * *whole* session family and audits `auth.refresh.reuse`, signing every
 * tab out and logging a false theft event for what was just two tabs
 * racing. A Web Locks resource name is scoped per-origin (not
 * per-script, per-tab, or per-process), so it serializes the race across
 * tabs, not just within one -- the in-tab-only dedup below
 * (`refreshInFlight`) cannot do that by itself. */
const REFRESH_LOCK_NAME = "loom-admin-auth-refresh";

/** Minimal shape of the bits of the Web Locks API this module uses --
 * not every target runtime (Node under `node:test`, in particular) has a
 * `navigator.locks`, so this is typed narrowly rather than imported from
 * `lib.dom.d.ts` wholesale, and every call site feature-detects before
 * using it (`hasWebLocks` below). */
interface LocksLike {
  locks: {
    request<T>(name: string, callback: () => Promise<T>): Promise<T>;
  };
}

function hasWebLocks(): boolean {
  return (
    typeof navigator !== "undefined" &&
    (navigator as unknown as Partial<LocksLike>).locks !== undefined
  );
}

export class AdminApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: unknown,
  ) {
    super(`admin API error: HTTP ${status}`);
  }
}

/** Why a step-up-gated call couldn't even be attempted -- no token at
 * all, distinct from the server answering `403 step_up_required`
 * (`AdminApiError` with `status === 403`). */
export class NoAccessTokenError extends Error {
  constructor() {
    super("no access token available");
  }
}

export interface WhoEntry {
  conn_id: number;
  account: string | null;
  connected_at: string;
  idle_secs: number;
}

export interface ObjectSummary {
  path: string;
  euid: string;
}

export interface VarEntry {
  name: string;
  value: string;
}

export interface ObjectVars {
  path: string;
  vars: VarEntry[];
}

export interface ErrorGroup {
  program: string;
  function: string;
  line: number | null;
  message: string;
  redacted: boolean;
  count: number;
  first_seen_unix_ms: number;
  last_seen_unix_ms: number;
  sample_trace: string[];
}

export interface AuditEntry {
  id: number;
  at: string;
  kind: string;
  caller: string | null;
  effective_principal: string | null;
  apply: string | null;
  class: number | null;
  argument: string | null;
  guard_set: string[];
  verdict: string;
  detail: string | null;
}

export interface SetTierRequest {
  target_uid: string;
  new_tier: number;
  reason: string;
}

/** The documented request/response shape for OBI-233's broadcast
 * endpoint (not yet landed as of this module -- see the module doc's
 * "stub against the documented shape" escape hatch in OBI-235's issue
 * body). `POST /api/v1/admin/broadcast`, `204` on success, same
 * tier/step-up/audit shape as `roles/tier`. */
export interface BroadcastRequest {
  text: string;
}

/**
 * Minimal `/auth/login` response shape this module needs (full shape is
 * `loom-http::handlers::TokenResponse`, OBI-174/OBI-198) -- just enough
 * to read the fresh access token back out after a step-up re-auth. As of
 * OBI-198 (PR #77) the server no longer returns a refresh token in this
 * body at all -- it travels only as the `__Host-loom_rt` HttpOnly
 * cookie, so there is nothing here for this module (or any other JS) to
 * read or store. */
export interface LoginResponse {
  access_token: string;
  access_expires_at: number;
}

/** `/auth/refresh`'s response shape -- identical to `LoginResponse`, kept
 * as its own type so a caller reading `RefreshResponse` isn't implying
 * "this came from a sign-in". */
export type RefreshResponse = LoginResponse;

/** An authenticated round trip with the body already read as text (see
 * [`AdminApi.requestRaw`]). `headers` is kept because
 * `GET /api/v1/files/content`'s `ETag` is the caller's concurrency
 * precondition (M-FS-6), not something a parsed body can carry. */
export interface RawResponse {
  status: number;
  ok: boolean;
  headers: Headers;
  body: string;
}

export class AdminApi {
  constructor(private readonly options: AdminApiOptions) {}

  /**
   * The authenticated-fetch seam every non-admin HTTP client uses too:
   * the IDE's file client (`../ide/files-api.ts`, OBI-180) talks to
   * `/api/v1/files/*`, which shares this exact bearer + silent-refresh
   * contract (`bearer_uid` in `loom-http`'s `files.rs` accepts the same
   * access token `/api/v1/admin/*` does), and a second copy of that
   * logic would be a second place to get OBI-297's refresh handling
   * wrong. Returns the response rather than throwing on a non-2xx: a
   * file read's `404` and a write's `412` are results the caller acts
   * on, not errors to unwind to.
   *
   * Throws [`NoAccessTokenError`] when no token is stored, so callers
   * know to show sign-in instead of firing an unauthenticated request.
   */
  async requestRaw(path: string, init?: RequestInit): Promise<RawResponse> {
    const attempt = async (): Promise<Response> => {
      const token = this.options.getAccessToken();
      if (token === null) {
        throw new NoAccessTokenError();
      }
      return fetch(`${this.options.baseUrl}${path}`, {
        ...init,
        headers: {
          ...(init?.headers ?? {}),
          Authorization: `Bearer ${token}`,
        },
      });
    };
    let response = await attempt();
    // Silent refresh-on-401 (OBI-297): a token that was fine when the
    // page loaded can expire mid-session (access tokens are 10 min,
    // D-TM2). One retry only -- a second 401 after a successful refresh
    // means the *new* token was rejected too, which is a real auth
    // failure, not an expiry race, and should surface to the caller.
    if (response.status === 401 && (await this.refresh())) {
      response = await attempt();
    }
    const body = await response.text();
    return { status: response.status, ok: response.ok, headers: response.headers, body };
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await this.requestRaw(path, init);
    const body = response.body.length > 0 ? safeJsonParse(response.body) : null;
    if (!response.ok) {
      throw new AdminApiError(response.status, body);
    }
    return body as T;
  }

  /** In-tab single-flight: while one `refresh()` round trip is already
   * in progress, every other caller (a 401 retry, the proactive timer,
   * another page module) awaits the *same* promise instead of firing a
   * second `/auth/refresh`. This is the in-tab half of the fix; the
   * `navigator.locks` call inside `refresh()` is the cross-tab half --
   * see `REFRESH_LOCK_NAME`'s doc comment. `null` whenever no refresh is
   * outstanding. */
  private refreshInFlight: Promise<boolean> | null = null;

  /** Silent refresh via the `__Host-loom_rt` HttpOnly cookie (OBI-198,
   * OBI-297): `credentials: "same-origin"` is what makes the browser
   * attach that cookie, and `X-Loom-Auth: 1` plus an allow-listed
   * `Origin` is what the server demands before it will read it
   * (M-AUTH-6). This module never reads the cookie itself -- it isn't
   * `HttpOnly`-exempt JS, it just rides along on the request -- and the
   * response body never contains it either, only a rotated access
   * token. Never throws: any failure (network error, non-2xx, malformed
   * body) resolves to `false` so callers can treat "couldn't silently
   * refresh" uniformly with "not signed in" and fall back to sign-in.
   *
   * Single-flight both within a tab (`refreshInFlight`) and across tabs
   * (`navigator.locks.request(REFRESH_LOCK_NAME, ...)`, CTO review on PR
   * #121) -- see `REFRESH_LOCK_NAME`'s doc comment for why the
   * cross-tab case matters: two tabs with the same cookie racing to
   * refresh would otherwise trip the server's reuse-detection and
   * revoke the whole session family out from under every tab. */
  async refresh(): Promise<boolean> {
    if (this.refreshInFlight !== null) {
      return this.refreshInFlight;
    }
    const tokenBeforeRefresh = this.options.getAccessToken();

    const doRefresh = async (): Promise<boolean> => {
      try {
        const response = await fetch(`${this.options.baseUrl}/auth/refresh`, {
          method: "POST",
          credentials: "same-origin",
          headers: { [STAFF_AUTH_HEADER]: "1" },
        });
        if (!response.ok) {
          return false;
        }
        const text = await response.text();
        const body = text.length > 0 ? safeJsonParse(text) : null;
        const accessToken = (body as { access_token?: unknown } | null)?.access_token;
        if (typeof accessToken !== "string") {
          return false;
        }
        this.options.setAccessToken(accessToken);
        return true;
      } catch {
        return false;
      }
    };

    const withCrossTabLock = async (): Promise<boolean> => {
      if (!hasWebLocks()) {
        return doRefresh();
      }
      return (navigator as unknown as LocksLike).locks.request(REFRESH_LOCK_NAME, async () => {
        // Another tab may have already rotated the cookie (and this
        // tab's token, via the shared `TokenStore`) while this call
        // was queued for the lock -- in that case the round trip this
        // call was about to make would just be the reuse the server
        // rejects. A changed token means someone else already won;
        // nothing left for this call to do.
        if (this.options.getAccessToken() !== tokenBeforeRefresh) {
          return true;
        }
        return doRefresh();
      });
    };

    const inFlight = withCrossTabLock();
    this.refreshInFlight = inFlight;
    try {
      return await inFlight;
    } finally {
      if (this.refreshInFlight === inFlight) {
        this.refreshInFlight = null;
      }
    }
  }

  /** Sign-out: tells the server to revoke the session family behind the
   * `__Host-loom_rt` cookie and clear it (OBI-198's `logout` handler),
   * same `credentials`/header contract as `refresh`. Best-effort -- a
   * network failure here must not stop the caller from clearing its own
   * token store; an unreachable server can't keep a stale cookie
   * confidential, but failing to clear the *local* token store would
   * leave the UI looking signed in. */
  async logout(): Promise<void> {
    try {
      await fetch(`${this.options.baseUrl}/auth/logout`, {
        method: "POST",
        credentials: "same-origin",
        headers: { [STAFF_AUTH_HEADER]: "1" },
      });
    } catch {
      // Best-effort; see doc comment above.
    }
  }

  who(): Promise<WhoEntry[]> {
    return this.request("/api/v1/admin/who");
  }

  objects(): Promise<ObjectSummary[]> {
    return this.request("/api/v1/admin/objects");
  }

  objectVars(path: string): Promise<ObjectVars> {
    return this.request(objectVarsPath(path));
  }

  /** `program_prefix` matches the server's own optional query param
   * (`GET /api/v1/admin/errors?program_prefix=...`). */
  errors(programPrefix?: string): Promise<ErrorGroup[]> {
    const qs = programPrefix
      ? `?program_prefix=${encodeURIComponent(programPrefix)}`
      : "";
    return this.request(`/api/v1/admin/errors${qs}`);
  }

  auditRecent(beforeId?: number): Promise<AuditEntry[]> {
    const qs = beforeId !== undefined ? `?before_id=${beforeId}` : "";
    return this.request(`/api/v1/admin/audit${qs}`);
  }

  /** M-ADM-2: this (and `broadcast` below) must only ever be called
   * with a token whose `mfa_at` is fresh -- `./stepup.ts`'s
   * `ensureStepUp` is the gate every page calls first; this method
   * itself does not and cannot enforce that (it has no visibility into
   * token claims), it only forwards whatever token the caller gives it.
   * The real enforcement is server-side (`AuthService::admin_set_tier`'s
   * `mfa_at` check) -- this is UX, not the boundary. */
  setTier(req: SetTierRequest): Promise<void> {
    return this.request("/api/v1/admin/roles/tier", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(req),
    });
  }

  /** See `BroadcastRequest`'s doc: stubbed against OBI-233's documented
   * shape, lands for real once that endpoint merges. */
  broadcast(req: BroadcastRequest): Promise<void> {
    return this.request("/api/v1/admin/broadcast", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(req),
    });
  }

  /** Sign-in and the step-up round-trip: `/auth/login` with the staff
   * member's **username** (not the token's `sub`, which is the uid),
   * password + current TOTP code. A successful reply's
   * `access_token` carries a fresh `mfa_at` (OBI-174: TOTP-verified
   * login always sets it) -- `./stepup.ts` is what swaps it into
   * whatever token store the page uses. */
  async login(
    username: string,
    password: string,
    totpCode: string,
  ): Promise<LoginResponse> {
    const response = await fetch(`${this.options.baseUrl}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        username,
        password,
        totp_code: totpCode.length > 0 ? totpCode : null,
      }),
    });
    const text = await response.text();
    const body = text.length > 0 ? safeJsonParse(text) : null;
    if (!response.ok) {
      throw new AdminApiError(response.status, body);
    }
    return body as LoginResponse;
  }
}

/** Builds `/api/v1/admin/objects/<path>/vars` with each path segment
 * percent-encoded, so an object path containing `?`, `#`, `%` or a
 * `..` segment can't re-target the bearer-authenticated request at a
 * different admin route. */
export function objectVarsPath(path: string): string {
  const segments = path
    .split("/")
    .filter((s) => s.length > 0)
    .map((s) => (s === "." || s === ".." ? encodeURIComponent(s).replace(/\./g, "%2E") : encodeURIComponent(s)));
  return `/api/v1/admin/objects/${segments.join("/")}/vars`;
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

/** A short, display-safe string for any error this module can throw --
 * used by every page module so a failed call renders as plain text
 * (`./dom.ts`'s `errorBanner`) instead of leaking a raw object into the
 * DOM via `String(err)`'s default `[object Object]` or similar. */
export function describeError(err: unknown): string {
  if (err instanceof NoAccessTokenError) {
    return "not signed in";
  }
  if (err instanceof AdminApiError) {
    if (err.status === 401) {
      return "session expired -- please sign in again";
    }
    if (err.status === 403) {
      const body = err.body as { error?: string } | null;
      if (body?.error === "step_up_required") {
        return "step-up re-authentication required";
      }
      return "forbidden";
    }
    if (err.status === 503) {
      return "service unavailable";
    }
    return `request failed (HTTP ${err.status})`;
  }
  if (err instanceof Error) {
    return err.message;
  }
  return "unknown error";
}
