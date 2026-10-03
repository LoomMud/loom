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
 * `loom-http::handlers::TokenPair`, OBI-174) -- just enough to read the
 * fresh access token back out after a step-up re-auth.
 */
export interface LoginResponse {
  access_token: string;
  refresh_token: string;
}

export class AdminApi {
  constructor(private readonly options: AdminApiOptions) {}

  private async request<T>(
    path: string,
    init?: RequestInit,
  ): Promise<T> {
    const token = this.options.getAccessToken();
    if (token === null) {
      throw new NoAccessTokenError();
    }
    const response = await fetch(`${this.options.baseUrl}${path}`, {
      ...init,
      headers: {
        ...(init?.headers ?? {}),
        Authorization: `Bearer ${token}`,
      },
    });
    const text = await response.text();
    const body = text.length > 0 ? safeJsonParse(text) : null;
    if (!response.ok) {
      throw new AdminApiError(response.status, body);
    }
    return body as T;
  }

  who(): Promise<WhoEntry[]> {
    return this.request("/api/v1/admin/who");
  }

  objects(): Promise<ObjectSummary[]> {
    return this.request("/api/v1/admin/objects");
  }

  objectVars(path: string): Promise<ObjectVars> {
    const trimmed = path.startsWith("/") ? path.slice(1) : path;
    return this.request(`/api/v1/admin/objects/${trimmed}/vars`);
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

  /** The step-up round-trip itself: re-`/auth/login` with the staff
   * member's password + current TOTP code. A successful reply's
   * `access_token` carries a fresh `mfa_at` (OBI-174: TOTP-verified
   * login always sets it) -- `./stepup.ts` is what swaps it into
   * whatever token store the page uses. */
  async reauth(
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
        totp_code: totpCode,
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
