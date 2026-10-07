# Phase 2 threat model: web-facing surfaces (P2-S1)

Status: **r1, normative for Phase 2.** Owner: Aragorn (CTO). Issue: [OBI-179](https://paperclip.home.oberfield.net/OBI/issues/OBI-179). Tracker: [OBI-165](https://paperclip.home.oberfield.net/OBI/issues/OBI-165).
Covers: the files API, the web IDE, LSP over WebSocket, `propose` / GitHub App / merge webhook, staff auth (JWT + TOTP + GitHub login), and the admin UI.
Spec references are to spec v2 r5 (§5.7, §5.11, §8.2–§8.5, §9.7–§9.8). Code references are to `LoomMud/loom@24ebbe4`.

Every mitigation has an ID (`M-…`) and an owning issue. **The owning issue's acceptance criteria quote the IDs**, and its PR is not mergeable until the CTO has checked each one (§9).

---

## 1. Scope and method

- **In scope:** everything a browser or GitHub can reach on the HTTP port (`loom:8080` behind Caddy and Cloudflare), plus everything those requests make the driver do: reading and writing the VFS, compiling, git, calling the GitHub API, and running role-change SQL.
- **Out of scope:** telnet (already threat-modelled in Phase 1, R6), copyover/supervisor (P2-O1, no network surface beyond the existing listeners), and Flux/K8s (K1). The Weft sandbox and tier model are taken as given (`docs/security.md`, E1.3 tier suite). This model makes sure the new surfaces **route through** them and never around them.
- **Method:** STRIDE per surface. For each threat, the table gives likelihood × impact as H/M/L and the mitigation IDs. Residual risk is in §8.

## 2. Assets

| # | Asset | Why it matters | Where it lives |
|---|---|---|---|
| A1 | **Integrity of mudlib code that runs live** (`warp` `main`, the pod's `live` branch and working tree) | Whoever writes live code runs code in the world as that program's uid, up to `root` for `/secure` | Pod VFS working tree; GitHub `LoomMud/warp` |
| A2 | **Tier/roles data** (`staff`, `domain_members`, `tier_policy`, `grants`, `role_changes`) | It decides every `valid_*` answer | Postgres, written only through `security definer` functions |
| A3 | **Staff credentials and sessions**: password hashes, TOTP secrets, recovery codes, refresh tokens, JWT signing key, GitHub account links | Taking over a T3+ session gives live writes to `domain_live`, and a T4/T5 session gives role changes | Postgres + a secret file on the host |
| A4 | **GitHub App private key, installation tokens, webhook secret, OAuth client secret** | Can push branches and open PRs on `warp`. If the same App is the reviewer App, it can also approve PRs on `loom`/`loom-gitops` (§6.4) | Secret file on the host; tokens in memory |
| A5 | **Confidentiality of source by tier** (§5.11.2 Read row: T1–T3 cannot read `/secure`, T1 cannot read other workrooms or non-member domains) | `/secure` holds the named SQL and the login/roles logic. An unreleased domain is content the game hasn't published | VFS |
| A6 | **Player personal data** (emails, IPs, chat/command logs, object state) | GDPR (Q11) | Postgres, `object_state`, the error inbox, audit samples |
| A7 | **Audit log integrity** | It is the only after-the-fact evidence | Postgres `audit_log` |
| A8 | **Availability of the world thread** | One thread serves all 150 players (E1.1) | `loom` process |
| A9 | **Host/container**: files outside the VFS root, env vars, `DATABASE_URL` | Escaping the VFS is escaping the sandbox | `loom` container |

## 3. Actors

| Actor | Has | Wants |
|---|---|---|
| Anonymous internet user | Reaches `loommud.com` through Cloudflare | Staff login, account takeover, DoS |
| Player (tier 0) | A game account and the ability to put text into the world (names, says, mail, bug reports) | Get text rendered as **HTML** in a staff browser (stored XSS), escalate |
| Malicious or compromised **T1/T2 builder** | A valid staff session; can write Weft in their workroom/wip; can `propose` | Read `/secure` or others' work, write outside their path class, get code onto `main` without review, run code in warp CI with secrets |
| Malicious T3/T4 | Wider rights | Self-promotion, bypassing the two-root rule, erasing audit trails |
| Compromised staff browser or stolen token | Whatever the session allows | Keep access going (long-lived refresh tokens) |
| GitHub-side attacker | Can send HTTP to the webhook URL; may control a GitHub account | Forge merges, make the driver pull unreviewed code |
| Supply chain | npm (Monaco, Vite), crates | Code in the staff origin or the driver |

## 4. Architecture and trust boundaries

```
 browser (player client)  ─┐                                   ┌─ GitHub (webhooks in, API out)
 browser (IDE / admin)    ─┤ TB1  Cloudflare → Caddy (TLS) ──→ loom:8080 (axum, tokio)
                           │                                        │ TB2 bounded channel, per-request budget
                           │                                        ▼
                           │                                  world thread: master valid_* under the staff euid
                           │                                        │ TB3 loom_app → security definer fns
                           │                                        ▼
                           │                                  Postgres            TB4 git / GitHub App token
 TB5 = the browser itself: everything the IDE/admin renders that came from the world, the VFS, or GitHub
```

- **TB1 Internet → loom.** Cloudflare (proxy) → Caddy (TLS, `trusted_proxies` = Cloudflare ranges) → `loom:8080`. Port 8080 is compose-internal only (`loom-gitops/staging/compose.yaml`). **Today one origin (`loommud.com`) serves the player client, `/ws`, and everything else** (`loom-http` fallback, OBI-158).
- **TB2 HTTP task → world thread.** A tokio handler has no authority of its own. Any decision about the VFS, compiling, or roles has to become an execution on the world thread whose guard set is the authenticated staff member's euid. This boundary is what keeps the existing tier model in force.
- **TB3 loom → Postgres.** `loom_app` has no DML on the roles tables (`docs/persistence.md`). That stays true for the admin UI.
- **TB4 loom ↔ GitHub.** The driver holds the App key and can mint tokens. Webhook payloads come in from the internet.
- **TB5 data → staff DOM.** File contents, file names, diagnostics, hover markdown, error messages, who-list names, audit rows, and PR titles are all attacker-influenced strings that end up in a page holding a staff access token.

## 5. Cross-cutting decisions

| # | Decision | Rejected alternative and why |
|---|---|---|
| D-TM1 | **Staff surfaces get their own origin**: `build.loommud.com` (IDE, admin UI, `/api/v1/*` staff routes, `/lsp`). The player client, `/ws`, and the future mudlib-defined `/api/game/*` stay on `loommud.com`. `loom-http` routes by `Host`: staff routes return `404` on the player host and the reverse. | *One origin with path separation.* Same-origin policy doesn't stop at paths. `/api/game/*` responses are **written by mudlib code** (§8.4), and any HTML they or the player client ever produce would run with access to the staff token. A second hostname costs one DNS record and one Caddy site block. **Needs a DNS record from the board (Q-TM1).** Until it exists, staging runs staff routes on the single origin, which is acceptable only while `/api/game/*` doesn't exist and staging is staff-only (Q-P2.4). |
| D-TM2 | **Tokens:** access JWT valid for **10 min**, kept **in JS memory only** and sent as `Authorization: Bearer`. Refresh token is opaque, random 256-bit, stored **hashed** in Postgres, delivered as a `__Host-loom_rt` cookie (`HttpOnly; Secure; SameSite=Strict; Path=/`). It is **rotated on every use**, and reuse of an old one revokes the whole token family. | *Tokens in `localStorage`*: one XSS steals a long-lived credential. *Cookie session for the whole API*: every mutating route becomes a CSRF target. With Bearer auth, only `refresh` and `logout` see the cookie, and both also require Origin + a custom header (M-AUTH-6). |
| D-TM3 | **The JWT is identity, not authority.** Claims: `sub` = staff uid, `sid` = token family, `amr`, `mfa_at`, `scope` (coarse, derived from tier at issue). **Every request re-reads the tier from the live `RolesSnapshot`**, and VFS decisions go through master `valid_*` with the uid as euid. A demotion therefore takes effect on the next request, not at token expiry. | *Trusting tier/scope claims for 10 min*: a demoted or removed staff member would keep their rights until expiry. The snapshot is already in memory, so the lookup costs nothing. |
| D-TM4 | **WebSocket auth (LSP, and any future staff WS) uses a single-use ticket sent in the first frame.** `POST /api/v1/ws-ticket` (Bearer) returns a 32-byte ticket valid for 30 s and bound to `sub`+`sid`. The client opens the WS, which is Origin-checked, and must send `{"auth":ticket}` within 5 s or be closed. | *Ticket in the query string*: Caddy's JSON access log and Cloudflare record the URI. *Cookie auth on the WS*: cross-site WebSocket hijacking, with Origin as the only defence. *Bearer header*: browsers can't set it on a WS. |
| D-TM5 | **HTTP handlers never touch the filesystem or the DB roles tables directly.** Files go through the VFS functions that `read_file`/`write_file` use (`fileio`) after a world-thread `valid_*` decision. Role changes go through the existing `roles_*` `security definer` functions with the actor set by the driver. | *An HTTP-side ACL "mirroring" the master*: two policies drift apart, and the master is the policy (§5.11.4). |
| D-TM6 | **`propose` uses its own GitHub App (`loom-propose`), installed on `warp` only**, with `contents:write` + `pull_requests:write` + `metadata:read`. It is **not** the OBI-43 reviewer App. | *Extending the OBI-43 reviewer App (the Q-P2.3 working assumption)*: its key would then sit on the internet-facing staging host, and a host compromise could **approve and merge PRs on `loom`/`loom-gitops`** — a supply-chain path into the driver and the deploy repo. GitHub App permissions can't be split per repo inside one App, and "`propose/*` only" can't be expressed as an App permission at all (see M-GH-2). **Changes the Q-P2.3 working assumption → Q-TM2.** |

## 6. Threats and mitigations per surface

### 6.1 Staff auth: JWT + TOTP + GitHub login (P2-O3, [OBI-174](https://paperclip.home.oberfield.net/OBI/issues/OBI-174))

| # | STRIDE | Threat | L×I | Mitigations |
|---|---|---|---|---|
| T-AUTH-1 | S | Password brute force or credential stuffing against staff accounts | H×H | M-AUTH-1, M-AUTH-2 |
| T-AUTH-2 | S | T3+ signs in with a password alone (TOTP not enforced on some path: GitHub login, refresh, a forgotten route) | M×H | M-AUTH-3 |
| T-AUTH-3 | E | Client-supplied or IdP-supplied tier/scope (forged JWT claims, `alg=none`/HS-RS confusion, GitHub org/team claims) | M×H | M-AUTH-4, D-TM3 |
| T-AUTH-4 | S | Stolen refresh token keeps access going; demotion or removal doesn't end sessions | M×H | D-TM2, M-AUTH-5 |
| T-AUTH-5 | T | CSRF on cookie-bearing endpoints (refresh, logout, OAuth callback) | M×M | M-AUTH-6 |
| T-AUTH-6 | S | GitHub login: account linked by matching login/email, a renamed or recycled GitHub login, auto-provisioning a `staff` row, a missing `state`, or a code interception | M×H | M-AUTH-7 |
| T-AUTH-7 | S | TOTP replay, brute force (10⁶ space), or theft of the TOTP secret at rest | M×H | M-AUTH-8 |
| T-AUTH-8 | I | Secrets in logs (passwords, TOTP codes, tokens, OAuth codes, `Authorization` headers) | M×H | M-X-4 |
| T-AUTH-9 | R | No record of who logged in from where, or of failed attempts | M×M | M-AUTH-9 |

- **M-AUTH-1** Rate limit login: per account (5 failures / 15 min → 15 min lockout, with the same response as a wrong password, and audited) and per client IP (token bucket). The client IP comes from `X-Forwarded-For` **only because port 8080 is reachable from Caddy alone**. Document that invariant next to the code that reads XFF.
- **M-AUTH-2** Use the driver's existing Argon2id (`auth_verify`) for staff passwords. No second hash implementation. Verify in constant time, and run a dummy hash for unknown users so timing doesn't reveal which usernames exist.
- **M-AUTH-3** **TOTP is enforced at token issue, for every login method, when `staff.tier >= 3` or `totp_required`.** The refresh path re-checks this: a T2 promoted to T3 without enrolled TOTP gets no new access token. It is sent to TOTP enrolment instead. Record `amr` and `mfa_at`. Step-up auth (`mfa_at` ≤ 5 min old) is required for role changes, TOTP reset, and GitHub link/unlink (M-ADM-2).
- **M-AUTH-4** Sign JWTs with **EdDSA (Ed25519)**, from a key file mounted as a secret, with a `kid` so keys can be rotated. Verification **pins the algorithm** and checks `iss`, `aud` (`loom-staff-access`; tickets and refresh use other values or aren't JWTs at all), `exp`, and `nbf` (≤ 30 s skew). Tier and scope come from Postgres at issue/refresh and from the snapshot per request (D-TM3), **never** from GitHub claims or the request body.
- **M-AUTH-5** Refresh tokens: hashed (SHA-256) in a `staff_sessions` table owned by `loom_owner`, with family id, `expires_at` (14 days absolute, 24 h idle), and `revoked_at`. **Revoke all families for a uid** on password change, TOTP reset, GitHub unlink, a tier change, or removal of the staff row. Implement this as a trigger, or inside the `security definer` functions, so no code path can forget it. Logout revokes the family.
- **M-AUTH-6** Endpoints that read the cookie (`/api/v1/auth/refresh`, `/logout`) require `Origin` ∈ the staff-origin allowlist **and** an `X-Loom-Auth: 1` header (which forces a CORS preflight). **No CORS** for any other origin (no `Access-Control-Allow-Origin` at all). Every other mutating route is Bearer-only. The allowlist is `LOOM_STAFF_ORIGINS` (`secrets.env.example`) -- unset by default, which refuses both routes outright, so every deploy serving the admin web client (OBI-185/OBI-297) **must** list that client's exact origin here or staff silent-refresh and sign-out both fail closed.
- **M-AUTH-7** GitHub login: OAuth2 authorization-code flow with **PKCE (S256)** and a `state` bound to a short-lived `__Host-` cookie. The redirect URI is exact. The identity key is the **numeric GitHub user id** (never the login or email). Linking happens **only** from an already-authenticated session with step-up MFA, through a `security definer` function `staff_link_github(actor, uid, github_id)`. An unlinked GitHub id is **refused** and never provisioned. GitHub login counts as the password factor only, so M-AUTH-3 still applies. Note that GitHub user sign-in is OAuth2, not OIDC (no `id_token`), so the "OIDC" label in the plan means "GitHub SSO". If a real OIDC IdP is added later, it must validate `id_token` signature, `iss`, `aud`, and `nonce`.
- **M-AUTH-8** TOTP (RFC 6238, SHA-1, 6 digits, 30 s, ±1 step). Remember the last accepted step per uid so codes can't be replayed. Same rate limit as M-AUTH-1. Store the secret **encrypted** (XChaCha20-Poly1305 or AES-GCM) under a key from the secret file, not in plaintext in Postgres. Enrolment requires the password again plus one valid code before activation. Issue 10 single-use recovery codes, stored hashed.
- **M-AUTH-9** Audit `auth.login.ok|fail`, `auth.refresh.reuse`, `auth.totp.enrol|reset`, and `auth.github.link|unlink` with uid, IP, and user-agent to `audit_log`.

Tests required (in addition to OBI-174's own list): `alg` confusion and `none` are rejected. A tier claim edited in the token has no effect. Refresh reuse revokes the family. A demotion ends the next request's privileges. GitHub login of a T3 without TOTP is refused. `state` mismatch is refused. A linked id with a changed login still works, and a login matching a staff username but with an unlinked id is refused.

### 6.2 Files API `GET/PUT /api/v1/files/*` (P2-B2, [OBI-180](https://paperclip.home.oberfield.net/OBI/issues/OBI-180))

| # | STRIDE | Threat | L×I | Mitigations |
|---|---|---|---|---|
| T-FS-1 | E | Write outside the caller's path class (HTTP handler checks its own ACL, runs as `root`/`mudlib`, or skips `valid_write`) | M×H | M-FS-1 |
| T-FS-2 | E/I | Path traversal: `..`, `%2e%2e`, double-encoding, `\`, NUL, absolute paths, Unicode look-alikes, **symlinks** in the working tree leading outside the VFS root, `/data/**` | M×H | M-FS-2 |
| T-FS-3 | I | Read source the tier can't read (`/secure`, other workrooms, non-member domains) — through GET **or through the directory listing**, ETags, error messages, or size metadata | M×M | M-FS-1, M-FS-3 |
| T-FS-4 | E | **Stored XSS on the staff origin**: a T1 saves `x.html` or `x.svg` in their workroom; a T4 opens the API URL and the browser renders it | M×H | M-FS-4 |
| T-FS-5 | D | Huge bodies, thousands of saves per second, or compile storms that starve the world thread | M×M | M-FS-5, M-X-2 |
| T-FS-6 | T | Lost update (two editors), or a silent overwrite of a file changed since it was loaded | M×L | M-FS-6 |
| T-FS-7 | R | A write with no attributable author | L×M | M-FS-7 |

- **M-FS-1** Every file operation is a **world-thread execution started by the request** (a cut, like player input), with guard set `{staff uid}` and the tier's tick budget. It calls the same paths as `read_file`/`write_file`/`compile_object`, so `valid_read`/`valid_write`/`valid_compile`, quotas (`disk_quota_mb`), and audit all apply unchanged. A staff uid that `is_reserved_principal` is refused. **Test:** E1.3-style cases run over HTTP — T1 in own workroom OK, T1 elsewhere 403, T2 `domain_wip` of a member domain OK, T2 `domain_live` 403, any tier on `/secure` or `/std` 403 (review only), `/data` 403.
- **M-FS-2** Normalise the path once, in the shared VFS resolver: percent-decode exactly once; reject NUL, `\`, any `.` or `..` segment, empty segments, and non-UTF-8; require NFC. Resolve under the VFS root. Open with `O_NOFOLLOW` on every component (or canonicalise and check the prefix **after** open), and **refuse symlinks altogether**. B3's pull/merge rejects trees that contain symlinks or submodules (M-GH-6). `/data/**` is never reachable through this API. **Fuzz/property test** of the resolver.
- **M-FS-3** The directory listing returns only entries the caller can `valid_read` (decide per directory, and filter entries by class). A denial returns **404, not 403**, for paths the caller can't read, so the name and existence of other people's files don't leak. ETag = content hash only for readable files.
- **M-FS-4** **All** `/api/v1/*` responses: JSON (`application/json`) or `text/plain; charset=utf-8`, with `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment` on raw file bodies, and `Content-Security-Policy: sandbox; default-src 'none'`. Never serve VFS content with an extension-derived MIME type. File contents reach the IDE as JSON strings only.
- **M-FS-5** Body limit 1 MiB per file (`DefaultBodyLimit`). Per-uid write rate limit (e.g. 2/s, burst 20). Compiles go through the off-thread compile queue (D-P1.5), with at most one in-flight compile per uid and the newest save superseding a queued one. The request has a 10 s timeout and returns 503 on queue backpressure, never blocking the world thread.
- **M-FS-6** `PUT` requires `If-Match: <etag>` (412 on mismatch). A create uses `If-None-Match: *`.
- **M-FS-7** Every write is audited with the actor and commits to `live` with author = that staff member (B3, M-GH-5).

### 6.3 Web IDE and LSP over WebSocket (P2-B2 [OBI-180](https://paperclip.home.oberfield.net/OBI/issues/OBI-180), P2-B1 [OBI-168](https://paperclip.home.oberfield.net/OBI/issues/OBI-168))

| # | STRIDE | Threat | L×I | Mitigations |
|---|---|---|---|---|
| T-IDE-1 | E | **XSS in the staff page** via attacker strings: file names, diagnostics messages, hover **markdown** (doc comments of builder code), completion labels, error-inbox messages (contain player input), PR titles | H×H | M-IDE-1, M-IDE-2 |
| T-IDE-2 | E | Malicious markdown in hover/doc links runs Monaco `command:` URIs or loads remote images (tracking, CSRF-by-GET) | M×M | M-IDE-2 |
| T-IDE-3 | T | Clickjacking the IDE/admin in a frame | L×M | M-IDE-1 |
| T-IDE-4 | E | Supply chain: Monaco/npm from a CDN or an unpinned package | L×H | M-IDE-3 |
| T-LSP-1 | S | Cross-site WebSocket hijacking or an unauthenticated LSP session | M×H | D-TM4, M-LSP-1 |
| T-LSP-2 | I | **LSP reads beyond the tier**: go-to-definition, hover, completion, or "find references" into `/secure`, other workrooms, or non-member domains, because the server reads the filesystem directly | **H×M** | M-LSP-2 |
| T-LSP-3 | E/I | Path resolution in `inherit`/`import`/`#include` escapes the VFS (absolute host paths, `..`), or document URIs (`file:///etc/passwd`) are honoured | M×H | M-LSP-3 |
| T-LSP-4 | D | Pathological input (deep nesting, 100 MB buffer, thousands of open docs), WS message bombs (axum's default max message is 64 MiB) | M×M | M-LSP-4 |
| T-LSP-5 | E | LSP runs as a subprocess and inherits secrets (`DATABASE_URL`, key paths) | L×H | M-LSP-5 |

- **M-IDE-1** Staff origin CSP (sent by `loom-http`, with Caddy as a backup): `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; worker-src 'self' blob:; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`. `'unsafe-inline'` styles are only for Monaco; **no inline scripts**, so the bootstrap `<script type="module">` in `web-client/index.html` moves into a file. Add `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and `Cross-Origin-Opener-Policy: same-origin`. HSTS stays at Cloudflare/Caddy.
- **M-IDE-2** **No `innerHTML`/`insertAdjacentHTML`/`outerHTML`/`document.write`** in the web client. Enforce with an ESLint rule (`no-unsanitized`) in CI. Render all strings as text nodes or as Monaco text models. Monaco markdown: `isTrusted: false`, `supportHtml: false`. Allow only `https:` links plus the IDE's own `loom-vfs:` scheme. No remote images.
- **M-IDE-3** Monaco is self-hosted from the bundle (no CDN), installed with `npm ci` from the committed lockfile. `npm audit --audit-level=high` runs in CI. Dependency PRs get CTO review.
- **M-LSP-1** `/lsp` is served only on the staff origin. Check `Origin` against the allowlist. Authenticate with the D-TM4 ticket in the first frame. The session is bound to `sub`; the tier is re-checked against the snapshot for every request batch, and the session closes on revocation (M-AUTH-5) or demotion.
- **M-LSP-2** **The LSP never reads the filesystem directly.** `loom-lsp`'s workspace is a `FileProvider` trait. The stdio/local build uses a directory, and the server build uses a **per-session provider that asks `valid_read(path)` for the session's uid** (cached per `(uid, path)` with the same invalidation as the security cache: snapshot swap, `/secure` recompile). For programs the uid can't read, the LSP returns **no locations, no source, and no doc comments**. Hover/completion may show the **public function signatures** of already-compiled `protected` programs (they're the API), and nothing from `/secure`. **Test:** a T1 session doing go-to-definition from its workroom into `/secure/master.wf` and into another workroom gets nothing, and the same request from a T4 gets the location.
- **M-LSP-3** Document URIs use a `loom-vfs:///path` scheme only (others rejected). Resolution of `inherit`/`import` uses the same VFS resolver as M-FS-2. No `file:` URIs and no host paths in responses. The compiler is **compile-only**: no Weft code runs during analysis (if const-eval is ever added, it must be tick-metered).
- **M-LSP-4** WS `max_message_size` 4 MiB and `max_frame_size` 1 MiB. Max document 1 MiB. ≤ 64 open documents per session, ≤ 2 sessions per uid, ≤ 32 sessions total. Analysis runs on a bounded blocking pool (never the world thread), with a 5 s per-request deadline and request cancellation honoured. A 60 s idle ping/pong timeout. Parser and checker are already fuzzed nightly (§8.5); add `loom-lsp` request fuzzing to the nightly job.
- **M-LSP-5** If the server LSP is a subprocess: spawn it with `env_clear()` plus an allowlist, a closed set of fds, rlimits (CPU, AS), and no network. If it's in-process, the bounded pool from M-LSP-4 applies. Either way, the LSP gets its file access only through M-LSP-2.

### 6.4 `propose`, the GitHub App, and the merge webhook (P2-B3, [OBI-181](https://paperclip.home.oberfield.net/OBI/issues/OBI-181))

| # | STRIDE | Threat | L×I | Mitigations |
|---|---|---|---|---|
| T-GH-1 | E | **Unreviewed code reaches `main`**: the App token pushes to `main`, an App is in a bypass list, CODEOWNERS is editable by the proposer, or the reviewer App approves its own sibling's PR | M×H | D-TM6, M-GH-1, M-GH-2 |
| T-GH-2 | E | **A `propose` PR changes `.github/workflows/**`**. Same-repo branches run `pull_request` workflows **with repository secrets**, so a T1 gets code execution in CI with secrets | **H×H** | M-GH-3, M-GH-4 |
| T-GH-3 | S/R | The proposer sets an arbitrary commit author or `Signed-off-by`, impersonating another builder | M×M | M-GH-5 |
| T-GH-4 | E | Proposing paths the caller can't read (to exfiltrate them into a PR), or files from outside the mudlib tree | M×M | M-GH-3 |
| T-GH-5 | S | **Forged webhook** makes the driver pull or apply a commit that isn't on `main` | M×H | M-GH-6 |
| T-GH-6 | E/I | Git on attacker-influenced trees: symlinks, submodules, hooks, `file://` transport, huge blobs; the token leaks via the remote URL or error output | M×H | M-GH-6, M-GH-7 |
| T-GH-7 | I | App private key or installation token leaks (disk, logs, env of child processes, core dumps) | L×H | M-GH-7 |
| T-GH-8 | D | `propose` spam: hundreds of PRs, large diffs, GitHub rate-limit exhaustion that blocks the `live` push | M×L | M-GH-8 |
| T-GH-9 | I | PR body built from builder text pings `@org/root` or the whole org, or embeds content from files the proposer can't read | L×L | M-GH-3, M-GH-8 |

- **M-GH-1** On `warp` `main`: a required PR, required **CODEOWNERS** review, `enforce_admins`, **no bypass for any App**, `dismiss_stale_reviews`, and required checks. CODEOWNERS covers `/.github/ @LoomMud/root` and `/CODEOWNERS @LoomMud/root`, plus the §5.11.4 domain/std/secure lines. **Owner: Legolas sets it up; the board does it if org admin is needed (folded into Q-P2.3).**
- **M-GH-2** "`contents:write` on `propose/*` only" **can't be expressed as an App permission**, so enforce it in two layers: (a) the driver only ever pushes refs `propose/<uid>/<slug>` (for `propose`) and `live` (for live auto-commits; if a different credential pushes `live`, the same rule applies to it). The ref name is built server-side, never taken from input. (b) A `warp` **branch ruleset** restricts updates to `main` (and to every branch except `live` and `propose/**`) to the merge path. Installation tokens are minted **per operation**, scoped with `repositories: ["warp"]` and the minimal `permissions` in the mint request. They are never cached past their use.
- **M-GH-3** A `propose` changeset is **built by the driver from VFS files only**. Every path must (a) be under a mudlib path class (`/domains`, `/std`, `/cmds`, `/daemons`, `/include`, `/secure`, `/builders`, `/doc`) — **never `/.github`, `/CODEOWNERS`, or anything at the repo root** — and (b) pass `valid_read` for the proposer. Proposing into `secure`/`protected`/`domain_live` is allowed: review is the gate. PR title and body: driver template + builder text truncated to 2 KiB, with `@` turned into `@​` (zero-width space, so no mention fires). **Test:** a propose that includes `.github/workflows/x.yml` is refused before any GitHub call.
- **M-GH-4** **warp CI uses no secrets on `pull_request`.** Pull the image from public GHCR (OBI-109 makes GHCR public) or use `GITHUB_TOKEN` with `packages:read` only, set `permissions: {contents: read}` at the top level, and never use `pull_request_target`. That way even a bypass of M-GH-3 yields no secrets. This is defence in depth for T-GH-2. **Owner: Legolas (warp CI).**
- **M-GH-5** Commit author = `<staff display name> <uid@users.noreply.loommud.com>` (or the linked GitHub noreply address), **derived from the staff row server-side**. Add `Signed-off-by` with the same identity, so DCO passes. The committer is the App. Builder input never reaches author or trailer fields.
- **M-GH-6** Webhook `POST /api/v1/hooks/github` on the player origin (GitHub doesn't need the staff origin):
  - Verify `X-Hub-Signature-256` HMAC-SHA256 over the raw body with a constant-time comparison. Body limit 1 MiB. Accept only `push` to `refs/heads/main` and `pull_request` `closed`; everything else gets a 204. Deduplicate on `X-GitHub-Delivery`.
  - **The payload is only a trigger.** The driver `git fetch`es `main` and applies only what is reachable from `origin/main` (§5.11.4 point 5). A forged-but-signed or replayed hook can only cause a no-op fetch.
  - Git hardening for every driver git invocation: `core.hooksPath=/dev/null`, `protocol.allow=never` + `protocol.https.allow=always`, `core.symlinks=false`, no submodule recursion, `GIT_TERMINAL_PROMPT=0`. **Reject a fetched tree containing symlinks (mode 120000), gitlinks (160000), or blobs > 1 MiB** before checkout into the VFS.
- **M-GH-7** The App private key and the webhook/OAuth secrets live in the secret file (`secrets.env`/SOPS per §9.7), mode 0400, readable only by `loom`. They are read once at boot and never logged. Pass tokens to git through `GIT_ASKPASS` or a credential helper reading from memory/fd — **never in the remote URL**. Scrub `x-access-token:` from any git stderr before it's logged. Child processes (`git`, the LSP) get `env_clear()` + an allowlist. Rotating the App key is a documented runbook step.
- **M-GH-8** `propose` rate limits: 5/h per uid, at most 10 open PRs per uid, ≤ 200 files, ≤ 2 MiB per changeset. Back off on GitHub `403`/`429`, and keep the `live` push in its own queue so propose spam can't starve it.

### 6.5 Admin UI (P2-O2, [OBI-185](https://paperclip.home.oberfield.net/OBI/issues/OBI-185)) and error inbox ([OBI-169](https://paperclip.home.oberfield.net/OBI/issues/OBI-169))

| # | STRIDE | Threat | L×I | Mitigations |
|---|---|---|---|---|
| T-ADM-1 | E | Role changes bypass the `security definer` functions, or the HTTP layer passes a body-supplied `actor` | M×H | M-ADM-1 |
| T-ADM-2 | E | Two-root rule bypassed from the UI (one root proposes and approves; the target approves) | L×H | M-ADM-1 (DB already enforces it) |
| T-ADM-3 | S | Stolen access token used for role changes inside its 10-min life | M×H | M-ADM-2 |
| T-ADM-4 | I | Object browser exposes player PII or `/secure` daemon state to T1–T3 | M×M | M-ADM-3 |
| T-ADM-5 | I | Error inbox reveals secrets or PII: a runtime error in `/secure/login` with the typed password in its message or args, or in a sample trace | M×H | M-ERR-1 |
| T-ADM-6 | E | XSS via who-list names, broadcast text, audit rows, error messages | H×H | M-IDE-1, M-IDE-2 |
| T-ADM-7 | R | Admin actions not audited, or the audit view lets someone delete or edit rows | L×M | M-ADM-4 |
| T-ADM-8 | T | Broadcast used to inject terminal control sequences (ESC/CSI) into every telnet client | L×L | M-ADM-5 |

- **M-ADM-1** Every role mutation calls the existing `roles_set_tier` / `roles_set_member` / `roles_grant` / `roles_revoke_grant` / `roles_propose_tier` / `roles_approve_proposal` SQL functions. The **actor is the token's `sub`, set by the driver**; any `actor` field in the request body is a 400. `loom_app` keeps no DML on roles tables. **Test:** a direct `UPDATE staff` as `loom_app` fails. An actor field in the body is rejected. A T3 promoting to T4 is refused by SQL even with the UI check removed.
- **M-ADM-2** Role changes, grants, TOTP reset for another user, and broadcast require **step-up** (`mfa_at` ≤ 5 min; the UI re-prompts for TOTP) and tier ≥ 3 (role changes, per the §5.11.2 promotion rules) or ≥ 4 (broadcast, grants).
- **M-ADM-3** Object browser: listing (path, uid, owner, counts) for T3+, filtered to programs the caller can `valid_read`. **Variable inspection is T4+, audited, and excludes objects whose program is under `/secure`** (T5 only). Player objects show no email or IP; those stay in Postgres and aren't part of object state.
- **M-ERR-1** Error-inbox entries are visible only if the caller can `valid_read` the erroring program. That also covers `/secure/**` errors (T4+). The driver **does not record argument values** in sample traces (function + line only). Error messages from `/secure/**` programs are stored with a `redacted` flag and shown only to T5. Message length is capped at 512 bytes. Rendered as text (M-IDE-2).
- **M-ADM-4** Every admin endpoint appends `audit_log` (actor, IP, action, target, verdict). The audit view is read-only: there's no delete/update route, and `loom_app` has `INSERT`/`SELECT` only on `audit_log` (check the grant). Audit retention follows §8.6.
- **M-ADM-5** Broadcast text: strip C0/C1 control characters except `\n`, cap at 1 KiB, and send it as plain text through the normal mudlib output path. (Telnet IAC is already safe: output is `&str`, so 0xFF can't occur; `to_wire` only adds CR.)

## 7. Cross-cutting mitigations (all surfaces)

- **M-X-1 Host routing and headers (D-TM1).** `loom-http` gets `LOOM_PLAYER_HOST` / `LOOM_STAFF_HOST`. Staff routes (`/api/v1/*` except `who`, `mssp`, and `hooks/github`; `/lsp`; the IDE/admin bundle) answer only on the staff host. CSP and headers follow M-IDE-1 on the staff host and a tighter player-client CSP on the player host. **Owner: Legolas (O3 for routing; B2 for the bundle/CSP; the gitops Caddy site block too).**
- **M-X-2 World-thread protection.** HTTP → world requests go over a **bounded** channel with a per-request deadline and the requesting tier's tick budget. When the channel is full the answer is 503 and the world thread never waits. No HTTP handler holds a lock the world thread needs.
- **M-X-3 Limits everywhere.** A global `DefaultBodyLimit` (64 KiB default; 1 MiB on files PUT) and a request timeout (`tower_http::timeout`, 15 s). Per-IP rate limiting on unauthenticated routes. WS limits per M-LSP-4.
- **M-X-4 Logging hygiene.** Never log `Authorization`, cookies, request bodies of `/auth/*`, TOTP codes, tickets, OAuth `code`/`state`, or GitHub tokens. A test greps captured `tracing` output from the auth test suite for the test password, token, and TOTP code. (Caddy logs the URI, so the OAuth `code` appears in Caddy's log. PKCE + single use + 10-min expiry make that acceptable. Record this in the runbook.)
- **M-X-5 Secrets inventory** (new in Phase 2): JWT signing key, TOTP encryption key, GitHub OAuth client secret, `loom-propose` App key, webhook secret. All go in `secrets.env.example` (names only) and SOPS for Flux. All are rotatable. `gitleaks` already gates CI.
- **M-X-6 Dependency review.** New crates (JWT, TOTP, OAuth, octocrab or equivalent, AEAD) pass `cargo deny` and get named CTO review in the PR. Prefer RustCrypto/`ring` primitives over hand-rolled ones.

## 8. Residual risks (accepted, with owner)

| Risk | Why accepted | Revisit |
|---|---|---|
| A T4/T5 staff browser compromise is game over for that tier's rights | Inherent. Bounded by 10-min access tokens, step-up for role changes, and the two-root rule for T4/T5 | Hardware keys (WebAuthn) for T4+: Phase 3 |
| Single origin on staging until Q-TM1 is answered | `/api/game/*` doesn't exist yet and staging is staff-only (Q-P2.4) | **Must be closed before `/api/game/*` ships or non-staff get access** |
| LSP reveals public signatures of `protected` programs to T1 | They're the documented API (§5.11.2 lets T1 read `protected` anyway) | — |
| Caddy logs OAuth codes | PKCE-bound, single use, short-lived | If log shipping to a third party starts |
| GitHub is trusted for `main` integrity | The review model depends on it (§5.11.4) | — |

## 9. Mitigation → owner issue map, and the review gate

| Issue | Owner | Mitigation IDs it must meet |
|---|---|---|
| [OBI-174](https://paperclip.home.oberfield.net/OBI/issues/OBI-174) P2-O3 staff auth | Legolas | D-TM2, D-TM3, D-TM4 (ticket endpoint), M-AUTH-1…9, M-X-1 (host routing), M-X-3, M-X-4, M-X-5, M-X-6 |
| [OBI-180](https://paperclip.home.oberfield.net/OBI/issues/OBI-180) P2-B2 web IDE + files API | Legolas | M-FS-1…7, M-IDE-1…3, M-LSP-1, M-LSP-4 (WS limits), M-X-1 (CSP/bundle), M-X-2 |
| [OBI-168](https://paperclip.home.oberfield.net/OBI/issues/OBI-168) P2-B1 loom-lsp | Gimli | M-LSP-2, M-LSP-3, M-LSP-4 (doc/session/pool limits), M-LSP-5 |
| [OBI-181](https://paperclip.home.oberfield.net/OBI/issues/OBI-181) P2-B3 git workflow + `propose` | Aragorn (lead), Legolas (App/webhook) | D-TM6, M-GH-1…8, M-FS-2 (tree rejection) |
| [OBI-185](https://paperclip.home.oberfield.net/OBI/issues/OBI-185) P2-O2 admin UI | Legolas | M-ADM-1…5, M-IDE-1, M-IDE-2, M-X-2 |
| [OBI-169](https://paperclip.home.oberfield.net/OBI/issues/OBI-169) P2-B4 error inbox | Gimli | M-ERR-1 |
| [OBI-183](https://paperclip.home.oberfield.net/OBI/issues/OBI-183) P2-B8 E2.1 gate | Aragorn | The scripted E2.1 run includes the negative cases: T2 write to `domain_live` refused, T1 LSP into `/secure` empty, propose with `.github/` refused |

**Review gate (rest of Phase 2).** Any PR touching `crates/loom-http`, `web-client/`, the files API, `loom-lsp`'s server transport, auth, GitHub App/webhook code, admin routes, the roles SQL, or the staging Caddyfile needs an **Aragorn review against this document's IDs** before merge. Security-relevant code also needs the retro-rule second reviewer (Gimli for code Aragorn wrote). The reviewer lists the IDs checked in the review body.

## 10. Questions for the board (via CEO), each with a working assumption

| # | Question | Needed by | Working assumption |
|---|---|---|---|
| Q-TM1 | Add DNS `build.loommud.com` (Cloudflare-proxied, pointing at the same staging host as `loommud.com`) for the staff surfaces (D-TM1)? | Before `/api/game/*` or any non-staff access; ideally M2.2 | Yes. Until then, staging serves staff routes on `loommud.com` (residual risk in §8). |
| Q-TM2 | Create a **separate** GitHub App `loom-propose` on `warp` only, instead of extending the OBI-43 reviewer App (amends Q-P2.3, D-TM6)? | M2.2 (B3 GitHub part) | Yes: separate App. Extending the reviewer App would put a key that can approve `loom`/`loom-gitops` PRs on the internet-facing host. |
