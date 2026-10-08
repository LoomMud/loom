// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `loom`'s axum HTTP server (§8/§9). Owner: Legolas.
//!
//! Routes:
//! - `/ws` (OBI-39): a browser session gets the same seam as telnet
//!   (`loom_net::NetEvent`/`NetCommand`).
//! - `/lsp` (OBI-180, `lsp.rs`): the production WebSocket bridge to
//!   `loom-lsp`'s protocol core, gated by an Origin allowlist and a
//!   D-TM4 single-use ticket from `POST /api/v1/ws-ticket` (M-LSP-1/
//!   M-LSP-4).
//! - `/healthz` (OBI-28/OBI-115): liveness -- "is the process up at
//!   all". Always `200 OK` once the axum server itself is serving
//!   requests; never consults readiness or any backend.
//! - `/readyz` (OBI-28/OBI-115): readiness -- `200 OK` once
//!   `HttpState`'s [`loom_obs::Readiness`] has been flipped by the world
//!   thread (mudlib compiled, DB backend reachable), `503` before that.
//! - `/metrics` (OBI-28/OBI-115): renders `HttpState`'s
//!   [`loom_obs::PrometheusMetrics`] as Prometheus text exposition
//!   format.
//! - fallback (OBI-158): when `HttpState`'s `web_root` is set, serves the
//!   built `web-client/` (`index.html` and its `dist/` bundle) as the
//!   router fallback -- explicit routes above always win, so this can
//!   never shadow `/ws`, `/healthz`, `/readyz`, or `/metrics`. With no
//!   `web_root` (the default -- see `LOOM_WEB_ROOT` in `loom-cli`), the
//!   fallback is a plain `404`, matching pre-OBI-158 behaviour for tests
//!   and local runs that don't set it.
//! - fallback caching (OBI-338): the same file service stamps
//!   `Cache-Control` and a validator on what it serves -- `immutable`
//!   only inside a version-stamped `/vendor/<package>/<version>/` tree,
//!   revalidation for everything else. See
//!   [`with_static_cache_headers`].

use std::path::PathBuf;
use std::time::UNIX_EPOCH;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{WebSocket, WebSocketUpgrade};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use loom_obs::{PrometheusMetrics, Readiness};
use tokio::sync::mpsc;
use tower::Layer;
use tower_http::services::ServeDir;
use tracing::debug;

mod admin;
pub mod admin_query;
pub mod auth;
mod client_ip;
pub mod files;
mod handlers;
mod lsp;
pub mod webhook;

pub use handlers::auth_router;

/// Shared state for `loom-http`'s routes.
#[derive(Clone)]
pub struct HttpState {
    ws_accept_tx: mpsc::Sender<WebSocket>,
    readiness: Readiness,
    metrics: PrometheusMetrics,
    web_root: Option<PathBuf>,
    auth: Option<auth::AuthService>,
    github: Option<std::sync::Arc<dyn auth::GithubIdentityProvider>>,
    /// The (non-secret) half of the GitHub OAuth app config (OBI-201):
    /// client id + exact redirect URI, which `/auth/github/start` needs
    /// to build the authorize URL. `Some` iff [`Self::with_github`] was
    /// called.
    github_login: Option<auth::GithubLoginConfig>,
    /// M-AUTH-6: the exact `Origin` values `/auth/refresh` and
    /// `/auth/logout` accept (no CORS for anything else). Empty by
    /// default, which refuses every cookie-bearing request -- an
    /// operator who wants those routes reachable from a browser must set
    /// `LOOM_STAFF_ORIGINS` themselves (see `loom-cli`).
    staff_origins: Vec<String>,
    github_webhook: Option<webhook::GithubWebhookConfig>,
    file_op_tx: Option<files::FileOpSender>,
    write_rate_limiter: files::WriteRateLimiter,
    world_query: Option<std::sync::Arc<dyn admin_query::WorldAdminQuery>>,
    /// M-LSP-4's session caps for `/lsp` (OBI-180) -- always present
    /// (unlike `file_op_tx`'s `Option`), since an empty limiter still
    /// correctly allows sessions right up to the cap; the route itself
    /// answers `503` before ever touching this if no file-op channel is
    /// wired.
    lsp_sessions: lsp::SessionLimiter,
    /// Test-only override for `/lsp`'s timing constants (idle timeout,
    /// ping interval, first-frame timeout, revocation-recheck interval)
    /// -- `None` uses the real spec values (M-LSP-1/M-LSP-4). Set via
    /// [`Self::with_lsp_tuning_for_test`], never by `loom-cli`.
    lsp_tuning: lsp::LspTuning,
}

impl HttpState {
    pub fn new(
        ws_accept_tx: mpsc::Sender<WebSocket>,
        readiness: Readiness,
        metrics: PrometheusMetrics,
    ) -> Self {
        Self {
            ws_accept_tx,
            readiness,
            metrics,
            web_root: None,
            auth: None,
            github: None,
            github_login: None,
            staff_origins: Vec::new(),
            github_webhook: None,
            file_op_tx: None,
            write_rate_limiter: files::new_write_rate_limiter(),
            world_query: None,
            lsp_sessions: lsp::SessionLimiter::default(),
            lsp_tuning: lsp::LspTuning::default(),
        }
    }

    /// Serve the built web client (index.html + dist/) from `root` as the
    /// router fallback (OBI-158). Unset by default -- see `LOOM_WEB_ROOT`.
    pub fn with_web_root(mut self, root: PathBuf) -> Self {
        self.web_root = Some(root);
        self
    }

    /// Mount `/auth/*` (OBI-174): staff login, refresh, logout, TOTP
    /// enrolment/verification. Unset by default -- `loom-cli` only calls
    /// this when Postgres (`LOOM_DATABASE_URL`) and a JWT secret
    /// (`LOOM_JWT_KEY_FILE`) are both configured.
    pub fn with_auth(mut self, auth: auth::AuthService) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Mount `/auth/github/*` (OBI-174/OBI-201, optional): the real
    /// authorization-code + PKCE flow. Unset by default; requires
    /// [`Self::with_auth`] to also be set, since GitHub login still goes
    /// through the same `AuthService`. `login_config` is the non-secret
    /// half (client id + exact redirect URI) `/auth/github/start` needs
    /// to build the authorize URL.
    pub fn with_github(
        mut self,
        github: std::sync::Arc<dyn auth::GithubIdentityProvider>,
        login_config: auth::GithubLoginConfig,
    ) -> Self {
        self.github = Some(github);
        self.github_login = Some(login_config);
        self
    }

    /// Set the staff-origin allowlist (OBI-198, M-AUTH-6): the exact
    /// `Origin` values `/auth/refresh` and `/auth/logout` accept. Unset
    /// (empty) by default, which refuses both routes outright -- see
    /// `LOOM_STAFF_ORIGINS` in `loom-cli`.
    pub fn with_staff_origins(mut self, origins: Vec<String>) -> Self {
        self.staff_origins = origins;
        self
    }

    /// `Some` iff [`Self::with_auth`] was called -- shared by `handlers.rs`
    /// and `admin.rs` (OBI-185) for bearer-token extraction.
    pub(crate) fn auth_service(&self) -> Option<&auth::AuthService> {
        self.auth.as_ref()
    }

    /// Mount `POST /api/v1/hooks/github` (OBI-212, D-B3.12). Unset by
    /// default -- answers `503` until `loom-cli` configures a webhook
    /// secret and wires a `GitWorkerHandle`.
    pub fn with_github_webhook(mut self, config: webhook::GithubWebhookConfig) -> Self {
        self.github_webhook = Some(config);
        self
    }

    /// Mount `GET /api/v1/files/content` (OBI-180 M-FS-1). Unset by
    /// default -- answers `503` until `loom-cli` wires the world-thread
    /// file-op channel (see `files::file_op_channel`).
    pub fn with_file_ops(mut self, file_op_tx: files::FileOpSender) -> Self {
        self.file_op_tx = Some(file_op_tx);
        self
    }

    /// Wire the `who`/object-browser routes (OBI-234, P2-O2) to a real
    /// world-thread query channel. Unset by default -- those routes
    /// answer `503` (`AdminError::WorldUnavailable`) until `loom-cli`
    /// configures the world-side receiver (see `admin_query`'s module
    /// doc for the channel contract) and calls this.
    pub fn with_world_query(
        mut self,
        world_query: std::sync::Arc<dyn admin_query::WorldAdminQuery>,
    ) -> Self {
        self.world_query = Some(world_query);
        self
    }

    /// `Some` iff [`Self::with_world_query`] was called -- `admin.rs`'s
    /// `who`/`objects`/`objects/:path/vars` handlers.
    pub(crate) fn world_query(&self) -> Option<&dyn admin_query::WorldAdminQuery> {
        self.world_query.as_deref()
    }

    /// `lsp.rs`'s own accessors: `/lsp` reuses the M-FS-1 file-op channel
    /// and the M-AUTH-6 staff-origin allowlist exactly as `files.rs`/
    /// `handlers.rs` do, plus its own always-present session limiter.
    pub(crate) fn file_op_tx(&self) -> Option<&files::FileOpSender> {
        self.file_op_tx.as_ref()
    }

    pub(crate) fn staff_origins(&self) -> &[String] {
        &self.staff_origins
    }

    pub(crate) fn lsp_sessions(&self) -> &lsp::SessionLimiter {
        &self.lsp_sessions
    }

    pub(crate) fn lsp_tuning(&self) -> &lsp::LspTuning {
        &self.lsp_tuning
    }

    /// Shrink `/lsp`'s timing constants for a fast, deterministic test
    /// (idle timeout/ping interval/revocation-recheck interval all
    /// default to tens of seconds, far too slow for a test to wait out
    /// in real wall-clock time). Test-only -- `loom-cli` never calls
    /// this, so every real `/lsp` connection gets the spec's actual
    /// M-LSP-4 values.
    #[cfg(test)]
    pub(crate) fn with_lsp_tuning_for_test(mut self, tuning: lsp::LspTuning) -> Self {
        self.lsp_tuning = tuning;
        self
    }
}

/// The static bundle's response CSP (OBI-180 M-IDE-1, threat model v2
/// §5), sent by loom-http as a header so `frame-ancestors` actually
/// applies (it is ignored in `<meta>` per the CSP spec; `report-uri`
/// and `sandbox` are the other header-only directives).
///
/// This is the threat model's policy *verbatim*. Two directives look
/// looser than they need to be and are not optional:
///
/// * `style-src 'unsafe-inline'` -- Monaco injects inline `<style>` and
///   `style=` attributes for every measured text block; without it the
///   editor renders wrong. It is the one exception the threat model
///   grants explicitly ("'unsafe-inline' styles are only for Monaco").
///   Pages that don't need it tighten it back in their own `<meta>`
///   (`index.html`, `admin.html`), since a document bound by both a
///   header and a meta must satisfy *both*.
/// * `worker-src 'self' blob:` -- Monaco's language/ editor workers are
///   started from a same-origin blob URL. `blob:` is scoped to workers
///   only; scripts stay `'self'`.
///
/// `script-src 'self'` with no `'unsafe-inline'`/`'unsafe-eval'` is the
/// point of the whole policy: it is only safe to send because no served
/// file contains an inline script any more (OBI-180 moved
/// `index.html`'s bootstrap into `loom.css` + `dist/main.js`; the
/// `check-static-csp.mjs` gate in `npm run lint` keeps that true, per
/// O3-T6's "a CI-enforced test that no served static file contains an
/// inline script").
///
/// `{CONNECT}` is filled in per request by [`static_csp`], because
/// `connect-src` is the one directive here that cannot be a literal.
const STATIC_CSP_TEMPLATE: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; worker-src 'self' blob:; img-src 'self' data:; connect-src {CONNECT}; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// The static bundle's `connect-src`, computed per request from the
/// authority it arrived on (OBI-180, M-IDE-1).
///
/// **Why this is not the literal `'self'`.** Both documents served from
/// this origin open a WebSocket: the player's `/ws` (`web-client/src/main.ts`,
/// shipped since OBI-39) and the IDE's `/lsp` (M-LSP-1). CSP3 matches
/// `'self'` on *scheme equality* with one documented allowance -- an `http`
/// document may match an `https` source. There is no ws/wss upgrade in the
/// spec, and MDN says so outright: "`connect-src 'self'` does not resolve to
/// websocket schemes in all browsers". A literal `connect-src 'self'` is
/// therefore a policy whose correctness depends on an undocumented,
/// browser-specific extension: fine in the browsers that implemented the
/// upgrade, and a silently dead `/ws` in the ones that did not. This is the
/// directive that gates exfiltration, so it gets the reading that works
/// everywhere: `'self'` for same-origin `fetch` to `/api/v1/*`, plus this
/// request's own host under both websocket schemes.
///
/// **Why host-pinned rather than `ws: wss:`.** A scheme-only source matches
/// *any* host under that scheme, which would hand injected script a working
/// exfiltration channel to an attacker's server -- precisely the capability
/// `default-src 'self'` exists to remove. Pinning the request's authority
/// grants nothing to a third party: `main.ts` builds the socket URL from
/// `location.host`, so a client can only ever dial the host it was served
/// from.
///
/// A missing or non-conforming `Host` yields `'self'` alone (fail closed),
/// and [`ws_authority`] is a character allow-list rather than a sanity
/// filter, so no `Host` value can inject source expressions into the policy.
///
/// Deployment constraint this implies: the `Host` loom-http sees must be the
/// authority the browser dialed, i.e. the proxy must pass it through (Caddy
/// and the compose stack both do; an nginx `proxy_set_header Host
/// $upstream_host` would grant a source the client cannot match and
/// silently kill its socket).
pub fn static_csp(host: Option<&str>) -> String {
    let connect = match ws_authority(host) {
        Some(authority) => format!("'self' ws://{authority} wss://{authority}"),
        None => "'self'".to_string(),
    };
    STATIC_CSP_TEMPLATE.replace("{CONNECT}", &connect)
}

/// The request authority a websocket source may be built from, if `host` is
/// a bare `name[:port]` or a bracketed IPv6 literal `[addr]:port`. Letters,
/// digits, `.`, `-`, `_` (or a real `Ipv6Addr` inside brackets) only -- no
/// `@`, `'`, `/`, or stray whitespace -- so no `Host` value can inject a
/// source expression into the policy or break out of the header. See
/// [`static_csp`].
fn ws_authority(host: Option<&str>) -> Option<&str> {
    let host = host?;
    if let Some(rest) = host.strip_prefix('[') {
        // Bracketed IPv6 literal, with an optional port after `]`. Parsed
        // rather than pattern-matched: the legal shape of an IPv6 literal is
        // fiddly, and `Ipv6Addr` is the authority on it.
        let (addr, suffix) = rest.split_once(']')?;
        return (addr.parse::<std::net::Ipv6Addr>().is_ok() && port_ok(suffix)).then_some(host);
    }
    let (name, port) = match host.split_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host, None),
    };
    let name_ok = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    (name_ok && port.is_none_or(is_port)).then_some(host)
}

/// `:443` -> true, `""` -> true (no port present), anything else -> false.
fn port_ok(suffix: &str) -> bool {
    match suffix.strip_prefix(':') {
        Some(port) => is_port(port),
        None => suffix.is_empty(),
    }
}

fn is_port(port: &str) -> bool {
    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
}

/// The rest of M-IDE-1's static-bundle header set, as `(name, value)`
/// pairs so the policy stays one reviewable list. Values are all
/// literals, hence `from_static`.
///
/// * `X-Frame-Options: DENY` -- header-only fallback for UAs that
///   predate `frame-ancestors`.
/// * `X-Content-Type-Options: nosniff` -- a served `.txt`/`.js` is never
///   sniffed into something the CSP would then have to protect against.
/// * `Referrer-Policy: no-referrer` -- an admin/IDE URL *is* a domain
///   path (`/builders/<u>/<area>/...`, M-IDE-1/T-IDE-2), so it must not
///   leak to a third party through the Referer of a sub-resource.
/// * `Cross-Origin-Opener-Policy: same-origin` -- isolates this
///   document's browsing group, so a window opened by another origin
///   can't hold a handle on the staff session's window (M-IDE-1).
const STATIC_SECURITY_HEADERS: [(&str, &str); 4] = [
    ("x-frame-options", "DENY"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("cross-origin-opener-policy", "same-origin"),
];

/// Stamp the static-bundle policy onto every response the file service
/// produces (OBI-180/M-IDE-1). Applied as a `tower::Layer` on the
/// [`axum::middleware::from_fn`] service in [`app`], so it covers every path
/// the file service answers -- including a 404 for a missing file, which is
/// harmless and cheaper than path-sniffing -- and deliberately not on `/ws`,
/// `/metrics` or the API routes, which set their own per-response headers (a
/// file body served by `/api/v1/files/content` carries a
/// `sandbox; default-src 'none'` CSP of its own, M-FS-4). Only headers
/// change; the body and status pass through.
///
/// It is a request-aware middleware rather than the `map_response` this
/// function replaced because `connect-src` needs the `Host` the request came
/// in on; see [`static_csp`] for why a literal cannot do that job.
async fn with_static_security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // `to_str` rather than lossy conversion: a non-ASCII `Host` (an IDN) is
    // not something this policy will pin, and `ws_authority` would reject it
    // anyway. `HeaderMap::get(HOST)` is the authority the browser dialed,
    // which is what its own `location.host` will be.
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut response = next.run(request).await;
    let csp = static_csp(host.as_deref());
    // `from_str` cannot fail here: every byte of `csp` is ASCII by
    // construction (`STATIC_CSP_TEMPLATE` is ASCII, and `ws_authority`
    // only lets `[A-Za-z0-9._-:]` through into the interpolation).
    let value = HeaderValue::from_str(&csp).unwrap_or_else(|_| HeaderValue::from_static("invalid"));
    response
        .headers_mut()
        .insert(header::CONTENT_SECURITY_POLICY, value);
    for (name, header_value) in STATIC_SECURITY_HEADERS {
        response.headers_mut().insert(
            header::HeaderName::from_static(name),
            HeaderValue::from_static(header_value),
        );
    }
    response
}

/// `Cache-Control` for a file whose URL cannot outlive its bytes (OBI-338).
///
/// `immutable` is the Cache-Control extension of RFC 8246 §2: the server
/// asserts that the representation behind this URL will not change during
/// its freshness lifetime, so a client "never needs to revalidate a cached
/// fresh resource" -- which is the whole point, because the vendored bundle
/// is ~21.9 MB of Monaco (OBI-180 accepted that size on this condition) and
/// revalidation is precisely what stops being paid on a page load.
///
/// One year is what RFC 8246 §2.2 uses as its own example
/// (`max-age=31536000, immutable`), and it is not a number pulled out of the
/// air: RFC 9111 §5.3 records that HTTP capped freshness at a year
/// historically, and that even now larger values are useless because caches
/// evict far sooner and 32-bit date arithmetic overflows (§1.2.2). So a year
/// is the longest promise that is worth making, not the longest one allowed.
const STATIC_CACHE_IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// `Cache-Control` for every other file the static service answers.
///
/// `max-age=0, must-revalidate` looks like a strange thing to send on a
/// response we are asking to be cached, so the reasoning is spelled out:
/// the web client's own build step is `tsc` with no bundler, so `dist/**`
/// is *not* content-hashed -- `/dist/ide/app.js` is the same URL in every
/// deploy, holding different bytes. A positive `max-age` there would let a
/// builder load yesterday's editor code against today's `ide.html` (the two
/// are never deployed independently of each other, but a cache happily serves
/// them independently), which is exactly the "needs a hard reload to take
/// effect" failure this issue exists to prevent. So the response is stored
/// and revalidated through the validator below, which costs a header-only
/// `304` rather than the file.
///
/// If `dist/**` ever grows a content hash (a real bundler, or the stamping
/// `scripts/vendor-monaco.mjs` does for `vendor/`), the class flips to
/// [`STATIC_CACHE_IMMUTABLE`] and this constant is what changes.
const STATIC_CACHE_REVALIDATE: &str = "public, max-age=0, must-revalidate";

/// Is `path` a file inside a **version-stamped** vendor tree --
/// `/vendor/<package>/<version>/<file..>`, e.g. the
/// `/vendor/monaco/0.57.0/vs/loader.js` that `scripts/vendor-monaco.mjs`
/// stages (OBI-338)?
///
/// This is the only gate on [`STATIC_CACHE_IMMUTABLE`], and it is deliberately
/// structural rather than "is under `/vendor/`": `immutable` is safe exactly
/// when the URL changes as the bytes do, so an unversioned
/// `/vendor/monaco/vs/loader.js` -- which is what the tree looked like before
/// this issue, and what a hand-placed asset or a `latest` symlink would look
/// like -- must not get it. A false positive here is a stale 21 MB bundle in
/// every builder's browser until they clear their cache; a false negative
/// costs a `304`.
///
/// The rules, each of which is tested:
///
/// * the stamp is the *third* segment and starts with a digit, which is what
///   separates `0.57.0` from `vs`, `monaco`, or `latest`;
/// * every segment is `[A-Za-z0-9._-]`, non-empty, and neither `.` nor `..`
///   -- a URL that `ServeDir` would resolve somewhere else than under the
///   stamp must not be pinned;
/// * the path contains no `%`, because a percent-encoded URL is not the path
///   on disk it resolves to, so the URL alone no longer identifies the bytes;
/// * at least one segment follows the stamp: the stamp *directory* is not an
///   asset (`ServeDir` answers it with a redirect or an index, not bytes).
fn is_version_stamped_asset(path: &str) -> bool {
    if path.contains('%') {
        return false;
    }
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    let mut segments = rest.split('/');
    if segments.next() != Some("vendor") {
        return false;
    }
    let (Some(package), Some(stamp)) = (segments.next(), segments.next()) else {
        return false;
    };
    if !is_plain_segment(package) || !is_version_stamp(stamp) {
        return false;
    }
    match segments.next() {
        None => false,
        Some(first) => is_plain_segment(first) && segments.all(is_plain_segment),
    }
}

/// A path segment with nothing in it that could resolve elsewhere: no empty
/// segment, no dot-segment, and only characters that survive percent-encoding
/// unchanged (`ServeDir` percent-decodes what it is given).
fn is_plain_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// A plain segment that begins with a digit -- the shape of the npm version
/// `scripts/vendor-monaco.mjs` puts in the URL.
fn is_version_stamp(segment: &str) -> bool {
    segment.starts_with(|byte: char| byte.is_ascii_digit()) && is_plain_segment(segment)
}

/// A validator for one served file, from the two headers the file service
/// already paid to produce: `content-length` and `last-modified`.
///
/// **Weak, on purpose.** A strong validator has to change whenever anything
/// observable in the payload changes (RFC 9110 §8.8.1), and `(length, mtime)`
/// cannot promise that -- a length-preserving edit inside the same second,
/// or two builds under a pinned `SOURCE_DATE_EPOCH`, would collide. Weakness
/// costs nothing here: `If-None-Match` compares with the weak function
/// anyway (RFC 9110 §13.1.2, §8.8.3.2), so revalidation works exactly as
/// well, and the only thing given up is `If-Range`/`206` composition, which
/// nothing in this bundle uses.
///
/// Shaped as `<mtime-seconds-hex>-<length-hex>` -- the same two inputs nginx
/// hashes into its `ETag`, in hex -- so that a report of "the IDE is serving
/// me an old file" can be answered by reading the validator instead of
/// guessing.
///
/// Returns `None` when either header is missing (a filesystem without mtimes,
/// or a response that is not a file at all): no validator, no conditional
/// handling, and the freshness lifetime still applies.
fn static_etag(headers: &axum::http::HeaderMap) -> Option<HeaderValue> {
    let last_modified = headers
        .get(header::LAST_MODIFIED)?
        .to_str()
        .ok()
        .and_then(|value| httpdate::parse_http_date(value).ok())?;
    let seconds = last_modified.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let length: u64 = headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()?;
    HeaderValue::from_str(&format!("W/\"{seconds:x}-{length:x}\"")).ok()
}

/// Does one `If-None-Match` header value select the representation we are
/// about to send? `*` matches anything, and a list is comma-separated.
///
/// Splitting on `,` is safe for the values this crate emits: [`static_etag`]
/// is hex, `-`, and quotes, so it cannot contain a comma. Stripping `W/` from
/// both sides is the weak comparison that RFC 9110 §13.1.2 makes mandatory
/// for `If-None-Match`, and needed anyway -- a client echoes back the `W/`
/// prefix we sent.
fn if_none_match_matches(candidates: &str, etag: &str) -> bool {
    let ours = strip_weakness(etag);
    candidates.split(',').any(|candidate| {
        let candidate = strip_weakness(candidate);
        candidate == "*" || candidate == ours
    })
}

fn strip_weakness(value: &str) -> &str {
    value.trim().strip_prefix("W/").unwrap_or(value).trim()
}

/// Turn a `200` whose body the client already holds into the `304` RFC 9110
/// §15.4.5 asks for. That section names the headers a `304` must still carry
/// (`Content-Location`, `Date`, `ETag`, `Vary`, `Cache-Control`, `Expires` --
/// all of them already on the `200` we are converting, so this function adds
/// none) and says a sender SHOULD NOT generate other representation metadata:
/// so the four payload headers below, which describe a body this response
/// does not have, come off, along with the body itself.
fn to_not_modified(response: axum::response::Response) -> axum::response::Response {
    let (mut parts, _body) = response.into_parts();
    parts.status = StatusCode::NOT_MODIFIED;
    for name in [
        header::CONTENT_LENGTH,
        header::CONTENT_TYPE,
        header::CONTENT_ENCODING,
        header::CONTENT_LANGUAGE,
    ] {
        parts.headers.remove(name);
    }
    axum::response::Response::from_parts(parts, axum::body::Body::empty())
}

/// Freshness and validators for the static bundle (OBI-338), layered under
/// [`with_static_security_headers`] in [`app`].
///
/// Two classes only, and the split is [`is_version_stamped_asset`]: a
/// version-stamped vendor URL is [`STATIC_CACHE_IMMUTABLE`], and everything
/// else the file service answers is [`STATIC_CACHE_REVALIDATE`] with a
/// validator. `/api`, `/ws`, `/metrics` and `/healthz` never reach this layer
/// -- they are explicit routes above the fallback, and `handlers.rs` already
/// sets `no-store` on the responses that need it.
///
/// The M-IDE-1 header set is untouched: this layer only adds headers, and the
/// security layer wraps it, so a `304` produced here is still stamped with
/// the CSP (a `304` updates a cache's stored headers, so an entry that loses
/// the policy would be a policy the next load does not get).
async fn with_static_cache_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let immutable = is_version_stamped_asset(request.uri().path());
    // Collected before the request is moved into `next.run`. A client may
    // send the header more than once, and all of them are then compared.
    let if_none_match: Vec<String> = request
        .headers()
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    let mut response = next.run(request).await;

    let status = response.status();
    // Say nothing about freshness unless the response carries the file (or a
    // `304` about it). This is not decoration: stamping a `404` for a not-yet
    // deployed `/vendor/monaco/0.58.0/...` would cache the miss for a year,
    // and the page that eventually ships those files would never see them.
    if !(status.is_success() || status == StatusCode::NOT_MODIFIED) {
        return response;
    }
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if immutable {
            STATIC_CACHE_IMMUTABLE
        } else {
            STATIC_CACHE_REVALIDATE
        }),
    );
    // The CSP riding on this response is computed from the request's `Host`
    // (`static_csp`, because `connect-src` has to name the authority the
    // browser dialed), so the response varies on something its URL does not
    // name. A cache keyed on the URL alone could hand host A's policy to host
    // B -- and B's `/ws` would be the thing that breaks. Browsers key on
    // origin anyway; this is for anything shared in front of them, and
    // `public` above is what makes that case reachable.
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Host"));

    // Validators only for a complete `200`: a `206`'s `content-length` is the
    // range's, not the file's, and a `304` from the file service's own
    // `If-Modified-Since` handling has no metadata of its own to read.
    if status != StatusCode::OK {
        return response;
    }
    let Some(etag) = static_etag(response.headers()) else {
        return response;
    };
    // Every byte of it is ASCII by construction, so the borrow that follows
    // cannot fail -- and if it ever did, the answer is to send no validator.
    let Ok(etag_text) = etag.to_str() else {
        return response;
    };
    let etag_text = etag_text.to_owned();
    response.headers_mut().insert(header::ETAG, etag);
    if if_none_match
        .iter()
        .any(|candidates| if_none_match_matches(candidates, &etag_text))
    {
        return to_not_modified(response);
    }
    response
}

pub fn app(state: HttpState) -> Router {
    let web_root = state.web_root.clone();
    let router = Router::new()
        .route("/ws", get(ws_handler))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .merge(handlers::auth_router())
        .merge(admin::admin_router())
        .merge(webhook::webhook_router())
        .merge(files::files_router())
        .merge(lsp::lsp_router())
        .with_state(state);
    match web_root {
        Some(root) => {
            // `from_fn` is used as a `tower::Layer` here rather than through a
            // `Router::layer`, because the thing that needs stamping is the
            // `ServeDir` *service* -- putting it on the router would also wrap
            // `/api`, `/ws` and `/metrics`, whose responses set their own
            // headers. `ServeDir`'s request body stays implicit: it is a single
            // generic type (the fallback), and `Service<Request>` is picked from
            // the router's `fallback_service` bound.
            //
            // Two layers, nested so the caching one sits next to the file
            // service (OBI-338): it reads the `content-length`/`last-modified`
            // `ServeDir` produces, and the security layer stamps whatever comes
            // back -- including the `304` it may turn a `200` into, so a cached
            // entry cannot lose M-IDE-1's policy.
            let static_files = axum::middleware::from_fn(with_static_security_headers).layer(
                axum::middleware::from_fn(with_static_cache_headers).layer(ServeDir::new(root)),
            );
            router.fallback_service(static_files)
        }
        None => router,
    }
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<HttpState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        if state.ws_accept_tx.send(socket).await.is_err() {
            debug!("dropped websocket upgrade: net server is not accepting connections");
        }
    })
}

async fn healthz() -> impl IntoResponse {
    StatusCode::OK
}

async fn readyz(State(state): State<HttpState>) -> impl IntoResponse {
    if state.readiness.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn metrics(State(state): State<HttpState>) -> impl IntoResponse {
    state.metrics.render()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The authority a browser would put in `Host` when served the bundle in
    /// production; [`static_csp`] builds `connect-src` around it.
    const TEST_HOST: &str = "mud.example";

    use std::net::SocketAddr;

    use futures_util::{SinkExt, StreamExt};
    use http_body_util::BodyExt;
    use loom_net::{NetCommand, NetConfig, NetEvent};
    use serde_json::json;
    use tokio::net::TcpListener as TokioTcpListener;
    use tokio_tungstenite::tungstenite::Message as ClientMessage;
    use tower::ServiceExt;

    async fn spawn_test_server() -> (
        SocketAddr,
        mpsc::Sender<NetCommand>,
        mpsc::Receiver<NetEvent>,
        tokio::sync::watch::Sender<bool>,
    ) {
        let http_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();

        let (ws_accept_tx, ws_accept_rx) = mpsc::channel(16);
        let state = HttpState::new(
            ws_accept_tx,
            Readiness::new(),
            PrometheusMetrics::new_unregistered(),
        );
        let app = app(state);
        tokio::spawn(async move {
            axum::serve(http_listener, app).await.unwrap();
        });

        // A bound-but-unused telnet listener: `run_server_with_ws` still
        // wants one, but nothing in these tests dials it.
        let telnet_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();

        let (event_tx, event_rx) = mpsc::channel(256);
        let (command_tx, command_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        tokio::spawn(loom_net::run_server_with_ws(
            telnet_listener,
            NetConfig::default(),
            event_tx,
            command_rx,
            shutdown_rx,
            ws_accept_rx,
        ));

        (http_addr, command_tx, event_rx, shutdown_tx)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ws_line_round_trips_through_net_event_and_command() {
        let (addr, command_tx, mut event_rx, _shutdown_tx) = spawn_test_server().await;

        let url = format!("ws://{addr}/ws");
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();

        ws.send(ClientMessage::Text(
            json!({"type": "line", "text": "look"}).to_string().into(),
        ))
        .await
        .unwrap();

        let conn_id = loop {
            match event_rx.recv().await.unwrap() {
                NetEvent::Connected(id) => {
                    let _ = id;
                }
                NetEvent::Line(id, text) => {
                    assert_eq!(text, "look");
                    break id;
                }
                other => panic!("unexpected event: {other:?}"),
            }
        };

        command_tx
            .send(NetCommand::Send(conn_id, "A Room\n".to_string()))
            .await
            .unwrap();

        let reply = ws.next().await.unwrap().unwrap();
        let ClientMessage::Text(text) = reply else {
            panic!("expected a text frame, got {reply:?}");
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["type"], "line");
        assert_eq!(parsed["text"], "A Room\n");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ws_gmcp_round_trips_as_json() {
        let (addr, command_tx, mut event_rx, _shutdown_tx) = spawn_test_server().await;

        let url = format!("ws://{addr}/ws");
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();

        ws.send(ClientMessage::Text(
            json!({"type": "gmcp", "package": "Core.Hello", "payload": {"client": "web", "version": "1"}})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();

        let conn_id = loop {
            match event_rx.recv().await.unwrap() {
                NetEvent::Connected(id) => {
                    let _ = id;
                }
                NetEvent::Gmcp(id, msg) => {
                    assert_eq!(
                        msg,
                        loom_net::GmcpMessage::CoreHello {
                            client: "web".to_string(),
                            version: "1".to_string(),
                        }
                    );
                    break id;
                }
                other => panic!("unexpected event: {other:?}"),
            }
        };

        command_tx
            .send(NetCommand::SendGmcp(
                conn_id,
                "Char.Vitals".to_string(),
                json!({"hp": 10}),
            ))
            .await
            .unwrap();

        let reply = ws.next().await.unwrap().unwrap();
        let ClientMessage::Text(text) = reply else {
            panic!("expected a text frame, got {reply:?}");
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["type"], "gmcp");
        assert_eq!(parsed["package"], "Char.Vitals");
        assert_eq!(parsed["payload"]["hp"], 10);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_ws_reader_is_dropped_without_affecting_a_fast_one() {
        let http_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        let (ws_accept_tx, ws_accept_rx) = mpsc::channel(16);
        let state = HttpState::new(
            ws_accept_tx,
            Readiness::new(),
            PrometheusMetrics::new_unregistered(),
        );
        let app = app(state);
        tokio::spawn(async move {
            axum::serve(http_listener, app).await.unwrap();
        });

        let telnet_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let (command_tx, command_rx) = mpsc::channel(256);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(loom_net::run_server_with_ws(
            telnet_listener,
            NetConfig {
                output_queue_depth: 1,
                ..NetConfig::default()
            },
            event_tx,
            command_rx,
            shutdown_rx,
            ws_accept_rx,
        ));

        let url = format!("ws://{http_addr}/ws");
        let (mut slow, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        let (mut fast, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

        slow.send(ClientMessage::Text(
            json!({"type": "line", "text": "slow"}).to_string().into(),
        ))
        .await
        .unwrap();
        fast.send(ClientMessage::Text(
            json!({"type": "line", "text": "fast"}).to_string().into(),
        ))
        .await
        .unwrap();

        let mut slow_conn = None;
        let mut saw_slow_disconnect = false;
        let mut replied_fast = false;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while !(saw_slow_disconnect && replied_fast) {
            let event = tokio::time::timeout_at(deadline, event_rx.recv())
                .await
                .expect("timed out waiting for slow disconnect / fast reply")
                .expect("event channel closed");
            match event {
                NetEvent::Connected(_) => {}
                NetEvent::Line(id, line) => {
                    if line == "slow" {
                        slow_conn = Some(id);
                        for i in 0..200 {
                            let _ = command_tx
                                .send(NetCommand::Send(id, format!("spam-{i}\n")))
                                .await;
                        }
                    } else if line == "fast" {
                        let _ = command_tx
                            .send(NetCommand::Send(id, "ok\n".to_string()))
                            .await;
                        replied_fast = true;
                    }
                }
                NetEvent::Disconnected(id) => {
                    if Some(id) == slow_conn {
                        saw_slow_disconnect = true;
                    }
                }
                other => panic!("unexpected event: {other:?}"),
            }
        }

        assert!(saw_slow_disconnect, "slow WS client was never dropped");

        // The fast client keeps getting served: read frames until we see
        // the "ok" reply (there may be a stray earlier frame in flight).
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let msg = tokio::time::timeout_at(deadline, fast.next())
                .await
                .expect("timed out waiting for fast client reply")
                .expect("fast client stream ended")
                .unwrap();
            let ClientMessage::Text(text) = msg else {
                continue;
            };
            let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
            if parsed["type"] == "line" && parsed["text"] == "ok\n" {
                break;
            }
        }

        // Draining the slow socket eventually surfaces the server-initiated
        // close (or the read simply erroring once the TCP connection is
        // torn down) -- either way confirms it was actually dropped, not
        // just stalled.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), slow.next()).await;
    }

    /// Copyover, old-process side (OBI-184/OBI-227 review): a WebSocket
    /// session has no raw-fd story, so `loom_net::ws`'s `Reclaim` handler
    /// must answer `None` *and* actually end the session -- not leave a
    /// zombie task that the registry no longer routes commands to but
    /// that keeps reading the client's frames and emitting `NetEvent`s
    /// for a `conn_id` nothing tracks anymore. Drives a real
    /// `axum`-upgraded WS connection (not a bare `TcpStream`, unlike
    /// `loom-net`'s own reclaim test) through `run_server_full`'s
    /// `reclaim_rx` directly, since `run_server_with_ws` doesn't expose
    /// it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ws_reclaim_answers_none_and_ends_the_session() {
        let http_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        let (ws_accept_tx, ws_accept_rx) = mpsc::channel(16);
        let state = HttpState::new(
            ws_accept_tx,
            Readiness::new(),
            PrometheusMetrics::new_unregistered(),
        );
        let app = app(state);
        tokio::spawn(async move {
            axum::serve(http_listener, app).await.unwrap();
        });

        let telnet_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let (_command_tx, command_rx) = mpsc::channel(256);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (_adopt_tx, adopt_rx) = mpsc::channel(1);
        let (reclaim_tx, reclaim_rx) = mpsc::channel(4);
        tokio::spawn(loom_net::run_server_full(
            telnet_listener,
            NetConfig::default(),
            event_tx,
            command_rx,
            shutdown_rx,
            ws_accept_rx,
            adopt_rx,
            reclaim_rx,
        ));

        let url = format!("ws://{http_addr}/ws");
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();

        ws.send(ClientMessage::Text(
            json!({"type": "line", "text": "hi"}).to_string().into(),
        ))
        .await
        .unwrap();

        let conn_id = loop {
            match event_rx.recv().await.unwrap() {
                NetEvent::Connected(_) => {}
                NetEvent::Line(id, text) => {
                    assert_eq!(text, "hi");
                    break id;
                }
                other => panic!("unexpected event: {other:?}"),
            }
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        reclaim_tx.send((conn_id, reply_tx)).await.unwrap();
        let reclaimed = tokio::time::timeout(std::time::Duration::from_secs(5), reply_rx)
            .await
            .expect("WS reclaim must answer promptly, not hang")
            .expect("reclaim reply channel dropped");
        assert!(
            reclaimed.is_none(),
            "a WS connection has no raw fd to hand off -- reclaim must answer None"
        );

        // Not a zombie: the session actually ends -- the client sees its
        // socket close, and the registry still reports a real disconnect
        // (so a bound object's `net_dead()` still runs; this session does
        // not survive the copyover).
        let closed = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await
            .expect("client should observe the server closing the socket");
        assert!(
            matches!(closed, Some(Ok(ClientMessage::Close(_))) | None),
            "expected the server to close the WS session after an unsupported reclaim, got {closed:?}"
        );

        let disconnect_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let event = tokio::time::timeout_at(disconnect_deadline, event_rx.recv())
                .await
                .expect("timed out waiting for the post-reclaim Disconnected event")
                .expect("event channel closed");
            if let NetEvent::Disconnected(id) = event {
                assert_eq!(id, conn_id);
                break;
            }
        }
    }

    async fn spawn_health_test_server() -> Router {
        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let readiness = Readiness::new();
        let state = HttpState::new(
            ws_accept_tx,
            readiness,
            PrometheusMetrics::new_unregistered(),
        );
        app(state)
    }

    #[tokio::test]
    async fn healthz_is_always_ok() {
        let app = spawn_health_test_server().await;
        let request = axum::http::Request::builder()
            .uri("/healthz")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_reflects_readiness_gate() {
        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let readiness = Readiness::new();
        let state = HttpState::new(
            ws_accept_tx,
            readiness.clone(),
            PrometheusMetrics::new_unregistered(),
        );
        let app = app(state);

        let request = axum::http::Request::builder()
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        readiness.set_ready();
        let request = axum::http::Request::builder()
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_renders_prometheus_text() {
        let app = spawn_health_test_server().await;
        let request = axum::http::Request::builder()
            .uri("/metrics")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // An empty recorder still renders valid (if empty) exposition
        // text -- just check the route wires through to `render()`
        // without error.
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _ = String::from_utf8(body.to_vec()).unwrap();
    }

    #[tokio::test]
    async fn root_is_404_without_a_web_root() {
        let app = spawn_health_test_server().await;
        let request = axum::http::Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        // No `LOOM_WEB_ROOT` set (`HttpState::new`'s default): unchanged
        // pre-OBI-158 behaviour for tests and local runs.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn root_serves_index_html_with_a_web_root_set() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html>loom</html>").unwrap();
        std::fs::create_dir(dir.path().join("dist")).unwrap();
        std::fs::write(dir.path().join("dist").join("app.js"), "export {};").unwrap();

        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let state = HttpState::new(
            ws_accept_tx,
            Readiness::new(),
            PrometheusMetrics::new_unregistered(),
        )
        .with_web_root(dir.path().to_path_buf());
        let app = app(state);

        let request = axum::http::Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "<html>loom</html>".as_bytes());

        // A path inside the served tree (the built JS bundle) also comes
        // through the fallback, not just `/` itself.
        let request = axum::http::Request::builder()
            .uri("/dist/app.js")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Explicit routes still win over the fallback.
        let request = axum::http::Request::builder()
            .uri("/healthz")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn static_fallback_carries_the_m_ide_1_csp_and_header_set() {
        // OBI-294/OBI-180 M-IDE-1: `frame-ancestors` (and `report-uri`/
        // `sandbox`) are no-ops when delivered only via
        // `<meta http-equiv="Content-Security-Policy">` -- they take
        // effect as a response header alone. So the static fallback sends
        // the whole M-IDE-1 policy as headers, for every path under the
        // served tree -- not just the staff pages -- and each page's
        // `<meta>` stays as the belt-and-braces copy for whatever loom
        // -http is not in front of (a proxy serving the bundle directly).
        // Two policies on one document are both enforced, so a tighter
        // `<meta>` can only narrow what the header allows, never widen it.
        // The `<meta>` policies leave out `connect-src` *and* `default-src`
        // on purpose: a static file cannot name the host it will be served
        // from, and `default-src` would fill in for a missing `connect-src`
        // and block `/ws`/`/lsp`. `check-static-csp.mjs` pins that shape.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html>loom</html>").unwrap();
        std::fs::write(
            dir.path().join("admin.html"),
            "<html><!-- meta CSP lives here too --></html>",
        )
        .unwrap();

        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let state = HttpState::new(
            ws_accept_tx,
            Readiness::new(),
            PrometheusMetrics::new_unregistered(),
        )
        .with_web_root(dir.path().to_path_buf());
        let app = app(state);

        for path in ["/", "/admin.html"] {
            let response = app
                .clone()
                .oneshot(static_request(path, "mud.example"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "path: {path}");
            let csp = response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap_or_else(|| panic!("missing CSP header on {path}"))
                .to_str()
                .unwrap()
                .to_owned();
            assert_eq!(
                csp,
                static_csp(Some("mud.example")),
                "path: {path}: the header must be the policy this host needs"
            );
            assert!(
                csp.contains("frame-ancestors 'none'"),
                "frame-ancestors must ride in the header, not only the meta: {path}"
            );
            assert!(
                csp.contains("wss://mud.example"),
                "the player's /ws and the IDE's /lsp are WebSockets; 'self' alone \n            is not documented to cover them: {path}"
            );
            let xfo = response
                .headers()
                .get(header::HeaderName::from_static("x-frame-options"))
                .unwrap_or_else(|| panic!("missing X-Frame-Options header on {path}"))
                .to_str()
                .unwrap();
            assert_eq!(xfo, "DENY");
        }

        // Explicit (non-fallback) routes are untouched by the static-file
        // header stamping -- it only wraps the `ServeDir` fallback
        // service. `/healthz` must not pick up a document CSP.
        let request = axum::http::Request::builder()
            .uri("/healthz")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .is_none()
        );
    }

    /// A `script-src 'self'` with an escape hatch is the same as no
    /// script-src at all for a page that renders builder-authored text
    /// (M-IDE-2/T-IDE-1: a stored `<script>`-shaped string is only
    /// dangerous if the policy lets inline or remote script in). Pin the
    /// exact directive rather than grepping for substrings that could
    /// appear in another directive's source list.
    #[test]
    fn static_csp_grants_no_script_escape_hatch() {
        let policy = static_csp(Some(TEST_HOST));
        let policy = policy.as_str();
        let script_src = csp_directive(policy, "script-src");
        assert_eq!(script_src, "'self'", "script-src must stay 'self' only");
        for forbidden in [
            "unsafe-inline",
            "unsafe-eval",
            "blob:",
            "data:",
            "*",
            "http",
        ] {
            assert!(
                !script_src.contains(forbidden),
                "script-src carries {forbidden:?}: {script_src}"
            );
        }
        // `default-src` is the fallback for every directive the policy
        // does not name, so it must not be looser than script-src either.
        assert_eq!(csp_directive(policy, "default-src"), "'self'");
        assert_eq!(csp_directive(policy, "object-src"), "'none'");
        assert_eq!(csp_directive(policy, "base-uri"), "'none'");
        assert_eq!(csp_directive(policy, "form-action"), "'self'");
    }

    /// The two `style-src`/`worker-src` exceptions are documented in
    /// [`static_csp`] as Monaco-only. Pin them so a future "tighten
    /// everything" change can't silently drop them (Monaco renders wrong
    /// without inline styles and starts its workers from a blob URL), and
    /// so the exceptions cannot spread to `script-src`.
    #[test]
    fn static_csp_keeps_the_monaco_exceptions_scoped_to_monaco() {
        let policy = static_csp(Some(TEST_HOST));
        let policy = policy.as_str();
        assert_eq!(csp_directive(policy, "style-src"), "'self' 'unsafe-inline'");
        assert_eq!(csp_directive(policy, "worker-src"), "'self' blob:");
        // `blob:` belongs to workers only: if it ever reached the script
        // or fetch directives, a same-origin blob could carry code. The
        // admin pages' `<meta>` is where the `style-src` exception is
        // narrowed back to `'self'` for pages that don't mount Monaco.
        for directive in ["script-src", "connect-src", "default-src"] {
            assert!(
                !csp_directive(policy, directive).contains("blob:"),
                "{directive} must not allow blob:"
            );
        }
    }

    /// `connect-src` is the directive that decides whether a client can
    /// reach the driver at all, and both clients use a WebSocket (`/ws` for
    /// the player, `/lsp` for the IDE). CSP3 matches `'self'` by scheme
    /// equality with only an http->https allowance, and MDN records that
    /// `connect-src 'self'` "does not resolve to websocket schemes in all
    /// browsers" -- so the policy names this request's host under `ws:` and
    /// `wss:` explicitly instead of relying on an undocumented extension.
    /// A wildcard source is not acceptable here: it would hand injected
    /// script an exfiltration channel to any host (M-IDE-1). Pinned so the
    /// constraint is visible at the point someone tries to widen it.
    #[test]
    fn static_csp_pins_connect_src_to_the_requests_host() {
        assert_eq!(
            csp_directive(&static_csp(Some(TEST_HOST)), "connect-src"),
            "'self' ws://mud.example wss://mud.example"
        );
        // A port is part of the authority the browser dials, so it must
        // survive into the source (compose maps `localhost:8080 -> :3000`,
        // and the browser's own Host is what CSP matches).
        assert_eq!(
            csp_directive(&static_csp(Some("localhost:3000")), "connect-src"),
            "'self' ws://localhost:3000 wss://localhost:3000"
        );
        // IPv6 literals are bracketed; dev against `http://[::1]:3000` must
        // not silently lose its socket.
        assert_eq!(
            csp_directive(&static_csp(Some("[::1]:3000")), "connect-src"),
            "'self' ws://[::1]:3000 wss://[::1]:3000"
        );
        // No Host (HTTP/1.0-style request, or a probe) -> fail closed.
        assert_eq!(
            csp_directive(&static_csp(None), "connect-src"),
            "'self'",
            "without a usable Host the policy must not guess a websocket source"
        );
        for policy in [static_csp(Some(TEST_HOST)), static_csp(None)] {
            assert!(
                !policy.contains("connect-src *") && !policy.contains(":*"),
                "a wildcard connect-src would let a compromised staff page exfiltrate: {policy}"
            );
        }
    }

    /// The host lands inside a header value, so a `Host` that could inject
    /// a source expression -- or a second header -- must be refused, not
    /// sanitised. `ws_authority` is a character allow-list for exactly this
    /// reason; these are the shapes an attacker (or a confused proxy) could
    /// put in the header.
    #[test]
    fn ws_authority_refuses_hosts_that_could_inject_a_source() {
        for hostile in [
            "",
            ":3000",
            "mud.example:",
            "mud.example:port",
            "mud.example:3000:4000",
            "evil.com mud.example",
            "evil.com/",
            "evil.com/\"",
            "evil.com;js=1",
            "u@evil.com",
            "evil.com 'unsafe-eval'",
            "evil.com'",
            "mud.example\r\nx-content-security-policy: default-src *",
            "mud.example\nref",
            "[::1]:",
            "[gg::1]:3000",
            "[..]:3000",
            "[]:3000",
            "mud.example:3000x",
            "\u{00e9}mud.example", // non-ASCII (IDN): `to_str` refuses it, and so must this
        ] {
            assert_eq!(
                ws_authority(Some(hostile)),
                None,
                "must not be usable as a websocket source: {hostile:?}"
            );
            assert!(
                !static_csp(Some(hostile)).contains("wss://"),
                "policy for {hostile:?} leaked a websocket source"
            );
        }
        for good in [
            "mud.example",
            "localhost:3000",
            "127.0.0.1:3000",
            "[::1]",
            "[::1]:3000",
            "mud-2.example",
            "stage.mud.example.",
        ] {
            assert_eq!(ws_authority(Some(good)).unwrap(), good, "refused {good:?}");
        }
    }

    /// A request to the static fallback, with the `Host` a browser would
    /// send. `Request::builder` does not add one implicitly, and the policy
    /// now depends on it.
    fn static_request(path: &str, host: &str) -> axum::extract::Request {
        axum::http::Request::builder()
            .uri(path)
            .header(header::HOST, host)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn static_fallback_sends_nosniff_referrer_policy_and_coop() {
        // M-IDE-1's remaining three headers. `Referrer-Policy` matters
        // because the *path itself* is a domain path (T-IDE-2), and
        // `nosniff` because `/api/v1/files/content` serves raw builder
        // text -- the same reasoning as M-FS-4's per-response headers.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html>loom</html>").unwrap();
        std::fs::write(dir.path().join("admin.html"), "<html>admin</html>").unwrap();
        std::fs::create_dir(dir.path().join("dist")).unwrap();
        std::fs::write(dir.path().join("dist/app.js"), "export {};\n").unwrap();
        let app = app_with_static_root(dir.path());

        for path in ["/", "/admin.html", "/dist/app.js", "/nope.html"] {
            let request = axum::http::Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            for (name, expected) in STATIC_SECURITY_HEADERS {
                let value = response
                    .headers()
                    .get(header::HeaderName::from_static(name))
                    .unwrap_or_else(|| panic!("missing {name} header on {path}"))
                    .to_str()
                    .unwrap();
                assert_eq!(value, expected, "{name} on {path}");
            }
            assert!(
                response
                    .headers()
                    .get(header::CONTENT_SECURITY_POLICY)
                    .is_some(),
                "missing CSP header on {path}"
            );
        }
    }

    /// The sources of one CSP directive, or `"<absent>"`. Matching is on
    /// the whole directive token (splitting on `;` and then on the first
    /// space) rather than `contains`, so `script-src` assertions can't be
    /// satisfied by `worker-src`'s or `style-src`'s source list.
    fn csp_directive(policy: &str, directive: &str) -> String {
        policy
            .split(';')
            .map(str::trim)
            .find_map(|part| {
                let (name, rest) = part.split_once(char::is_whitespace)?;
                (name == directive).then(|| rest.trim().to_owned())
            })
            .unwrap_or_else(|| format!("<{directive} absent>"))
    }

    /// `app` with a `web_root` pointing at `root` (the static-file path
    /// needs one; every other route is left at its default).
    fn app_with_static_root(root: &std::path::Path) -> Router {
        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let state = HttpState::new(
            ws_accept_tx,
            Readiness::new(),
            PrometheusMetrics::new_unregistered(),
        )
        .with_web_root(root.to_path_buf());
        app(state)
    }

    /// A web root with one file of each shape OBI-338 cares about: a
    /// document, an unhashed `tsc` output file, and the vendored Monaco tree
    /// both with and without its version stamp.
    fn cache_web_root() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html>loom</html>").unwrap();
        std::fs::write(dir.path().join("ide.html"), "<html>ide</html>").unwrap();
        std::fs::create_dir_all(dir.path().join("dist").join("ide")).unwrap();
        std::fs::write(
            dir.path().join("dist").join("ide").join("amd-boot.js"),
            "start();",
        )
        .unwrap();
        for vs in ["vendor/monaco/0.57.0/vs", "vendor/monaco/vs"] {
            let loader = dir.path().join(vs);
            std::fs::create_dir_all(&loader).unwrap();
            std::fs::write(loader.join("loader.js"), "/* amd loader */").unwrap();
        }
        dir
    }

    #[test]
    fn only_a_version_stamp_makes_a_vendor_url_immutable() {
        // The gate on `immutable` is structural (see `is_version_stamped_asset`
        // for the rules); these are the shapes that decide the answer, in both
        // directions, including the ones that would *look* versioned.
        let stamped = [
            "/vendor/monaco/0.57.0/vs/loader.js",
            "/vendor/monaco/0.57.0/vs/editor/editor.main.css",
            "/vendor/monaco/0.57.0-beta.1/vs/loader.js",
            "/vendor/loom-mudlib/2026.04.01/area.css",
        ];
        let not_stamped = [
            // What the tree looked like before OBI-338: the same file, one
            // directory shallower, and no promise that the URL moved.
            "/vendor/monaco/vs/loader.js",
            "/vendor/monaco/latest/vs/loader.js",
            // The stamp directory itself, a dot-segment anywhere in the path,
            // an encoded separator, an empty package, a leading double slash,
            // a path that only *contains* the stamp, and everything outside
            // `/vendor/`.
            "/vendor/monaco/0.57.0",
            "/vendor/monaco/0.57.0/",
            "/vendor/monaco/0.57.0/../0.57.0/vs/loader.js",
            "/vendor/monaco/0.57.0/./vs/loader.js",
            "/vendor/monaco/0.57.0/vs%2Floader.js",
            "/vendor//0.57.0/loader.js",
            "//vendor/monaco/0.57.0/vs/loader.js",
            "/assets/vendor/monaco/0.57.0/vs/loader.js",
            "/index.html",
            "/dist/ide/amd-boot.js",
            "/",
        ];
        for path in stamped {
            assert!(is_version_stamped_asset(path), "{path} is stamped");
        }
        for path in not_stamped {
            assert!(
                !is_version_stamped_asset(path),
                "{path} must not be promised immutable"
            );
        }
    }

    #[test]
    fn if_none_match_compares_weakly_and_across_a_list() {
        // RFC 9110 §13.1.2: a recipient MUST use the weak comparison
        // function for `If-None-Match`, so the `W/`
        // prefix a client echoes back must not be what decides the answer --
        // and a candidate list is a comma-separated list of them.
        let ours = "W/\"65e4b3a0-1f\"";
        let cases = [
            (ours, true),
            ("\"65e4b3a0-1f\"", true),
            ("*", true),
            ("W/\"deadbeef-1\", \"65e4b3a0-1f\"", true),
            ("W/\"deadbeef-1\", W/\"cafe-2\"", false),
            ("\"65e4b3a0-1g\"", false),
            ("", false),
        ];
        for (candidate, expected) in cases {
            assert_eq!(
                if_none_match_matches(candidate, ours),
                expected,
                "If-None-Match: {candidate:?} against {ours}"
            );
        }
    }

    /// The request a client holding `if_none_match` would send for `path`.
    fn conditional_get(path: &str, if_none_match: &str) -> axum::extract::Request {
        axum::http::Request::builder()
            .uri(path)
            .header(header::HOST, TEST_HOST)
            .header(header::IF_NONE_MATCH, if_none_match)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn a_stamped_vendor_asset_is_the_only_thing_promised_immutable() {
        let dir = cache_web_root();
        let app = app_with_static_root(dir.path());

        let served = [
            ("/vendor/monaco/0.57.0/vs/loader.js", STATIC_CACHE_IMMUTABLE),
            // The same file at the old, unstamped URL: it is the whole reason
            // the classifier is structural. A year here would be a year of
            // stale Monaco for every builder, with no URL left to change.
            ("/vendor/monaco/vs/loader.js", STATIC_CACHE_REVALIDATE),
            ("/dist/ide/amd-boot.js", STATIC_CACHE_REVALIDATE),
            ("/ide.html", STATIC_CACHE_REVALIDATE),
            ("/", STATIC_CACHE_REVALIDATE),
        ];
        for (path, expected) in served {
            let response = app
                .clone()
                .oneshot(static_request(path, TEST_HOST))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .unwrap_or_else(|| panic!("no Cache-Control on {path}"))
                    .to_str()
                    .unwrap(),
                expected,
                "{path}"
            );
            // OBI-338's other half: the M-IDE-1 header set still rides on a
            // cached response, and `Vary: Host` is there because `connect-src`
            // is derived from the request's `Host` (`static_csp`), so a shared
            // cache keyed on the URL alone could serve one host's policy to
            // another and kill *its* `/ws`.
            assert!(
                response
                    .headers()
                    .get(header::CONTENT_SECURITY_POLICY)
                    .is_some(),
                "the CSP header set must survive caching on {path}"
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::VARY)
                    .unwrap_or_else(|| panic!("no Vary on {path}"))
                    .to_str()
                    .unwrap(),
                "Host",
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn a_conditional_get_on_a_revalidated_asset_answers_304_with_no_body() {
        let dir = cache_web_root();
        let app = app_with_static_root(dir.path());

        let first = app
            .clone()
            .oneshot(static_request("/ide.html", TEST_HOST))
            .await
            .unwrap();
        let etag = first
            .headers()
            .get(header::ETAG)
            .expect("a revalidated asset must carry a validator")
            .to_str()
            .unwrap()
            .to_owned();
        assert!(
            etag.starts_with("W/\"") && etag.ends_with('"'),
            "metadata-derived, so weak (RFC 9110 §8.8.1): {etag}"
        );
        let body = first.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "<html>ide</html>".as_bytes());

        // The revalidation a browser sends on the next load of the page.
        let second = app
            .clone()
            .oneshot(conditional_get("/ide.html", &etag))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
        // A `304` must not carry a payload, nor the headers that describe one
        // (RFC 9110 §15.4.5) -- `ServeDir` put a `Content-Length` and a
        // `Content-Type` in the `200` this replaced, and hyper would be right
        // to reject the mismatch.
        assert!(
            second.headers().get(header::CONTENT_LENGTH).is_none(),
            "no payload, no Content-Length"
        );
        assert!(
            second.headers().get(header::CONTENT_TYPE).is_none(),
            "a 304 must not repeat payload headers"
        );
        // ...but everything that decides *whether* to revalidate, and the
        // policy the stored entry is kept under, still rides along: a `304`
        // replaces the headers of the cached response.
        assert_eq!(
            second
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok())
                .unwrap(),
            STATIC_CACHE_REVALIDATE
        );
        assert_eq!(
            second
                .headers()
                .get(header::ETAG)
                .unwrap()
                .to_str()
                .unwrap(),
            etag
        );
        assert_eq!(
            second
                .headers()
                .get(header::VARY)
                .unwrap()
                .to_str()
                .unwrap(),
            "Host"
        );
        assert!(
            second
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .is_some(),
            "M-IDE-1's policy must not be the thing a 304 loses"
        );
        assert_eq!(
            second.into_body().collect().await.unwrap().to_bytes().len(),
            0
        );

        // A candidate list, ours second: weak comparison across the list.
        let list = format!("W/\"deadbeef-1\", {etag}");
        let third = app
            .clone()
            .oneshot(conditional_get("/ide.html", &list))
            .await
            .unwrap();
        assert_eq!(third.status(), StatusCode::NOT_MODIFIED);
        // `*` is the other thing a client may send.
        let any = app
            .oneshot(conditional_get("/ide.html", "*"))
            .await
            .unwrap();
        assert_eq!(any.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn a_validator_that_does_not_match_streams_the_file() {
        let dir = cache_web_root();
        let app = app_with_static_root(dir.path());
        let request = axum::http::Request::builder()
            .uri("/dist/ide/amd-boot.js")
            .header(header::HOST, TEST_HOST)
            .header(header::IF_NONE_MATCH, "W/\"0-0\"")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "start();".as_bytes());
    }

    #[tokio::test]
    async fn the_validator_moves_when_the_bytes_move() {
        // The promise behind `max-age=0, must-revalidate` is that a
        // revalidation notices a rebuild, so pin that the validator is not
        // constant per URL. The rewrite is a different length *and* a later
        // mtime, so this does not depend on the filesystem's clock granularity
        // -- the assertion is that the two differ, not what either one is.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("dist")).unwrap();
        let file = dir.path().join("dist").join("app.js");
        std::fs::write(&file, "v1").unwrap();
        let app = app_with_static_root(dir.path());

        let first = app
            .clone()
            .oneshot(static_request("/dist/app.js", TEST_HOST))
            .await
            .unwrap();
        let before = first
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        std::fs::write(&file, "v2 is longer").unwrap();
        let second = app
            .oneshot(static_request("/dist/app.js", TEST_HOST))
            .await
            .unwrap();
        let after = second
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert_ne!(before, after, "a rebuild must not keep the old validator");
        assert_eq!(second.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_miss_says_nothing_about_freshness() {
        // A `404` for a stamped URL must not be cached: the file may exist in
        // the next image, and a client that cached the miss for a year would
        // never learn about it. The CSP stamp stays (M-IDE-1's reasoning about
        // 404s is unchanged); only the cache directives are withheld.
        let dir = cache_web_root();
        let app = app_with_static_root(dir.path());
        let response = app
            .clone()
            .oneshot(static_request(
                "/vendor/monaco/0.58.0/vs/loader.js",
                TEST_HOST,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.headers().get(header::CACHE_CONTROL).is_none());
        assert!(response.headers().get(header::ETAG).is_none());
        assert!(response.headers().get(header::VARY).is_none());
        assert!(
            response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .is_some(),
            "the security layer is independent of caching"
        );
    }

    #[tokio::test]
    async fn explicit_routes_keep_their_own_response_headers() {
        // The cache layer wraps the `ServeDir` fallback only -- `/healthz` and
        // `/metrics` must not pick up `immutable`, a validator, or a `Vary`.
        let dir = cache_web_root();
        let app = app_with_static_root(dir.path());
        for path in ["/healthz", "/metrics"] {
            let response = app
                .clone()
                .oneshot(static_request(path, TEST_HOST))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            for name in [
                header::CACHE_CONTROL,
                header::ETAG,
                header::VARY,
                header::CONTENT_SECURITY_POLICY,
            ] {
                assert!(
                    response.headers().get(&name).is_none(),
                    "{path} must be untouched by the static layer, but carried {}",
                    name.as_str()
                );
            }
        }
    }
}
