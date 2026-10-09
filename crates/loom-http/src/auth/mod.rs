// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Staff web auth (OBI-174, design §9/D-P2.5): JWT access + refresh tokens,
//! TOTP enrolment/verification (mandatory for T3+), and an optional
//! GitHub-login path that only ever authenticates an *already-linked*
//! staff uid.
//!
//! ## The tier always comes from Postgres
//!
//! [`StaffDirectory::auth_status_for`] is the *only* source of truth for a
//! staff uid's tier. [`AuthService::issue_tokens`] -- the single place
//! shared by the password and GitHub login paths (a refresh goes through
//! [`AuthService::refresh`]/[`AuthService::mint_access_token`] instead,
//! since it must carry an existing session family forward rather than
//! minting a fresh one) -- is always fed a status read fresh just
//! beforehand: an access token's `tier`/`scopes` claims are a snapshot
//! taken at issue time, never a value the client (or an upstream IdP) can
//! set, and a promotion or demotion always takes effect at the access
//! token's next refresh, which can be forced by revoking the caller's
//! sessions (see OBI-198's `staff_sessions` revoke triggers, or
//! [`AuthService::logout`] for a single family). A uid with *no* `staff`
//! row at all (e.g. removed staff) is refused outright rather than minting
//! a tier-0 token (OBI-195 review fix 5).
//!
//! ## TOTP is mandatory for T3+, at issue and at refresh
//!
//! [`AuthService::login`]/[`AuthService::github_login`] refuse a
//! tier-3-or-above staff member's session with [`AuthError::TotpRequired`]
//! unless their TOTP secret is both enrolled *and* confirmed (see
//! `staff.totp_confirmed_at` in migration 0003) and a correct `totp_code`
//! is supplied (OBI-195 review fix 2: the first cut of this PR only gated
//! the password path, which meant a T3+ uid promoted after an earlier,
//! sub-T3 login could keep refreshing T3+ tokens forever, and GitHub login
//! skipped the gate entirely). There is no bypass: a T3+ row with no
//! confirmed secret cannot get a session, only enrol one (via
//! [`AuthService::totp_enroll`]/[`AuthService::totp_confirm`], which
//! themselves require a password login having already succeeded up to the
//! TOTP gate -- see `handlers.rs`). Every accepted code also consumes its
//! RFC 6238 time-step via [`StaffDirectory::totp_consume_step`], so the
//! same code can never be replayed even within the skew window (OBI-195
//! review fix 4).
//!
//! [`AuthService::refresh`] enforces the *same* mandatory-TOTP floor, but
//! against state rather than a fresh code (OBI-197/OBI-198 follow-up to
//! OBI-195 review fix 2): the refresh token travels only as an HttpOnly
//! cookie (OBI-198), which cannot carry a TOTP code, and step-up freshness
//! is `mfa_at`'s job (M-ADM-2), not every refresh's. A refresh for a T3+
//! uid is refused if there is no staff row, if TOTP isn't confirmed, or if
//! the token family's `amr` (fixed at login, never recomputed by a
//! refresh -- see [`Self::issue_tokens`]) doesn't contain `"otp"`; any of
//! those refusals revokes the whole family.
//!
//! ## GitHub login never creates staff
//!
//! [`AuthService::github_login`] looks up the numeric GitHub user id in
//! `github_identities` (populated only by an arch/root through
//! `Persist::github_link`, T4+). An unlinked id is refused outright --
//! this module has no code path that inserts a `staff` row.
//!
//! ## Rate limiting, lockout, and audit (OBI-200, OBI-204)
//!
//! [`AuthService::login`]/[`AuthService::totp_confirm`] share one
//! [`RateLimiter`] (see that module's docs for the exact numbers): a
//! wrong password or wrong TOTP code counts as a failure toward both a
//! per-account lockout and a per-IP token bucket, and a locked account
//! gets exactly the same response as a wrong password. Both entry points
//! key the account lockout by the same resolved staff uid (OBI-204), so
//! splitting guesses across `login` and `totp_confirm` can't double an
//! attacker's effective budget. Every login,
//! refresh-reuse, and TOTP enrol/reset is appended to `audit_log` via
//! [`StaffDirectory::record_audit`] (M-AUTH-9); see
//! `docs/threat-model-phase2.md` §6.1 (M-AUTH-1, M-AUTH-2, M-AUTH-9).

mod claims;
mod cookie;
mod directory;
mod github;
pub mod jwt;
pub mod ratelimit;
mod statetoken;
mod totp;
mod wsticket;

pub use claims::{AccessClaims, GITHUB_PENDING_PURPOSE, GithubPendingClaims, scopes_for_tier};
pub use cookie::{
    REFRESH_COOKIE_NAME, STAFF_AUTH_HEADER, clear_cookie_header, refresh_token_from_cookies,
    set_cookie_header, set_cookie_name, staff_csrf_guard_passes,
};
pub use directory::{
    AdminAuditEntry, AdminDirectoryError, AuditEvent, DirectoryError, RefreshRecord,
    SessionRotateOutcome, StaffAuthRecord, StaffAuthStatus, StaffDirectory,
};
pub use github::{
    GithubAuthError, GithubIdentityProvider, GithubLoginConfig, GithubOAuthConfig, GithubUser,
    LiveGithubProvider, OAUTH_STATE_PURPOSE, OAuthStateClaims, PkcePair, generate_pkce,
    generate_state,
};
pub use jwt::{AUDIENCE, JwtKeys, TokenPair};
pub use ratelimit::{RateLimitDecision, RateLimiter};
#[cfg(test)]
pub use statetoken::StateTokenKey;
pub use totp::{
    TotpEnrollment, generate_totp_secret, totp_for_secret, totp_step_for_code, verify_totp_code,
};
pub use wsticket::{WsTicketError, WsTicketIdentity};

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tracing::warn;

/// Everything a login/refresh/TOTP attempt carries about *who's asking*,
/// for the rate limiter (M-AUTH-1) and the audit trail (M-AUTH-9) --
/// never for an authorization decision (that's still `sub`/tier, read
/// fresh from the directory). `ip` is `None` only in tests or if
/// `loom-http`'s client-IP resolution ([`crate::client_ip`]) truly has
/// nothing to fall back to.
#[derive(Debug, Clone, Default)]
pub struct AuthContext {
    pub ip: Option<IpAddr>,
    pub user_agent: Option<String>,
}

impl AuthContext {
    pub fn new(ip: Option<IpAddr>, user_agent: Option<String>) -> Self {
        Self { ip, user_agent }
    }
}

/// Access tokens are short-lived: a promotion/demotion or a TOTP
/// requirement change is at most this stale before a refresh picks it up.
pub const ACCESS_TOKEN_TTL: Duration = Duration::from_secs(10 * 60);
/// Sessions are long-lived but revocable and rotated on every refresh.
/// Design §9/D-TM2: 14 days absolute.
pub const REFRESH_TOKEN_TTL: Duration = Duration::from_secs(14 * 24 * 60 * 60);
/// A session not used (rotated) for this long is treated as expired even
/// if its absolute `expires_at` has not passed yet (OBI-198, M-AUTH-5:
/// "24h idle").
pub const IDLE_SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Tiers at or above this one must have a confirmed TOTP secret to obtain a
/// session (design §9/D-P2.5: "mandatory for T3+").
pub const MANDATORY_TOTP_TIER: i16 = 3;
/// A GitHub-login-pending-TOTP token (OBI-201) is a narrow, single-use
/// credential: it only ever proves "GitHub's authorization-code exchange
/// already resolved to this numeric github_id", not "this uid is signed
/// in". Kept short so a leaked one is cheap to wait out.
pub const GITHUB_PENDING_TTL: Duration = Duration::from_secs(5 * 60);
/// How long a GitHub OAuth `state`/PKCE-verifier cookie is good for
/// (OBI-201, M-AUTH-7) -- long enough for a human to authorize on GitHub,
/// short enough that a captured cookie isn't useful for long.
pub const OAUTH_STATE_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Bad username/password, or (for GitHub) an unlinked identity, or a
    /// uid with no `staff` row at all (removed staff -- OBI-195 review
    /// fix 5).
    InvalidCredentials,
    /// Correct password, but the account needs a TOTP code and none (or an
    /// incorrect one) was supplied -- or, on refresh, the account's tier
    /// now requires TOTP and the session family never completed it.
    TotpRequired,
    /// Correct password and tier is below the mandatory-TOTP floor, but the
    /// account somehow has no *confirmed* TOTP secret even though one was
    /// supplied/expected -- surfaced separately from `TotpRequired` so
    /// callers can tell "you didn't send a code" apart from "your code was
    /// wrong" (this also covers a replayed/already-consumed step: RFC
    /// 6238-valid but refused, OBI-195 review fix 4).
    TotpInvalid,
    /// `totp_enroll` refused: the uid already has a *confirmed* secret.
    /// Overwriting one from nothing but a bearer token would let a stolen
    /// access token downgrade a T3+ account's second factor (OBI-195
    /// review fix 3) -- a real reset needs a dedicated, step-up-gated flow
    /// (tracked as a follow-up, OBI-199).
    TotpAlreadyEnrolled,
    /// The refresh token is unknown, expired, or already revoked.
    InvalidRefreshToken,
    /// The backing directory (Postgres) failed.
    DirectoryUnavailable,
    /// A D-TM4 WebSocket ticket (`/lsp`'s first frame) was malformed,
    /// unsigned, expired, or already redeemed once before.
    InvalidWsTicket,
    /// The per-IP token bucket is empty (M-AUTH-1). Distinct from
    /// [`AuthError::InvalidCredentials`] -- unlike an account lockout,
    /// which must look exactly like a wrong password, an IP-level
    /// throttle is not account-specific and doesn't leak anything about
    /// a particular username.
    RateLimited,
    /// The GitHub-login-pending-TOTP token is unknown, expired, malformed,
    /// or was issued for a different purpose (OBI-201).
    InvalidPendingToken,
    /// The OAuth `state` cookie is missing, expired, malformed, signed for
    /// a different purpose, or doesn't match the `state` GitHub echoed
    /// back (OBI-201, M-AUTH-7).
    InvalidOAuthState,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AuthError::InvalidCredentials => "invalid credentials",
            AuthError::TotpRequired => "totp code required",
            AuthError::TotpInvalid => "totp code invalid",
            AuthError::TotpAlreadyEnrolled => "totp already enrolled",
            AuthError::InvalidRefreshToken => "invalid refresh token",
            AuthError::DirectoryUnavailable => "directory unavailable",
            AuthError::RateLimited => "rate limited",
            AuthError::InvalidPendingToken => "invalid pending token",
            AuthError::InvalidOAuthState => "invalid oauth state",
            AuthError::InvalidWsTicket => "invalid ws ticket",
        };
        f.write_str(s)
    }
}

impl std::error::Error for AuthError {}

/// Tier floor for role-change actions (M-ADM-2/§5.11.2): a domain lead
/// (T3) may act (within `roles_set_tier`'s own, narrower SQL rules), but
/// nothing below that.
pub const ADMIN_ROLE_CHANGE_MIN_TIER: i16 = 3;
/// Tier floor to list objects at all (OBI-234, P2-O2 scope: "T3+ to list
/// at all"). The actual *filtering* within that is `valid_read`, done on
/// the world side -- this is just the HTTP edge's cheap floor, same role
/// as [`ADMIN_ROLE_CHANGE_MIN_TIER`] for role changes (UX, not the
/// security boundary).
pub const OBJECT_LIST_MIN_TIER: i16 = 3;
/// Tier floor for `GET /api/v1/admin/who` (OBI-234, CTO review on PR
/// #98): the scope note doesn't set a floor for `who`, only M-ADM-3's
/// response-shape rule. T2+ (not T1/builder) is the explicit, more
/// conservative default the review asked for -- a plain builder token
/// can no longer enumerate every connected account.
pub const WHO_MIN_TIER: i16 = 2;
/// Tier floor for `GET /api/v1/admin/objects/:path/vars` (OBI-234 scope:
/// "T4, audited per access").
pub const OBJECT_VARS_MIN_TIER: i16 = 4;
/// Additional tier floor for variable inspection of anything under
/// `/secure/` (OBI-234 scope: "`/secure` objects T5 only") -- on top of,
/// not instead of, [`OBJECT_VARS_MIN_TIER`].
pub const SECURE_VARS_MIN_TIER: i16 = 5;
/// Tier floor for `GET /api/v1/admin/errors` (OBI-235 scope: "T3+,
/// consistent with object listing"). As with [`OBJECT_LIST_MIN_TIER`],
/// the real per-program filter (`valid_read`) and the `/secure`
/// redaction rule both live on the world side (`errors` efun /
/// `crate::admin_query::WorldAdminQuery::errors`); this is only the HTTP
/// edge's cheap floor.
pub const ERROR_INBOX_MIN_TIER: i16 = 3;
/// Tier floor for the server-wide staff broadcast (OBI-233, M-ADM-2):
/// strictly higher than role changes -- a domain lead (T3) can promote
/// within their own narrower SQL rules, but every connected session
/// seeing a message is a bigger blast radius, so this wants an
/// arch/root-equivalent tier.
pub const ADMIN_BROADCAST_MIN_TIER: i16 = 4;
/// Step-up MFA freshness window for role changes, grants, another user's
/// TOTP reset, and broadcast (M-ADM-2): `mfa_at` must be within this many
/// seconds of "now".
pub const STEP_UP_WINDOW_SECS: i64 = 5 * 60;
/// Hard cap on a broadcast body, in bytes (OBI-233, M-ADM-5): measured
/// *before* sanitization, on the UTF-8 byte length of the request's
/// `text` field.
pub const BROADCAST_MAX_BYTES: usize = 1024;
/// Driver-fixed prefix (CTO review, OBI-233) prepended to every line of
/// a broadcast, so a player can tell a staff broadcast apart from
/// ordinary game output. Never caller-configurable -- the request body
/// has no field for it, and [`sanitize_broadcast_text`]'s output never
/// contains it either, so there's no way for broadcast text to forge
/// this marker.
pub const BROADCAST_PREFIX: &str = "[Broadcast] ";

/// A failure from one of the admin (OBI-185) actions on [`AuthService`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminError {
    /// The caller's tier is below the action's floor (M-ADM-2:
    /// tier >= 3 for role changes).
    Forbidden,
    /// The caller's tier is high enough, but their session has no
    /// `mfa_at` within the last 5 minutes (M-ADM-2 step-up).
    StepUpRequired,
    /// The request body carried a client-supplied `actor`, or otherwise
    /// failed input validation -- M-ADM-1: the actor is always the
    /// token's `sub`, never anything the body can override.
    BadRequest,
    /// The `security definer` function itself refused the call (M-ADM-1:
    /// e.g. self-promotion, actor tier too low for *this* target, tier
    /// outside the Phase-1 1-3 range). The admin UI's own tier/step-up
    /// checks above are UX, not the security boundary -- this is what
    /// actually enforces it, and this variant is reachable even if every
    /// check above it were removed.
    Rejected(String),
    /// The directory (Postgres) failed outright.
    DirectoryUnavailable,
    /// The world-thread query channel failed outright (busy, timed out,
    /// or closed -- see `admin_query::WorldQueryError`): distinct from
    /// [`AdminError::DirectoryUnavailable`] since this is a different
    /// backend (the live world, not Postgres).
    WorldUnavailable,
    /// `object_vars` for a path that isn't a live object (or that
    /// `valid_read` refused -- the two are indistinguishable on purpose,
    /// see [`crate::admin_query::WorldAdminQuery::object_vars`]'s doc
    /// comment).
    NotFound,
    /// The broadcast body was over [`BROADCAST_MAX_BYTES`] (M-ADM-5).
    BodyTooLarge,
}

impl From<AdminDirectoryError> for AdminError {
    fn from(err: AdminDirectoryError) -> Self {
        match err {
            AdminDirectoryError::Rejected(message) => AdminError::Rejected(message),
            AdminDirectoryError::Unavailable => AdminError::DirectoryUnavailable,
        }
    }
}

/// The world-error -> HTTP-status contract, in one place (OBI-347): the
/// world's answer decides the status, and nothing here invents a `500`. A name
/// that resolves to nothing is the caller's mistake (`404`); a world that could
/// not answer is unavailable (`503`), not broken. Pinned by
/// `crate::admin::tests::object_vars_for_a_path_that_is_not_live_is_404_not_500`,
/// `a_world_that_could_not_answer_is_503_not_500`, and
/// `no_admin_error_variant_answers_500` -- the last is exhaustive over
/// `AdminError`, so answering `500` somewhere requires adding a variant and
/// arguing which class of failure it is.
impl From<crate::admin_query::WorldQueryError> for AdminError {
    fn from(err: crate::admin_query::WorldQueryError) -> Self {
        use crate::admin_query::WorldQueryError;
        match err {
            WorldQueryError::NotFound => AdminError::NotFound,
            WorldQueryError::Busy | WorldQueryError::Timeout | WorldQueryError::Closed => {
                AdminError::WorldUnavailable
            }
            // OBI-279: a `valid_read` that failed to produce a real
            // decision is a different failure than a `Busy`/`Timeout`/
            // `Closed` channel, but the HTTP-visible outcome (`503`) is
            // the same -- both mean "the world side could not safely
            // answer this query right now".
            WorldQueryError::Internal(_) => AdminError::WorldUnavailable,
        }
    }
}

impl From<DirectoryError> for AuthError {
    fn from(_: DirectoryError) -> Self {
        AuthError::DirectoryUnavailable
    }
}

/// Everything [`AuthService::login`]/[`AuthService::refresh`]/
/// [`AuthService::github_login`] need: the staff directory, the JWT
/// signing keys, the TTLs (fixed to the module constants above, exposed as
/// fields only so tests can shrink them), and the rate limiter (OBI-200).
#[derive(Clone)]
pub struct AuthService {
    directory: Arc<dyn StaffDirectory>,
    keys: JwtKeys,
    access_ttl: Duration,
    refresh_ttl: Duration,
    idle_ttl: Duration,
    rate_limiter: Arc<RateLimiter>,
    /// Signs/verifies the GitHub OAuth state cookie and the pending-TOTP
    /// cookie (OBI-201) -- a signing domain entirely separate from
    /// `keys` (must-fix 2, PR #78 CTO review): see `statetoken`'s module
    /// doc for why. Generated fresh per process; never the same key
    /// across a restart.
    state_key: statetoken::StateTokenKey,
    /// D-TM4's single-use `/lsp` WebSocket ticket (OBI-180): its own
    /// signing domain and its own (small, TTL-swept) used-ticket set,
    /// kept separate from `state_key` even though both are
    /// `StateTokenKey`-shaped, since a ticket needs single-use tracking
    /// the OAuth-state/pending-TOTP tokens don't.
    ws_tickets: Arc<wsticket::WsTicketIssuer>,
}

impl AuthService {
    pub fn new(directory: Arc<dyn StaffDirectory>, keys: JwtKeys) -> Self {
        Self {
            directory,
            keys,
            access_ttl: ACCESS_TOKEN_TTL,
            refresh_ttl: REFRESH_TOKEN_TTL,
            idle_ttl: IDLE_SESSION_TTL,
            rate_limiter: Arc::new(RateLimiter::new()),
            state_key: statetoken::StateTokenKey::generate(),
            ws_tickets: Arc::new(wsticket::WsTicketIssuer::new()),
        }
    }

    /// Shrink the TTLs for a deterministic test (e.g. a 1-nanosecond-ish
    /// access TTL to exercise expiry without sleeping real minutes).
    #[cfg(test)]
    pub fn with_ttls(mut self, access_ttl: Duration, refresh_ttl: Duration) -> Self {
        self.access_ttl = access_ttl;
        self.refresh_ttl = refresh_ttl;
        self
    }

    /// Shrink the idle-session TTL for a deterministic test (OBI-198,
    /// M-AUTH-5: "24h idle" is too long to sleep through in a unit test).
    #[cfg(test)]
    pub fn with_idle_ttl(mut self, idle_ttl: Duration) -> Self {
        self.idle_ttl = idle_ttl;
        self
    }

    /// Swap in a rate limiter with shrunk windows for a deterministic
    /// test (OBI-200).
    #[cfg(test)]
    pub fn with_rate_limiter(mut self, rate_limiter: RateLimiter) -> Self {
        self.rate_limiter = Arc::new(rate_limiter);
        self
    }

    /// Username/password login (design §9). Refuses with
    /// [`AuthError::TotpRequired`]/[`AuthError::TotpInvalid`] for a T3+
    /// staff member unless `totp_code` verifies against their confirmed
    /// secret -- the only path, together with [`Self::github_login`],
    /// that gates on a *code*; [`Self::refresh`] gates on state instead
    /// (see the module docs).
    ///
    /// Rate limiting (OBI-200, M-AUTH-1): checked *before* any
    /// credential work. A throttled IP gets [`AuthError::RateLimited`]. A
    /// locked account gets exactly [`AuthError::InvalidCredentials`] --
    /// the same response as a wrong password, so a client can never tell
    /// "this account is locked" from "that password is wrong" (which
    /// would otherwise leak account existence/activity). A wrong
    /// password or a wrong TOTP code both count as a failure toward the
    /// account lockout; a *missing* TOTP code does not (it isn't a
    /// guess). Every outcome is audited (M-AUTH-9).
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        totp_code: Option<&str>,
        ctx: &AuthContext,
    ) -> Result<TokenPair, AuthError> {
        // OBI-204 review fix: check the (cheap, no-DB) IP bucket before
        // paying for the `resolve_uid` lookup below, so a throttled IP is
        // refused without ever touching Postgres.
        if let Some(ip) = ctx.ip
            && self.rate_limiter.check_ip(ip) == RateLimitDecision::IpThrottled
        {
            self.audit(
                "auth.login.fail",
                None,
                ctx,
                "deny",
                Some("ip_rate_limited".to_string()),
            )
            .await;
            return Err(AuthError::RateLimited);
        }

        // OBI-204: resolve the account limiter key to the staff uid up
        // front (no password check involved -- this is a plain lookup),
        // the same namespace `totp_confirm` uses, so a wrong login
        // password and a wrong TOTP code for the same staff member always
        // land on the same bucket. A username that doesn't resolve (wrong
        // username, or the directory itself is unavailable) falls back to
        // a username-namespaced key -- there is no uid to share, and that
        // namespace can never collide with a real `uid:` key.
        let resolved_uid = self.directory.resolve_uid(username).await.unwrap_or(None);
        let account_key = account_rate_key(resolved_uid.as_deref(), username);

        match self.rate_limiter.check_account(&account_key) {
            RateLimitDecision::AccountLocked => {
                self.audit(
                    "auth.login.fail",
                    None,
                    ctx,
                    "deny",
                    Some("account_locked".to_string()),
                )
                .await;
                return Err(AuthError::InvalidCredentials);
            }
            RateLimitDecision::Allowed => {}
            RateLimitDecision::IpThrottled => {
                unreachable!("check_account never checks the IP bucket")
            }
        }

        let record = match self.directory.staff_login(username, password).await {
            Ok(Some(record)) => record,
            Ok(None) => {
                self.rate_limiter.record_failure(&account_key);
                self.audit(
                    "auth.login.fail",
                    None,
                    ctx,
                    "deny",
                    Some("invalid_credentials".to_string()),
                )
                .await;
                return Err(AuthError::InvalidCredentials);
            }
            Err(err) => {
                // Neither a guess nor a success -- give the reservation
                // back rather than let it sit as a phantom failure.
                self.rate_limiter.release(&account_key);
                return Err(err.into());
            }
        };

        // Re-read tier/TOTP state fresh rather than trusting `record`,
        // which could in principle be a moment stale, and so that a
        // removed staff row (OBI-195 review fix 5) is refused here too.
        let status = match self.require_staff_status(&record.uid).await {
            Ok(status) => status,
            Err(err) => {
                // Not a guess (directory error or removed staff row):
                // give the reservation back (OBI-204).
                self.rate_limiter.release(&account_key);
                self.audit(
                    "auth.login.fail",
                    Some(record.uid.clone()),
                    ctx,
                    "deny",
                    Some(totp_gate_detail(&err).to_string()),
                )
                .await;
                return Err(err);
            }
        };

        let totp_verified = match self
            .enforce_totp_gate_with_code(
                &record.uid,
                status.tier,
                status.totp_secret.as_deref(),
                status.totp_confirmed,
                totp_code,
            )
            .await
        {
            Ok(verified) => verified,
            Err(err) => {
                if err == AuthError::TotpInvalid {
                    self.rate_limiter.record_failure(&account_key);
                } else {
                    // TotpRequired (or any other non-guess outcome): not
                    // a guess, give the reservation back rather than
                    // count it toward the lockout.
                    self.rate_limiter.release(&account_key);
                }
                self.audit(
                    "auth.login.fail",
                    Some(record.uid.clone()),
                    ctx,
                    "deny",
                    Some(totp_gate_detail(&err).to_string()),
                )
                .await;
                return Err(err);
            }
        };
        let (amr, mfa_at) = if totp_verified {
            (vec!["pwd".to_string(), "otp".to_string()], Some(now()))
        } else {
            (vec!["pwd".to_string()], None)
        };

        self.rate_limiter.record_success(&account_key);
        let pair = self
            .issue_tokens(&record.uid, status.tier, generate_sid(), amr, mfa_at)
            .await?;
        self.audit(
            "auth.login.ok",
            Some(record.uid.clone()),
            ctx,
            "allow",
            None,
        )
        .await;
        Ok(pair)
    }

    /// GitHub login (design §9, M-AUTH-7): `github_id` is the numeric id
    /// the caller already obtained from the real OAuth2 + PKCE exchange
    /// (see [`GithubIdentityProvider`]/`crate::handlers`) -- this function
    /// never talks to GitHub itself, it only resolves the link. An
    /// unlinked id is always refused; this never creates a staff row.
    ///
    /// `totp_code` is required for a T3+ uid exactly like the password
    /// path (OBI-195 review fix 2): linking a GitHub identity to a T3+ uid
    /// is itself a T4+ action (`auth_github_link`), but that only vouches
    /// for the *link*, not for a second factor on *this* login -- a GitHub
    /// account takeover must not bypass the mandatory-TOTP floor just
    /// because an arch linked it once.
    ///
    /// Shares the password path's rate limiter and audit trail (OBI-206:
    /// GitHub login previously bypassed both, so a compromised GitHub
    /// account -- or a stolen/forged authorization code -- could brute
    /// force TOTP codes through repeated callbacks with no lockout and no
    /// record). The limiter key is `github:{github_id}` rather than a
    /// uid: the id is known before the link is resolved, so a flood of
    /// bogus/unlinked ids is throttled too, not just guesses against a
    /// linked account.
    pub async fn github_login(
        &self,
        github_id: i64,
        totp_code: Option<&str>,
        ctx: &AuthContext,
    ) -> Result<TokenPair, AuthError> {
        let rate_limit_key = format!("github:{github_id}");
        match self.rate_limiter.check(&rate_limit_key, ctx.ip) {
            RateLimitDecision::IpThrottled => {
                self.audit(
                    "auth.login.fail",
                    None,
                    ctx,
                    "deny",
                    Some("ip_rate_limited".to_string()),
                )
                .await;
                return Err(AuthError::RateLimited);
            }
            RateLimitDecision::AccountLocked => {
                self.audit(
                    "auth.login.fail",
                    None,
                    ctx,
                    "deny",
                    Some("account_locked".to_string()),
                )
                .await;
                return Err(AuthError::InvalidCredentials);
            }
            RateLimitDecision::Allowed => {}
        }

        let uid = match self.directory.github_lookup(github_id).await {
            Ok(Some(uid)) => uid,
            Ok(None) => {
                self.rate_limiter.record_failure(&rate_limit_key);
                self.audit(
                    "auth.login.fail",
                    None,
                    ctx,
                    "deny",
                    Some("github_unlinked".to_string()),
                )
                .await;
                return Err(AuthError::InvalidCredentials);
            }
            Err(err) => return Err(err.into()),
        };

        let status = match self.require_staff_status(&uid).await {
            Ok(status) => status,
            Err(err) => {
                self.rate_limiter.release(&rate_limit_key);
                self.audit(
                    "auth.login.fail",
                    Some(uid.clone()),
                    ctx,
                    "deny",
                    Some(totp_gate_detail(&err).to_string()),
                )
                .await;
                return Err(err);
            }
        };

        let totp_verified = match self
            .enforce_totp_gate_with_code(
                &uid,
                status.tier,
                status.totp_secret.as_deref(),
                status.totp_confirmed,
                totp_code,
            )
            .await
        {
            Ok(verified) => verified,
            Err(err) => {
                if err == AuthError::TotpInvalid {
                    self.rate_limiter.record_failure(&rate_limit_key);
                } else {
                    self.rate_limiter.release(&rate_limit_key);
                }
                self.audit(
                    "auth.login.fail",
                    Some(uid.clone()),
                    ctx,
                    "deny",
                    Some(totp_gate_detail(&err).to_string()),
                )
                .await;
                return Err(err);
            }
        };
        let (amr, mfa_at) = if totp_verified {
            (vec!["github".to_string(), "otp".to_string()], Some(now()))
        } else {
            (vec!["github".to_string()], None)
        };

        self.rate_limiter.record_success(&rate_limit_key);
        let pair = self
            .issue_tokens(&uid, status.tier, generate_sid(), amr, mfa_at)
            .await?;
        self.audit("auth.login.ok", Some(uid.clone()), ctx, "allow", None)
            .await;
        Ok(pair)
    }

    /// Mint a short-lived, single-purpose token asserting "GitHub's
    /// authorization-code exchange already resolved to this numeric
    /// `github_id`" (OBI-201), for `crate::handlers::github_callback` to
    /// carry in the pending-TOTP cookie when [`Self::github_login`]
    /// refuses with [`AuthError::TotpRequired`]: the authorization code is
    /// single-use and already spent by that point, so the client can't
    /// just redo the OAuth dance with a `totp_code` attached -- it
    /// redeems this token instead, via [`Self::github_login_with_pending`].
    /// Signed with [`Self::state_key`] (`statetoken::StateTokenKey`), not
    /// the staff access-token keyset (must-fix 2, PR #78 CTO review).
    pub fn issue_github_pending(&self, github_id: i64) -> Result<String, AuthError> {
        let issued_at = now();
        let claims = GithubPendingClaims {
            github_id,
            purpose: GITHUB_PENDING_PURPOSE.to_string(),
            iat: issued_at.unix_timestamp(),
            exp: (issued_at + GITHUB_PENDING_TTL).unix_timestamp(),
        };
        self.state_key
            .encode(&claims)
            .map_err(|_| AuthError::DirectoryUnavailable)
    }

    /// Redeem a [`Self::issue_github_pending`] token plus a TOTP code,
    /// completing a GitHub login that stopped at the TOTP gate. Resolves
    /// the link fresh (same as [`Self::github_login`] would), rather than
    /// trusting a uid baked into the pending token, so a link revoked in
    /// the interim is honoured.
    pub async fn github_login_with_pending(
        &self,
        pending_token: &str,
        totp_code: Option<&str>,
        ctx: &AuthContext,
    ) -> Result<TokenPair, AuthError> {
        let claims: GithubPendingClaims = self
            .state_key
            .decode(pending_token)
            .map_err(|_| AuthError::InvalidPendingToken)?;
        if claims.purpose != GITHUB_PENDING_PURPOSE {
            return Err(AuthError::InvalidPendingToken);
        }
        self.github_login(claims.github_id, totp_code, ctx).await
    }

    /// Sign an [`OAuthStateClaims`] bundle for the `__Host-` state cookie
    /// (OBI-201, M-AUTH-7). Used by `crate::handlers::github_start`.
    pub fn sign_oauth_state(&self, claims: &OAuthStateClaims) -> Result<String, AuthError> {
        self.state_key
            .encode(claims)
            .map_err(|_| AuthError::DirectoryUnavailable)
    }

    /// Verify and decode the `__Host-` state cookie (OBI-201, M-AUTH-7).
    /// Refuses an expired cookie, a bad signature, or one signed for a
    /// different purpose -- used by `crate::handlers::github_callback`
    /// before it trusts anything in the cookie (the PKCE verifier
    /// especially).
    pub fn verify_oauth_state(&self, cookie_value: &str) -> Result<OAuthStateClaims, AuthError> {
        let claims: OAuthStateClaims = self
            .state_key
            .decode(cookie_value)
            .map_err(|_| AuthError::InvalidOAuthState)?;
        if claims.purpose != OAUTH_STATE_PURPOSE {
            return Err(AuthError::InvalidOAuthState);
        }
        Ok(claims)
    }

    /// Rotate a session: the presented refresh token must be unexpired
    /// (both absolute, 14 days from login, and idle, 24h since last
    /// rotation) and unrevoked, else [`AuthError::InvalidRefreshToken`].
    /// On success the old token is revoked and a new (access, refresh)
    /// pair is issued in the *same session family* -- atomically, via
    /// [`loom_persist::Persist::session_rotate`] (OBI-198 re-review,
    /// must-fix 1/2; supersedes the OBI-195 `refresh_token_rotate`
    /// design, OBI-216) -- with `tier`/`scopes` read fresh from Postgres
    /// (never carried over from whatever the old access token claimed)
    /// and `sid`/`amr`/`mfa_at` carried forward unchanged from the
    /// consumed row, same as `expires_at` (must-fix 1: the absolute cap
    /// is fixed at login, never extended by a later rotation).
    ///
    /// The mandatory-TOTP floor is enforced here too (OBI-195 review fix
    /// 2), but against *state*, not a fresh code (OBI-197/OBI-198
    /// follow-up): the refresh token travels only as a cookie (OBI-198),
    /// which has nowhere to carry a TOTP code, and the family's `amr`
    /// already records whether its login completed one. A refresh for a
    /// tier at or above [`MANDATORY_TOTP_TIER`] is refused -- revoking
    /// the whole family -- if there is no staff row, if TOTP isn't
    /// confirmed, or if `amr` doesn't contain `"otp"` (e.g. a T2 login
    /// later promoted to T3, which never had the chance to prove TOTP in
    /// the first place).
    ///
    /// Presenting an *already-revoked* token (replay of a rotated-out
    /// token, i.e. a stolen refresh token) revokes every other
    /// outstanding token in that token's family (M-AUTH-5), since by
    /// definition one of the two parties holding it is not the
    /// legitimate session. That replay is audited as `auth.refresh.reuse`
    /// (M-AUTH-9).
    pub async fn refresh(
        &self,
        refresh_token: &str,
        ctx: &AuthContext,
    ) -> Result<TokenPair, AuthError> {
        let old_hash = hash_token(refresh_token);
        let new_refresh_token = generate_refresh_token();
        let new_hash = hash_token(&new_refresh_token);
        let idle_cutoff = now() - self.idle_ttl;

        match self
            .directory
            .session_rotate(&old_hash, &new_hash, idle_cutoff)
            .await?
        {
            SessionRotateOutcome::Rotated {
                staff_uid,
                sid,
                amr,
                mfa_at,
                expires_at,
            } => {
                let status = self.require_staff_status(&staff_uid).await?;
                if let Err(err) = self.enforce_totp_gate_for_refresh(status.tier, &amr) {
                    self.directory.refresh_token_revoke_all(&staff_uid).await?;
                    return Err(err);
                }
                let (access_token, access_expires_at) =
                    self.mint_access_token(&staff_uid, status.tier, &sid, &amr, mfa_at)?;
                Ok(TokenPair {
                    access_token,
                    refresh_token: new_refresh_token,
                    access_expires_at,
                    refresh_expires_at: expires_at,
                })
            }
            SessionRotateOutcome::Reused { staff_uid } => {
                self.audit("auth.refresh.reuse", Some(staff_uid), ctx, "deny", None)
                    .await;
                Err(AuthError::InvalidRefreshToken)
            }
            SessionRotateOutcome::Invalid => Err(AuthError::InvalidRefreshToken),
        }
    }

    /// Revoke the whole session family the presented refresh token
    /// belongs to (logout, M-AUTH-5: "logout revokes the family").
    pub async fn logout(&self, refresh_token: &str) -> Result<(), AuthError> {
        let token_hash = hash_token(refresh_token);
        self.directory
            .session_revoke_family_by_token(&token_hash)
            .await?;
        Ok(())
    }

    /// Generate and store a fresh TOTP secret for `uid` (self-service --
    /// the directory re-checks actor == uid in SQL). Returns the
    /// enrolment payload (base32 secret + `otpauth://` URL) once; the
    /// caller must show it to the user now, since only its hash-adjacent
    /// state (not the plaintext) is ever returned again. Audited as
    /// `auth.totp.enrol` the first time `uid` gets a secret, or
    /// `auth.totp.reset` if one already existed (M-AUTH-9).
    ///
    /// Refuses with [`AuthError::TotpAlreadyEnrolled`] if `uid` already has
    /// a *confirmed* secret (OBI-195 review fix 3) -- the SQL function
    /// backing [`StaffDirectory::totp_enroll`] re-checks this too (D-27.2
    /// pattern), this is the fast/typed path so the HTTP layer can answer
    /// `409` instead of a generic `503`. A real reset of a *confirmed*
    /// secret needs a dedicated, step-up-gated flow (OBI-199 follow-up).
    pub async fn totp_enroll(
        &self,
        uid: &str,
        ctx: &AuthContext,
    ) -> Result<totp::TotpEnrollment, AuthError> {
        let status = self
            .directory
            .auth_status_for(uid)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        if status.totp_confirmed {
            return Err(AuthError::TotpAlreadyEnrolled);
        }
        let had_prior_secret = status.totp_secret.is_some();
        let enrollment = totp::generate_totp_secret(uid);
        self.directory
            .totp_enroll(uid, &enrollment.secret_base32)
            .await?;
        let kind = if had_prior_secret {
            "auth.totp.reset"
        } else {
            "auth.totp.enrol"
        };
        self.audit(kind, Some(uid.to_string()), ctx, "allow", None)
            .await;
        Ok(enrollment)
    }

    /// Verify `code` against `uid`'s just-enrolled (or previously
    /// enrolled) secret and, on success, mark it confirmed -- the gate
    /// [`Self::login`]/[`Self::github_login`] check for T3+ staff. Like
    /// every other TOTP check in this service, the matched step is
    /// consumed atomically (OBI-195 review fix 4): confirming with a code
    /// does not leave that code valid for a subsequent login. TOTP
    /// attempts share the login rate limiter (M-AUTH-1): a wrong code
    /// counts as a failure against both the per-account and per-IP
    /// limits.
    pub async fn totp_confirm(
        &self,
        uid: &str,
        code: &str,
        ctx: &AuthContext,
    ) -> Result<(), AuthError> {
        let account_key = uid_rate_key(uid);
        match self.rate_limiter.check(&account_key, ctx.ip) {
            RateLimitDecision::IpThrottled => return Err(AuthError::RateLimited),
            RateLimitDecision::AccountLocked => return Err(AuthError::TotpInvalid),
            RateLimitDecision::Allowed => {}
        }

        let secret = match self.directory.totp_secret_for(uid).await {
            Ok(Some(secret)) => secret,
            Ok(None) => {
                // No secret to check against -- not a guess, give the
                // reservation back rather than count it as a failure.
                self.rate_limiter.release(&account_key);
                return Err(AuthError::TotpInvalid);
            }
            Err(err) => {
                self.rate_limiter.release(&account_key);
                return Err(err.into());
            }
        };
        match self.verify_and_consume_totp(uid, &secret, code).await {
            Ok(()) => {
                if let Err(err) = self.directory.totp_confirm(uid).await {
                    self.rate_limiter.release(&account_key);
                    return Err(err.into());
                }
                self.rate_limiter.record_success(&account_key);
                Ok(())
            }
            Err(err) => {
                self.rate_limiter.record_failure(&account_key);
                Err(err)
            }
        }
    }

    /// Verify an access token's signature/expiry and return its claims.
    /// Does **not** re-read the tier from Postgres -- callers that need a
    /// guaranteed-current tier (any privileged write) must still check
    /// against the directory directly; this is for cheap, read-mostly
    /// authorization at the edge.
    pub fn verify_access_token(&self, token: &str) -> Result<AccessClaims, AuthError> {
        self.keys
            .decode(token)
            .map_err(|_| AuthError::InvalidRefreshToken)
    }

    /// `POST /api/v1/ws-ticket` (D-TM4): mint a single-use, 30s ticket
    /// bound to `claims.sub`+`claims.sid`, for the caller to send as
    /// `/lsp`'s first WS frame.
    pub fn issue_ws_ticket(&self, claims: &AccessClaims) -> Result<String, AuthError> {
        self.ws_tickets
            .issue(&claims.sub, &claims.sid)
            .map_err(|_| AuthError::InvalidWsTicket)
    }

    /// Redeem a D-TM4 ticket from `/lsp`'s first frame, keeping *why* it
    /// failed ([`wsticket::WsTicketError`]) instead of folding that into
    /// [`AuthError::InvalidWsTicket`].
    ///
    /// `/lsp`'s own connect path uses this so a refusal can be recorded as
    /// "this ticket already redeemed" (D-TM4 single use) rather than "the
    /// ticket was unusable". The answer a client sees is unchanged: both
    /// still get the same bare `Close`, because D-TM4 deliberately keeps
    /// those indistinguishable to whoever tried (OBI-365).
    pub fn redeem_ws_ticket_detailed(
        &self,
        ticket: &str,
    ) -> Result<wsticket::WsTicketIdentity, wsticket::WsTicketError> {
        self.ws_tickets.redeem(ticket)
    }

    /// Redeem a D-TM4 ticket from `/lsp`'s first frame: verifies the
    /// signature and expiry, and consumes it so a second redemption of
    /// the same ticket fails even within its 30s window.
    pub fn redeem_ws_ticket(&self, ticket: &str) -> Result<wsticket::WsTicketIdentity, AuthError> {
        self.redeem_ws_ticket_detailed(ticket)
            .map_err(|_| AuthError::InvalidWsTicket)
    }

    /// Fresh tier for `uid` (OBI-180, M-LSP-1): `/lsp`'s connect-time
    /// check and its periodic demotion/removal recheck both use this.
    /// `Ok(None)` means no `staff` row at all (removed staff). A
    /// directory error is surfaced as `Err` rather than folded into
    /// `Ok(None)`, so a caller doing a *periodic* recheck can choose not
    /// to treat a transient Postgres outage as a demotion.
    pub async fn current_tier(&self, uid: &str) -> Result<Option<i16>, AuthError> {
        Ok(self.directory.auth_status_for(uid).await?.map(|s| s.tier))
    }

    /// `true` iff `sid`'s token family is still live -- not revoked, not
    /// expired (OBI-180 M-LSP-1, CTO review of PR #122 must-fix 2):
    /// `/lsp`'s connect-time check and its periodic recheck both use
    /// this, the same way they both use [`Self::current_tier`] for the
    /// tier/removal check. A directory error surfaces as `Err` for the
    /// same reason `current_tier`'s doc gives: a periodic recheck must
    /// be able to tell a transient outage apart from a confirmed
    /// revocation.
    pub async fn session_family_live(&self, sid: &str) -> Result<bool, AuthError> {
        Ok(self.directory.session_family_live(sid).await?)
    }

    /// Sign arbitrary claims directly, bypassing `login`/`refresh`
    /// entirely -- test-only, so `loom-http`'s HTTP-wire admin tests
    /// (`admin.rs`) can mint a token with a specific tier/`mfa_at`
    /// without needing a full `StaffDirectory` fake to drive `login`.
    #[cfg(test)]
    pub fn sign_for_test(&self, claims: &AccessClaims) -> String {
        self.keys.encode(claims).expect("encode test claims")
    }

    /// Read `uid`'s fresh tier/TOTP status, refusing outright (and
    /// dropping any sessions it might still hold) if it has no `staff`
    /// row at all (OBI-195 review fix 5): the old `tier_of`-based design
    /// defaulted a missing row to tier 0 and minted a token anyway.
    async fn require_staff_status(&self, uid: &str) -> Result<StaffAuthStatus, AuthError> {
        let Some(status) = self.directory.auth_status_for(uid).await? else {
            self.directory.refresh_token_revoke_all(uid).await?;
            return Err(AuthError::InvalidCredentials);
        };
        Ok(status)
    }

    /// Issue a fresh (access, refresh) pair for `uid` at `tier` (read
    /// fresh from Postgres by the caller just beforehand -- see
    /// [`Self::require_staff_status`]). Shared by the password and GitHub
    /// login paths (a refresh goes through [`Self::refresh`]/
    /// [`Self::mint_access_token`] instead, since it must carry an
    /// existing family's `sid`/`amr`/`mfa_at`/`expires_at` forward rather
    /// than minting a fresh family here). `sid` is the token-family id
    /// (fresh via [`generate_sid`]), and `amr`/`mfa_at` describe *this
    /// login's* authentication context (D-TM3: identity, never
    /// authority).
    async fn issue_tokens(
        &self,
        uid: &str,
        tier: i16,
        sid: String,
        amr: Vec<String>,
        mfa_at: Option<OffsetDateTime>,
    ) -> Result<TokenPair, AuthError> {
        let (access_token, access_expires_at) =
            self.mint_access_token(uid, tier, &sid, &amr, mfa_at)?;

        let refresh_token = generate_refresh_token();
        let refresh_expires_at = now() + self.refresh_ttl;
        self.directory
            .refresh_token_insert(
                uid,
                &hash_token(&refresh_token),
                refresh_expires_at,
                &sid,
                &amr,
                mfa_at,
            )
            .await?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            access_expires_at,
            refresh_expires_at,
        })
    }

    /// Sign a fresh access token for `uid`/`tier`, carrying `sid`/`amr`/
    /// `mfa_at` -- the one place [`Self::issue_tokens`] (fresh login) and
    /// [`Self::refresh`] (rotation) both go through to turn a tier into
    /// scopes and mint an access JWT, so claim construction never drifts
    /// between the two paths.
    fn mint_access_token(
        &self,
        uid: &str,
        tier: i16,
        sid: &str,
        amr: &[String],
        mfa_at: Option<OffsetDateTime>,
    ) -> Result<(String, OffsetDateTime), AuthError> {
        let scopes = scopes_for_tier(tier);
        let issued_at = now();
        let access_expires_at = issued_at + self.access_ttl;
        let claims = AccessClaims {
            sub: uid.to_string(),
            tier,
            scopes,
            iss: self.keys.issuer().to_string(),
            aud: self.keys.audience().to_string(),
            iat: issued_at.unix_timestamp(),
            nbf: issued_at.unix_timestamp(),
            exp: access_expires_at.unix_timestamp(),
            sid: sid.to_string(),
            amr: amr.to_vec(),
            mfa_at: mfa_at.map(|t| t.unix_timestamp()),
        };
        let access_token = self
            .keys
            .encode(&claims)
            .map_err(|_| AuthError::DirectoryUnavailable)?;
        Ok((access_token, access_expires_at))
    }

    /// The mandatory-TOTP gate for [`Self::login`]/[`Self::github_login`]
    /// (design §9/D-P2.5: "mandatory for T3+"), enforced identically for
    /// both. Returns whether a TOTP code was presented and verified, so
    /// callers can set `amr`/`mfa_at` accordingly (M-AUTH-3's "record
    /// `amr` and `mfa_at`"). `Ok(false)` covers both "TOTP isn't mandatory
    /// for this uid and none was supplied" and -- deliberately -- is never
    /// reached for a mandatory-TOTP uid without a verified code, since
    /// those return `Err` instead.
    async fn enforce_totp_gate_with_code(
        &self,
        uid: &str,
        tier: i16,
        totp_secret: Option<&str>,
        totp_confirmed: bool,
        totp_code: Option<&str>,
    ) -> Result<bool, AuthError> {
        if tier < MANDATORY_TOTP_TIER {
            return Ok(false);
        }

        let Some(secret) = totp_secret.filter(|_| totp_confirmed) else {
            // T3+ with no confirmed secret: refused outright, not just
            // "code required" -- there is no code that would satisfy this.
            return Err(AuthError::TotpRequired);
        };

        let Some(code) = totp_code else {
            return Err(AuthError::TotpRequired);
        };

        self.verify_and_consume_totp(uid, secret, code).await?;
        Ok(true)
    }

    /// The mandatory-TOTP gate for [`Self::refresh`]: unlike the code-based
    /// gate above, this checks *state* -- tier, confirmation, and whether
    /// the session family's `amr` already contains `"otp"` -- since a
    /// cookie-only refresh has no code to present (see the module docs).
    fn enforce_totp_gate_for_refresh(&self, tier: i16, amr: &[String]) -> Result<(), AuthError> {
        if tier < MANDATORY_TOTP_TIER {
            return Ok(());
        }
        if !amr.iter().any(|m| m == "otp") {
            return Err(AuthError::TotpRequired);
        }
        Ok(())
    }

    /// Verify `code` against `secret` and, only if it matches, atomically
    /// consume the RFC 6238 step it matched (OBI-195 review fix 4) so the
    /// same code can never be accepted twice -- whether replayed by an
    /// attacker or resubmitted by a confused client.
    async fn verify_and_consume_totp(
        &self,
        uid: &str,
        secret: &str,
        code: &str,
    ) -> Result<(), AuthError> {
        let Some(step) = totp::totp_step_for_code(secret, code) else {
            return Err(AuthError::TotpInvalid);
        };
        if self.directory.totp_consume_step(uid, step).await? {
            Ok(())
        } else {
            // RFC 6238-valid, but this step was already used.
            Err(AuthError::TotpInvalid)
        }
    }

    /// Admin role-tier change (OBI-185, M-ADM-1/M-ADM-2): `claims` is the
    /// caller's *verified* access-token claims -- `claims.sub` is always
    /// the actor passed to `roles_set_tier`, never anything the request
    /// body supplies (the HTTP layer's `AdminSetTierRequest` has no
    /// `actor` field at all; see `admin.rs`). Enforces tier >= 3
    /// (§5.11.2) and step-up freshness (`mfa_at` within the last 5
    /// minutes) *before* ever calling the directory -- but the real
    /// boundary is `roles_set_tier` itself: a caller who somehow got past
    /// both checks (e.g. a build with the tier check deleted) still gets
    /// refused by SQL for anything the function doesn't allow, which is
    /// what [`AdminError::Rejected`] surfaces. Every outcome -- forbidden,
    /// step-up required, rejected, or allowed -- is audited (M-ADM-4).
    pub async fn admin_set_tier(
        &self,
        claims: &AccessClaims,
        ctx: &AuthContext,
        target_uid: &str,
        new_tier: i16,
        reason: &str,
    ) -> Result<(), AdminError> {
        let detail = format!("target={target_uid} new_tier={new_tier}");
        if claims.tier < ADMIN_ROLE_CHANGE_MIN_TIER {
            self.audit(
                "admin.roles.set_tier",
                Some(claims.sub.clone()),
                ctx,
                "deny",
                Some(format!("{detail} reason=forbidden")),
            )
            .await;
            return Err(AdminError::Forbidden);
        }
        if !self.has_fresh_step_up(claims) {
            self.audit(
                "admin.roles.set_tier",
                Some(claims.sub.clone()),
                ctx,
                "deny",
                Some(format!("{detail} reason=step_up_required")),
            )
            .await;
            return Err(AdminError::StepUpRequired);
        }
        match self
            .directory
            .admin_set_tier(&claims.sub, target_uid, new_tier, reason)
            .await
        {
            Ok(()) => {
                self.audit(
                    "admin.roles.set_tier",
                    Some(claims.sub.clone()),
                    ctx,
                    "allow",
                    Some(detail),
                )
                .await;
                Ok(())
            }
            Err(err) => {
                let admin_err: AdminError = err.into();
                let reason_detail = match &admin_err {
                    AdminError::Rejected(message) => format!("{detail} reason={message}"),
                    _ => format!("{detail} reason=directory_unavailable"),
                };
                self.audit(
                    "admin.roles.set_tier",
                    Some(claims.sub.clone()),
                    ctx,
                    "deny",
                    Some(reason_detail),
                )
                .await;
                Err(admin_err)
            }
        }
    }

    /// Admin audit view (OBI-185, M-ADM-4): read-only, tier-gated the
    /// same as object listing (§5.11.2-adjacent: T3+), and itself
    /// audited -- "every admin endpoint audited" includes the audit view.
    pub async fn admin_audit_recent(
        &self,
        claims: &AccessClaims,
        ctx: &AuthContext,
        limit: i64,
        before_id: Option<i64>,
    ) -> Result<Vec<AdminAuditEntry>, AdminError> {
        if claims.tier < ADMIN_ROLE_CHANGE_MIN_TIER {
            self.audit(
                "admin.audit.view",
                Some(claims.sub.clone()),
                ctx,
                "deny",
                None,
            )
            .await;
            return Err(AdminError::Forbidden);
        }
        let rows = match self.directory.admin_audit_recent(limit, before_id).await {
            Ok(rows) => rows,
            Err(err) => {
                let admin_err = AdminError::from(err);
                let reason_detail = match &admin_err {
                    AdminError::Rejected(message) => {
                        format!("limit={limit} before_id={before_id:?} reason={message}")
                    }
                    _ => format!(
                        "limit={limit} before_id={before_id:?} reason=directory_unavailable"
                    ),
                };
                self.audit(
                    "admin.audit.view",
                    Some(claims.sub.clone()),
                    ctx,
                    "deny",
                    Some(reason_detail),
                )
                .await;
                return Err(admin_err);
            }
        };
        self.audit(
            "admin.audit.view",
            Some(claims.sub.clone()),
            ctx,
            "allow",
            Some(format!("limit={limit} before_id={before_id:?}")),
        )
        .await;
        Ok(rows)
    }

    /// `GET /api/v1/admin/who` (OBI-234, CTO review on PR #98): tier >= 2
    /// ([`WHO_MIN_TIER`]) -- a T1 (builder) token alone no longer lists
    /// every connected account. The scope note didn't set a floor;
    /// picking one explicitly (over leaving `who` open to any staff
    /// token) is the more conservative default the review asked for.
    /// Still audited either way (M-ADM-4), and M-ADM-3 (no email/IP) is
    /// enforced by [`crate::admin_query::WhoEntry`] simply not having
    /// those fields, independent of this floor.
    pub async fn admin_who(
        &self,
        claims: &AccessClaims,
        ctx: &AuthContext,
        query: &dyn crate::admin_query::WorldAdminQuery,
    ) -> Result<Vec<crate::admin_query::WhoEntry>, AdminError> {
        if claims.tier < WHO_MIN_TIER {
            self.audit(
                "admin.who",
                Some(claims.sub.clone()),
                ctx,
                "deny",
                Some("reason=forbidden".to_string()),
            )
            .await;
            return Err(AdminError::Forbidden);
        }
        match query.who().await {
            Ok(rows) => {
                self.audit(
                    "admin.who",
                    Some(claims.sub.clone()),
                    ctx,
                    "allow",
                    Some(format!("count={}", rows.len())),
                )
                .await;
                Ok(rows)
            }
            Err(err) => {
                self.audit(
                    "admin.who",
                    Some(claims.sub.clone()),
                    ctx,
                    "deny",
                    Some(format!("reason={err:?}")),
                )
                .await;
                Err(err.into())
            }
        }
    }

    /// `GET /api/v1/admin/objects` (OBI-234, M-ADM-4): tier >= 3
    /// ([`OBJECT_LIST_MIN_TIER`]) to list at all; the listing itself is
    /// `valid_read`-filtered on the world side (`query.list_objects`),
    /// never re-filtered or re-derived here (design note: "do not invent
    /// a parallel rule set").
    pub async fn admin_list_objects(
        &self,
        claims: &AccessClaims,
        ctx: &AuthContext,
        query: &dyn crate::admin_query::WorldAdminQuery,
    ) -> Result<Vec<crate::admin_query::ObjectSummary>, AdminError> {
        if claims.tier < OBJECT_LIST_MIN_TIER {
            self.audit(
                "admin.objects.list",
                Some(claims.sub.clone()),
                ctx,
                "deny",
                Some("reason=forbidden".to_string()),
            )
            .await;
            return Err(AdminError::Forbidden);
        }
        match query.list_objects(&claims.sub, claims.tier).await {
            Ok(rows) => {
                self.audit(
                    "admin.objects.list",
                    Some(claims.sub.clone()),
                    ctx,
                    "allow",
                    Some(format!("count={}", rows.len())),
                )
                .await;
                Ok(rows)
            }
            Err(err) => {
                self.audit(
                    "admin.objects.list",
                    Some(claims.sub.clone()),
                    ctx,
                    "deny",
                    Some(format!("reason={err:?}")),
                )
                .await;
                Err(err.into())
            }
        }
    }

    /// `GET /api/v1/admin/objects/:path/vars` (OBI-234, M-ADM-4): tier >=
    /// 4 ([`OBJECT_VARS_MIN_TIER`]) to inspect any object's variables,
    /// and tier >= 5 ([`SECURE_VARS_MIN_TIER`]) specifically for anything
    /// under `/secure/` -- both floors are on top of, not instead of,
    /// `valid_read` itself (`query.object_vars`), which is the real
    /// boundary on the world side. Every call is audited, allow or deny,
    /// per access (M-ADM-4's "audited per access" for this endpoint
    /// specifically).
    pub async fn admin_object_vars(
        &self,
        claims: &AccessClaims,
        ctx: &AuthContext,
        query: &dyn crate::admin_query::WorldAdminQuery,
        path: &str,
    ) -> Result<crate::admin_query::ObjectVars, AdminError> {
        let detail = format!("path={path}");
        if claims.tier < OBJECT_VARS_MIN_TIER {
            self.audit(
                "admin.objects.vars",
                Some(claims.sub.clone()),
                ctx,
                "deny",
                Some(format!("{detail} reason=forbidden")),
            )
            .await;
            return Err(AdminError::Forbidden);
        }
        if is_or_might_be_secure(path) && claims.tier < SECURE_VARS_MIN_TIER {
            self.audit(
                "admin.objects.vars",
                Some(claims.sub.clone()),
                ctx,
                "deny",
                Some(format!("{detail} reason=forbidden_secure")),
            )
            .await;
            return Err(AdminError::Forbidden);
        }
        match query.object_vars(&claims.sub, claims.tier, path).await {
            Ok(vars) => {
                self.audit(
                    "admin.objects.vars",
                    Some(claims.sub.clone()),
                    ctx,
                    "allow",
                    Some(detail),
                )
                .await;
                Ok(vars)
            }
            Err(err) => {
                self.audit(
                    "admin.objects.vars",
                    Some(claims.sub.clone()),
                    ctx,
                    "deny",
                    Some(format!("{detail} reason={err:?}")),
                )
                .await;
                Err(err.into())
            }
        }
    }

    /// `GET /api/v1/admin/errors` (OBI-235, M-ADM-4): tier >= 3
    /// ([`ERROR_INBOX_MIN_TIER`]), consistent with [`OBJECT_LIST_MIN_TIER`].
    /// As with `admin_list_objects`, the per-program `valid_read` filter
    /// and the `/secure` redaction rule (M-ERR-1) both run on the world
    /// side (`query.errors`) -- this never re-derives or relaxes either
    /// one. `program_prefix` is an optional caller-supplied filter (same
    /// shape as the `errors` efun's own `filter` argument).
    pub async fn admin_errors(
        &self,
        claims: &AccessClaims,
        ctx: &AuthContext,
        query: &dyn crate::admin_query::WorldAdminQuery,
        program_prefix: Option<&str>,
    ) -> Result<Vec<crate::admin_query::ErrorGroup>, AdminError> {
        let detail = program_prefix.map(|p| format!("program_prefix={p}"));
        if claims.tier < ERROR_INBOX_MIN_TIER {
            self.audit(
                "admin.errors",
                Some(claims.sub.clone()),
                ctx,
                "deny",
                Some(format!(
                    "{} reason=forbidden",
                    detail.clone().unwrap_or_default()
                )),
            )
            .await;
            return Err(AdminError::Forbidden);
        }
        match query.errors(&claims.sub, claims.tier, program_prefix).await {
            Ok(rows) => {
                self.audit(
                    "admin.errors",
                    Some(claims.sub.clone()),
                    ctx,
                    "allow",
                    Some(format!(
                        "{} count={}",
                        detail.unwrap_or_default(),
                        rows.len()
                    )),
                )
                .await;
                Ok(rows)
            }
            Err(err) => {
                self.audit(
                    "admin.errors",
                    Some(claims.sub.clone()),
                    ctx,
                    "deny",
                    Some(format!("{} reason={err:?}", detail.unwrap_or_default())),
                )
                .await;
                Err(err.into())
            }
        }
    }

    /// `POST /api/v1/admin/broadcast` (OBI-233, M-ADM-2/4/5): tier >=
    /// [`ADMIN_BROADCAST_MIN_TIER`] and step-up fresh, exactly like
    /// [`Self::admin_set_tier`]'s checks, but gated at a higher tier
    /// floor given the blast radius (every interactive session). The
    /// size cap (M-ADM-5) is enforced on the *raw* body, before
    /// sanitization -- rejecting an oversized body rather than silently
    /// truncating it. The body is then sanitized
    /// ([`sanitize_broadcast_text`]) and, per line, given the
    /// driver-fixed [`BROADCAST_PREFIX`] (CTO review, OBI-233) -- a
    /// body that sanitizes to nothing (blank/whitespace-only) is a
    /// [`AdminError::BadRequest`], not a blank broadcast. The *exact*
    /// string this method hands to `query.broadcast` is also the
    /// audited `detail` (M-IDE-2: never raw input, never re-derived --
    /// the two can't drift). Delivery itself -- fan-out to interactive
    /// sessions only -- is `query.broadcast`'s job
    /// (`crate::admin_query::WorldAdminQuery::broadcast`'s doc comment);
    /// this method never talks to `loom-net` directly. Every outcome --
    /// forbidden, step-up required, too large, empty, or allowed/denied
    /// by the world side -- is audited. A *denied* delivery row also
    /// carries an `outcome=` saying whether delivery can be ruled out at
    /// all (`Busy` never left this process, so `not_delivered`; a
    /// `Timeout`/`Closed` was already queued to the world thread, so
    /// `unknown` -- see `delivery_outcome_label`).
    pub async fn admin_broadcast(
        &self,
        claims: &AccessClaims,
        ctx: &AuthContext,
        query: &dyn crate::admin_query::WorldAdminQuery,
        text: &str,
    ) -> Result<usize, AdminError> {
        if claims.tier < ADMIN_BROADCAST_MIN_TIER {
            self.audit(
                "admin.broadcast",
                Some(claims.sub.clone()),
                ctx,
                "deny",
                Some("reason=forbidden".to_string()),
            )
            .await;
            return Err(AdminError::Forbidden);
        }
        if !self.has_fresh_step_up(claims) {
            self.audit(
                "admin.broadcast",
                Some(claims.sub.clone()),
                ctx,
                "deny",
                Some("reason=step_up_required".to_string()),
            )
            .await;
            return Err(AdminError::StepUpRequired);
        }
        if text.len() > BROADCAST_MAX_BYTES {
            self.audit(
                "admin.broadcast",
                Some(claims.sub.clone()),
                ctx,
                "deny",
                Some(format!("reason=body_too_large bytes={}", text.len())),
            )
            .await;
            return Err(AdminError::BodyTooLarge);
        }
        let sanitized = sanitize_broadcast_text(text);
        if sanitized.trim().is_empty() {
            self.audit(
                "admin.broadcast",
                Some(claims.sub.clone()),
                ctx,
                "deny",
                Some("reason=empty_after_sanitizing".to_string()),
            )
            .await;
            return Err(AdminError::BadRequest);
        }
        let delivered = prefix_broadcast_lines(&sanitized);
        match query.broadcast(&delivered).await {
            Ok(count) => {
                // M-IDE-2/M-ADM-4: the audited `detail` is the exact
                // string delivered to sessions -- never raw,
                // unsanitized input, and never rendered as HTML by the
                // admin UI.
                self.audit(
                    "admin.broadcast",
                    Some(claims.sub.clone()),
                    ctx,
                    "allow",
                    Some(format!("recipients={count} text={delivered}")),
                )
                .await;
                Ok(count)
            }
            Err(err) => {
                // CTO review (OBI-233, third pass, optional item 1): a
                // `Timeout`/`Closed` here means the request was already
                // handed to the world thread and we simply stopped hearing
                // about it, so the broadcast *may* have gone out. Audit it
                // as a deny (the operator got a 503), but say plainly that
                // the delivery outcome is unknown instead of implying it
                // definitely did not land -- an operator who retries after
                // a blind failure can otherwise duplicate a message that
                // was already delivered, with no record of the first one.
                self.audit(
                    "admin.broadcast",
                    Some(claims.sub.clone()),
                    ctx,
                    "deny",
                    Some(format!(
                        "reason={err:?} outcome={} text={delivered}",
                        delivery_outcome_label(&err)
                    )),
                )
                .await;
                Err(err.into())
            }
        }
    }

    /// M-ADM-2: a session is "stepped up" if its `mfa_at` is within the
    /// last 5 minutes. A session that never completed a second factor
    /// (`mfa_at: None`, e.g. a sub-T3 password-only login) is never
    /// stepped up, regardless of its current tier.
    fn has_fresh_step_up(&self, claims: &AccessClaims) -> bool {
        let Some(mfa_at) = claims.mfa_at else {
            return false;
        };
        let now_secs = now().unix_timestamp();
        now_secs.saturating_sub(mfa_at) <= STEP_UP_WINDOW_SECS
    }

    /// Append one audit row (M-AUTH-9), logging and swallowing any
    /// directory failure -- see [`StaffDirectory::record_audit`]'s doc
    /// comment for why this never propagates.
    async fn audit(
        &self,
        kind: &'static str,
        uid: Option<String>,
        ctx: &AuthContext,
        verdict: &'static str,
        detail: Option<String>,
    ) {
        let event = AuditEvent {
            kind,
            uid,
            ip: ctx.ip,
            user_agent: ctx.user_agent.clone(),
            verdict,
            detail,
        };
        if let Err(err) = self.directory.record_audit(event).await {
            warn!(?err, kind, "failed to record auth audit event");
        }
    }
}

/// A short, non-sensitive label for why a login's TOTP/tier gate refused
/// it, for the `auth.login.fail` audit row's `detail`.
fn totp_gate_detail(error: &AuthError) -> &'static str {
    match error {
        AuthError::TotpRequired => "totp_required",
        AuthError::TotpInvalid => "totp_invalid",
        AuthError::InvalidCredentials => "staff_row_missing",
        _ => "totp_gate_failed",
    }
}

/// Does `path` name, or might it after normalization name, something
/// under `/secure/` (OBI-234, CTO review on PR #98)? This is only the
/// HTTP edge's T5 floor for [`AuthService::admin_object_vars`] -- the
/// real gate is `valid_read` on the world side, which resolves the path
/// for real. This helper exists so the edge floor isn't trivially
/// bypassed by an unnormalized path (`//secure/x`, `/./secure/x`) while
/// `valid_read` still (correctly) treats it as `/secure/x`; it fails
/// *closed*: anything it can't confidently normalize (a `..` segment) is
/// treated as "might be secure", never waved through as "definitely
/// not".
///
/// Splits on `/`, drops empty segments (collapsing repeated slashes) and
/// `.` segments; returns `true` if a `..` segment is seen (can't resolve
/// without knowing the real filesystem, so don't try -- refuse to rule
/// out `/secure/`) or if the first remaining segment is `"secure"`.
fn is_or_might_be_secure(path: &str) -> bool {
    // A `..` anywhere in the path can walk back out past a non-`secure`
    // prefix (e.g. `/std/../secure/master`), so treat any `..` segment as
    // "might be secure" rather than only checking the first segment
    // (CTO re-review must-fix, PR #98 / OBI-185 / OBI-234).
    if path.split('/').any(|segment| segment == "..") {
        return true;
    }
    for segment in path.split('/') {
        match segment {
            "" | "." => continue,
            "secure" => return true,
            _ => return false,
        }
    }
    false
}

/// M-ADM-5: strip every C0 (`U+0000..=U+001F`) and C1 (`U+0080..=U+009F`)
/// control character except `\n`, plus DEL (`U+007F`) -- not strictly C0/C1,
/// but still a control character with no safe plain-text rendering, and
/// the same category the design note's "strip control characters" is
/// guarding against (M-IDE-2: plain-text only, no escape-sequence or
/// terminal-control smuggling through the admin UI or any client's
/// terminal). `\r` is deliberately stripped too (not excepted like
/// `\n`): the only line terminator a broadcast body needs is `\n`, and
/// `loom-net`'s own wire framing (`to_wire`) already turns every `\n`
/// into `\r\n` for telnet -- letting a client-supplied `\r` through
/// would risk a raw, unescaped carriage return reaching the wire via the
/// WebSocket path (which does not go through `to_wire`).
///
/// CTO review (OBI-233, second pass): also strip the bidi/format and
/// zero-width characters a broadcast body has no legitimate use for and
/// that can otherwise be used to visually reorder or hide text in a
/// terminal or the admin UI -- explicit bidi embedding/override/isolate
/// controls (`U+202A..=U+202E`, `U+2066..=U+2069`), zero-width
/// space/non-joiner/joiner and the left-to-right/right-to-left marks
/// (`U+200B..=U+200F`), and the BOM/zero-width no-break space
/// (`U+FEFF`).
///
/// CTO review (OBI-233, third pass, optional item 2): also `U+2028` LINE
/// SEPARATOR, `U+2029` PARAGRAPH SEPARATOR and `U+061C` ARABIC LETTER
/// MARK. The first two are line breaks a JSON body can carry that some
/// terminals/renderers honour, which would split a `[Broadcast] `-prefixed
/// line into an unprefixed continuation and defeat the attribution -- they
/// are stripped rather than mapped to `\n`, since a broadcast's only line
/// terminator is `\n` (see [`prefix_broadcast_lines`]) and every other
/// line-break lookalike (`\r`, `U+0085` NEL) is already stripped. `U+061C`
/// is a bidi initiator in the same family as the `U+202A..=U+202E`
/// controls above.
fn sanitize_broadcast_text(input: &str) -> String {
    input
        .chars()
        .filter(|&c| {
            if c == '\n' {
                return true;
            }
            let code = c as u32;
            let is_control = code <= 0x1F || code == 0x7F || (0x80..=0x9F).contains(&code);
            let is_bidi_or_zero_width = (0x202A..=0x202E).contains(&code)
                || (0x2066..=0x2069).contains(&code)
                || (0x200B..=0x200F).contains(&code)
                || code == 0xFEFF
                || code == 0x2028
                || code == 0x2029
                || code == 0x061C;
            !(is_control || is_bidi_or_zero_width)
        })
        .collect()
}

/// Whether a failed delivery can be *ruled out*, for the `admin.broadcast`
/// deny audit row's `outcome=` field (CTO review, OBI-233 third pass,
/// optional item 1).
///
/// `"unknown"` for [`crate::admin_query::WorldQueryError::Timeout`] and
/// [`crate::admin_query::WorldQueryError::Closed`]: both happen *after* the
/// request was queued to (or picked up by) the world thread, so the text
/// may well have reached sessions even though no reply came back.
/// `"not_delivered"` for
/// [`crate::admin_query::WorldQueryError::Busy`], a `try_send` that failed
/// on a full queue -- the request never left `loom-http`, so nothing could
/// have been sent. `NotFound`/`Internal` are never produced by the
/// broadcast arm today; they are reported as `"unknown"` rather than
/// guessed at.
fn delivery_outcome_label(err: &crate::admin_query::WorldQueryError) -> &'static str {
    use crate::admin_query::WorldQueryError;
    match err {
        WorldQueryError::Busy => "not_delivered",
        WorldQueryError::Timeout
        | WorldQueryError::Closed
        | WorldQueryError::NotFound
        | WorldQueryError::Internal(_) => "unknown",
    }
}

/// CTO review (OBI-233, second pass): a driver-fixed [`BROADCAST_PREFIX`]
/// on every line, so a broadcast is visually distinguishable from
/// ordinary game output -- applied here, once, so the exact same string
/// is both the audited `detail` and the text handed to
/// `crate::admin_query::WorldAdminQuery::broadcast` (never two separately
/// derived copies that could drift). `sanitized` is assumed to already
/// be the output of [`sanitize_broadcast_text`] (no control characters,
/// so splitting on `\n` can't be confused by a stray `\r`). Always ends
/// in exactly one trailing `\n` (CTO review, first pass, must-fix 1):
/// the world/net output path owns line framing and otherwise the
/// broadcast would run into whatever the session prints next on the
/// same line.
fn prefix_broadcast_lines(sanitized: &str) -> String {
    let mut out = String::new();
    // `trim_end_matches` only drops *trailing* `\n`s (the split below
    // would otherwise produce one spurious empty final "line", since
    // `"a\n".split('\n')` is `["a", ""]`) -- interior blank lines (e.g.
    // a deliberate blank line in the middle of a multi-line broadcast)
    // are untouched and still get prefixed.
    for line in sanitized.trim_end_matches('\n').split('\n') {
        out.push_str(BROADCAST_PREFIX);
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// The rate limiter's account key for a resolved staff uid (OBI-204): the
/// one namespace both [`AuthService::login`] and
/// [`AuthService::totp_confirm`] use, so a wrong password and a wrong
/// TOTP code for the same staff member always land on the same bucket.
fn uid_rate_key(uid: &str) -> String {
    format!("{}{uid}", ratelimit::UID_KEY_PREFIX)
}

/// The rate limiter's account key for a login attempt whose username
/// didn't resolve to a uid (unknown username, or the directory was
/// unavailable for the resolve lookup) -- namespaced distinctly from
/// [`uid_rate_key`] so it can never collide with a real uid's bucket.
fn username_rate_key(username: &str) -> String {
    format!("user:{username}")
}

fn account_rate_key(resolved_uid: Option<&str>, username: &str) -> String {
    match resolved_uid {
        Some(uid) => uid_rate_key(uid),
        None => username_rate_key(username),
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// A fresh token-family id (M-AUTH-4's `sid` claim): identity only, never
/// looked up or revoked by itself (M-AUTH-5's revocation is keyed off the
/// refresh token's hash) -- it exists so audit/log correlation
/// (M-AUTH-9) can tie an access token back to the session that minted it
/// without logging the token itself.
fn generate_sid() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

/// A cryptographically random, URL-safe-ish opaque refresh token (32 bytes
/// of CSPRNG output, hex-encoded). Only its SHA-256 hash is ever persisted.
fn generate_refresh_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
pub(crate) mod tests;
