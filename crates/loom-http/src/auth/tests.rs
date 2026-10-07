// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Core [`AuthService`] tests against an in-memory fake [`StaffDirectory`]
//! (OBI-174 acceptance criteria): tier escalation attempts, expired/revoked
//! refresh, T3 without TOTP refused, and OIDC for an unlinked GitHub user
//! refused.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use time::OffsetDateTime;

use super::github::fake::FakeGithubProvider;
use super::*;

#[derive(Clone)]
struct FakeStaff {
    uid: String,
    password: String,
    tier: i16,
    totp_secret: Option<String>,
    totp_confirmed: bool,
    totp_last_step: Option<u64>,
}

#[derive(Default)]
struct FakeDirectoryInner {
    staff: HashMap<String, FakeStaff>, // keyed by username (== uid in these tests)
    sessions: HashMap<String, FakeSession>, // keyed by token_hash
    github_links: HashMap<i64, String>,
    audit_events: Vec<AuditEvent>,
    /// How many times [`StaffDirectory::resolve_uid`] has been called
    /// (OBI-204 review fix): used to prove `login` checks the IP bucket
    /// *before* paying for this lookup.
    resolve_uid_calls: u32,
    /// How many times [`StaffDirectory::admin_set_tier`] has actually
    /// reached the directory (OBI-185): used to prove a forbidden/
    /// step-up-refused call never gets this far.
    admin_set_tier_calls: u32,
    /// When `true`, [`StaffDirectory::admin_audit_recent`] fails outright
    /// (CTO review on PR #98: proving the deny path is audited too, not
    /// just the tier-floor refusal).
    fail_admin_audit: bool,
}

#[derive(Clone)]
struct FakeSession {
    staff_uid: String,
    expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
    sid: String,
    amr: Vec<String>,
    mfa_at: Option<OffsetDateTime>,
    last_used_at: OffsetDateTime,
}

#[derive(Clone, Default)]
pub(crate) struct FakeDirectory {
    inner: Arc<Mutex<FakeDirectoryInner>>,
}

impl FakeDirectory {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn add_staff(&self, uid: &str, password: &str, tier: i16) {
        self.inner.lock().unwrap().staff.insert(
            uid.to_string(),
            FakeStaff {
                uid: uid.to_string(),
                password: password.to_string(),
                tier,
                totp_secret: None,
                totp_confirmed: false,
                totp_last_step: None,
            },
        );
    }

    /// Simulate a staff row being deleted (OBI-195 review fix 5): the uid
    /// stops existing entirely, as opposed to [`Self::set_tier`] with 0,
    /// which keeps a legitimate (demoted) row.
    fn remove_staff(&self, uid: &str) {
        self.inner.lock().unwrap().staff.remove(uid);
    }

    fn set_tier(&self, uid: &str, tier: i16) {
        self.inner.lock().unwrap().staff.get_mut(uid).unwrap().tier = tier;
    }

    /// Make the next (and every subsequent) [`StaffDirectory::
    /// admin_audit_recent`] call fail with
    /// [`AdminDirectoryError::Unavailable`] (CTO review on PR #98).
    fn fail_admin_audit(&self) {
        self.inner.lock().unwrap().fail_admin_audit = true;
    }

    pub(crate) fn link_github(&self, github_id: i64, uid: &str) {
        self.inner
            .lock()
            .unwrap()
            .github_links
            .insert(github_id, uid.to_string());
    }

    /// Directly mark `uid`'s pending secret confirmed, *without* going
    /// through [`AuthService::totp_confirm`] (and so without consuming a
    /// real TOTP step). TOTP codes are tied to real wall-clock time --
    /// there is no way to mint a second, distinct *real* code inside one
    /// fast, non-sleeping test, so a test that wants to prove a *later*
    /// login with a real code succeeds must set up "already confirmed"
    /// this way instead of spending the one real code available to it on
    /// confirmation.
    pub(crate) fn confirm_totp_for_test(&self, uid: &str) {
        self.inner
            .lock()
            .unwrap()
            .staff
            .get_mut(uid)
            .unwrap()
            .totp_confirmed = true;
    }

    /// Directly mark a session revoked (simulating an admin/logout
    /// action taken through some other path, or the OBI-198 revoke-all
    /// trigger -- exercised directly here since the fake directory has
    /// no triggers).
    #[allow(dead_code)]
    fn revoke_for_test(&self, token_plaintext: &str) {
        let hash = hash_token(token_plaintext);
        if let Some(session) = self.inner.lock().unwrap().sessions.get_mut(&hash) {
            session.revoked_at = Some(now());
        }
    }

    /// Simulate the OBI-198 revoke-all-for-uid trigger (tier change, TOTP
    /// reset, GitHub unlink, staff removal, or password change all end up
    /// here in Postgres).
    fn revoke_all_for_uid_for_test(&self, uid: &str) {
        let mut inner = self.inner.lock().unwrap();
        for session in inner.sessions.values_mut() {
            if session.staff_uid == uid {
                session.revoked_at = Some(now());
            }
        }
    }

    /// Seed a `staff_sessions`-shaped row directly (bypassing login/
    /// refresh entirely), so a test can mint claims with a known `sid`
    /// via [`crate::auth::AccessClaims`] directly and have
    /// [`StaffDirectory::session_family_live`] see it as live, the way a
    /// real login would have inserted one (OBI-180, `/lsp`'s M-LSP-1
    /// revocation recheck).
    pub(crate) fn seed_live_session_for_test(&self, uid: &str, sid: &str) {
        self.inner.lock().unwrap().sessions.insert(
            format!("test-session-{sid}"),
            FakeSession {
                staff_uid: uid.to_string(),
                expires_at: now() + Duration::from_secs(3600),
                revoked_at: None,
                sid: sid.to_string(),
                amr: vec!["pwd".to_string()],
                mfa_at: None,
                last_used_at: now(),
            },
        );
    }

    /// Revoke every session sharing `sid` directly by family id, the way
    /// [`Self::revoke_all_for_uid_for_test`] does by uid -- used to
    /// simulate an M-AUTH-5 logout/revocation without a tier change.
    pub(crate) fn revoke_session_family_for_test(&self, sid: &str) {
        let mut inner = self.inner.lock().unwrap();
        for session in inner.sessions.values_mut() {
            if session.sid == sid {
                session.revoked_at = Some(now());
            }
        }
    }

    fn is_revoked(&self, token_plaintext: &str) -> bool {
        let hash = hash_token(token_plaintext);
        self.inner
            .lock()
            .unwrap()
            .sessions
            .get(&hash)
            .map(|r| r.revoked_at.is_some())
            .unwrap_or(false)
    }

    /// Back-date a session's `last_used_at` past the idle cutoff, for the
    /// idle-expiry test -- simulating a session nobody has refreshed in a
    /// while without sleeping real hours.
    fn backdate_last_used_for_test(&self, token_plaintext: &str, last_used_at: OffsetDateTime) {
        let hash = hash_token(token_plaintext);
        if let Some(session) = self.inner.lock().unwrap().sessions.get_mut(&hash) {
            session.last_used_at = last_used_at;
        }
    }

    fn audit_events(&self) -> Vec<AuditEvent> {
        self.inner.lock().unwrap().audit_events.clone()
    }

    fn admin_set_tier_calls(&self) -> u32 {
        self.inner.lock().unwrap().admin_set_tier_calls
    }

    fn tier_of(&self, uid: &str) -> Option<i16> {
        self.inner.lock().unwrap().staff.get(uid).map(|s| s.tier)
    }

    fn resolve_uid_calls(&self) -> u32 {
        self.inner.lock().unwrap().resolve_uid_calls
    }
}

#[async_trait::async_trait]
impl StaffDirectory for FakeDirectory {
    async fn staff_login(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<StaffAuthRecord>, DirectoryError> {
        let inner = self.inner.lock().unwrap();
        let Some(staff) = inner.staff.get(username) else {
            return Ok(None);
        };
        if staff.password != password {
            return Ok(None);
        }
        Ok(Some(StaffAuthRecord {
            uid: staff.uid.clone(),
            tier: staff.tier,
            totp_secret: staff.totp_secret.clone(),
            totp_confirmed: staff.totp_confirmed,
        }))
    }

    async fn resolve_uid(&self, username: &str) -> Result<Option<String>, DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        inner.resolve_uid_calls += 1;
        Ok(inner.staff.get(username).map(|s| s.uid.clone()))
    }

    async fn auth_status_for(&self, uid: &str) -> Result<Option<StaffAuthStatus>, DirectoryError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .staff
            .get(uid)
            .map(|s| StaffAuthStatus {
                tier: s.tier,
                totp_secret: s.totp_secret.clone(),
                totp_confirmed: s.totp_confirmed,
            }))
    }

    async fn totp_consume_step(&self, uid: &str, step: u64) -> Result<bool, DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        let Some(staff) = inner.staff.get_mut(uid) else {
            return Ok(false);
        };
        if staff.totp_last_step.is_none_or(|last| last < step) {
            staff.totp_last_step = Some(step);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn totp_enroll(&self, uid: &str, secret_base32: &str) -> Result<(), DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        let staff = inner.staff.get_mut(uid).ok_or(DirectoryError)?;
        staff.totp_secret = Some(secret_base32.to_string());
        staff.totp_confirmed = false;
        Ok(())
    }

    async fn totp_confirm(&self, uid: &str) -> Result<(), DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        let staff = inner.staff.get_mut(uid).ok_or(DirectoryError)?;
        if staff.totp_secret.is_none() {
            return Err(DirectoryError);
        }
        staff.totp_confirmed = true;
        Ok(())
    }

    async fn totp_secret_for(&self, uid: &str) -> Result<Option<String>, DirectoryError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .staff
            .get(uid)
            .and_then(|s| s.totp_secret.clone()))
    }

    async fn refresh_token_insert(
        &self,
        uid: &str,
        token_hash: &str,
        expires_at: OffsetDateTime,
        sid: &str,
        amr: &[String],
        mfa_at: Option<OffsetDateTime>,
    ) -> Result<(), DirectoryError> {
        self.inner.lock().unwrap().sessions.insert(
            token_hash.to_string(),
            FakeSession {
                staff_uid: uid.to_string(),
                expires_at,
                revoked_at: None,
                sid: sid.to_string(),
                amr: amr.to_vec(),
                mfa_at,
                last_used_at: now(),
            },
        );
        Ok(())
    }

    async fn refresh_token_lookup(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshRecord>, DirectoryError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .sessions
            .get(token_hash)
            .map(|s| RefreshRecord {
                staff_uid: s.staff_uid.clone(),
                expires_at: s.expires_at,
                revoked_at: s.revoked_at,
                sid: s.sid.clone(),
                amr: s.amr.clone(),
                mfa_at: s.mfa_at,
            }))
    }

    async fn refresh_token_revoke(&self, token_hash: &str) -> Result<(), DirectoryError> {
        if let Some(session) = self.inner.lock().unwrap().sessions.get_mut(token_hash) {
            session.revoked_at = Some(now());
        }
        Ok(())
    }

    async fn refresh_token_revoke_all(&self, uid: &str) -> Result<(), DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        for session in inner.sessions.values_mut() {
            if session.staff_uid == uid {
                session.revoked_at = Some(now());
            }
        }
        Ok(())
    }

    async fn session_revoke_family_by_token(&self, token_hash: &str) -> Result<(), DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        let Some(sid) = inner.sessions.get(token_hash).map(|s| s.sid.clone()) else {
            return Ok(());
        };
        for session in inner.sessions.values_mut() {
            if session.sid == sid {
                session.revoked_at = Some(now());
            }
        }
        Ok(())
    }

    async fn session_family_live(&self, sid: &str) -> Result<bool, DirectoryError> {
        let now = now();
        Ok(self
            .inner
            .lock()
            .unwrap()
            .sessions
            .values()
            .any(|s| s.sid == sid && s.revoked_at.is_none() && s.expires_at > now))
    }

    async fn session_rotate(
        &self,
        old_token_hash: &str,
        new_token_hash: &str,
        idle_cutoff: OffsetDateTime,
    ) -> Result<SessionRotateOutcome, DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        let Some(session) = inner.sessions.get(old_token_hash).cloned() else {
            return Ok(SessionRotateOutcome::Invalid);
        };

        if session.revoked_at.is_some() {
            // Reuse: kill the whole family.
            for other in inner.sessions.values_mut() {
                if other.sid == session.sid && other.revoked_at.is_none() {
                    other.revoked_at = Some(now());
                }
            }
            return Ok(SessionRotateOutcome::Reused {
                staff_uid: session.staff_uid,
            });
        }

        if session.expires_at <= now() || session.last_used_at <= idle_cutoff {
            return Ok(SessionRotateOutcome::Invalid);
        }

        inner.sessions.get_mut(old_token_hash).unwrap().revoked_at = Some(now());
        inner.sessions.insert(
            new_token_hash.to_string(),
            FakeSession {
                staff_uid: session.staff_uid.clone(),
                expires_at: session.expires_at,
                revoked_at: None,
                sid: session.sid.clone(),
                amr: session.amr.clone(),
                mfa_at: session.mfa_at,
                last_used_at: now(),
            },
        );
        Ok(SessionRotateOutcome::Rotated {
            staff_uid: session.staff_uid,
            sid: session.sid,
            amr: session.amr,
            mfa_at: session.mfa_at,
            expires_at: session.expires_at,
        })
    }

    async fn github_lookup(&self, github_id: i64) -> Result<Option<String>, DirectoryError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .github_links
            .get(&github_id)
            .cloned())
    }

    async fn record_audit(&self, event: AuditEvent) -> Result<(), DirectoryError> {
        self.inner.lock().unwrap().audit_events.push(event);
        Ok(())
    }

    /// A simplified re-implementation of `roles_set_tier`'s own rules
    /// (OBI-185, M-ADM-1): self-promotion, Phase-1 tier range, and actor
    /// tier floor. This is the fake's analogue of "the SQL function is
    /// the real boundary" -- tests exercise it to prove `AuthService`'s
    /// tier/step-up checks are UX, not the only thing standing between a
    /// caller and an illegal promotion.
    async fn admin_set_tier(
        &self,
        actor: &str,
        target_uid: &str,
        new_tier: i16,
        _reason: &str,
    ) -> Result<(), AdminDirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        inner.admin_set_tier_calls += 1;
        if actor == target_uid {
            return Err(AdminDirectoryError::Rejected(
                "self-promotion is not permitted".to_string(),
            ));
        }
        if !(1..=3).contains(&new_tier) {
            return Err(AdminDirectoryError::Rejected(
                "roles_set_tier may only set tiers 1-3 in Phase 1".to_string(),
            ));
        }
        let actor_tier = inner.staff.get(actor).map(|s| s.tier).unwrap_or(0);
        if actor_tier < 3 {
            return Err(AdminDirectoryError::Rejected(
                "actor tier may not change roles".to_string(),
            ));
        }
        let Some(staff) = inner.staff.get_mut(target_uid) else {
            return Err(AdminDirectoryError::Rejected(
                "no account found for uid".to_string(),
            ));
        };
        staff.tier = new_tier;
        Ok(())
    }

    async fn admin_audit_recent(
        &self,
        limit: i64,
        before_id: Option<i64>,
    ) -> Result<Vec<AdminAuditEntry>, AdminDirectoryError> {
        let inner = self.inner.lock().unwrap();
        if inner.fail_admin_audit {
            return Err(AdminDirectoryError::Unavailable);
        }
        let mut rows: Vec<AdminAuditEntry> = inner
            .audit_events
            .iter()
            .enumerate()
            .map(|(idx, event)| AdminAuditEntry {
                id: idx as i64,
                at: now(),
                kind: event.kind.to_string(),
                caller: event.uid.clone(),
                effective_principal: None,
                apply: None,
                class: None,
                argument: None,
                guard_set: Vec::new(),
                verdict: event.verdict.to_string(),
                detail: event.detail.clone(),
            })
            .collect();
        rows.reverse();
        if let Some(before) = before_id {
            rows.retain(|r| r.id < before);
        }
        rows.truncate(limit.max(0) as usize);
        Ok(rows)
    }
}

pub(crate) fn test_service(directory: FakeDirectory) -> AuthService {
    AuthService::new(
        Arc::new(directory),
        JwtKeys::single(
            [1u8; 32],
            "test-kid",
            "https://build.loommud.com/",
            jwt::AUDIENCE,
        ),
    )
}

fn ctx() -> AuthContext {
    AuthContext::default()
}

fn ctx_from(ip: &str) -> AuthContext {
    AuthContext::new(
        Some(ip.parse().unwrap()),
        Some("test-agent/1.0".to_string()),
    )
}

#[tokio::test]
async fn password_login_issues_a_token_with_tier_derived_scopes() {
    let directory = FakeDirectory::new();
    directory.add_staff("frodo", "ringbearer", 1);
    let service = test_service(directory);

    let pair = service
        .login("frodo", "ringbearer", None, &ctx())
        .await
        .unwrap();
    let claims = service.verify_access_token(&pair.access_token).unwrap();
    assert_eq!(claims.sub, "frodo");
    assert_eq!(claims.tier, 1);
    assert_eq!(claims.scopes, vec!["builder".to_string()]);
}

#[tokio::test]
async fn bad_password_is_refused() {
    let directory = FakeDirectory::new();
    directory.add_staff("frodo", "ringbearer", 1);
    let service = test_service(directory);

    let result = service.login("frodo", "wrong-password", None, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
}

/// Acceptance: "T3 without TOTP refused".
#[tokio::test]
async fn t3_staff_without_confirmed_totp_is_refused_even_with_correct_password() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory);

    let result = service.login("gandalf", "mithrandir", None, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::TotpRequired);

    // Supplying *some* code still doesn't help -- there's no secret to
    // check it against.
    let result = service
        .login("gandalf", "mithrandir", Some("123456"), &ctx())
        .await;
    assert_eq!(result.unwrap_err(), AuthError::TotpRequired);
}

/// Acceptance: T3+ with an enrolled+confirmed secret and a correct code
/// succeeds; a wrong code is refused distinctly from "none supplied".
#[tokio::test]
async fn t3_staff_with_confirmed_totp_can_log_in_with_a_correct_code() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory.clone());

    // Enrol via the service (same flow the HTTP handlers drive), but
    // confirm directly against the directory rather than through
    // `service.totp_confirm` -- TOTP codes are tied to real wall-clock
    // time, so going through the real confirm flow would consume *this
    // test's* one available real code and leave nothing left to prove a
    // later login succeeds with.
    let enrollment = service.totp_enroll("gandalf", &ctx()).await.unwrap();
    directory.confirm_totp_for_test("gandalf");
    let totp = totp::totp_for_secret(&enrollment.secret_base32, "gandalf").unwrap();

    // A stale/wrong code is refused distinctly from "none supplied".
    let result = service
        .login("gandalf", "mithrandir", Some("000000"), &ctx())
        .await;
    assert_eq!(result.unwrap_err(), AuthError::TotpInvalid);
    let result = service.login("gandalf", "mithrandir", None, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::TotpRequired);

    // The current code succeeds.
    let code = totp.generate_current().to_string();
    let pair = service
        .login("gandalf", "mithrandir", Some(&code), &ctx())
        .await
        .unwrap();
    let claims = service.verify_access_token(&pair.access_token).unwrap();
    assert_eq!(claims.tier, 3);
}

/// Acceptance: "tier escalation attempts" -- a forged access token (wrong
/// signing key) is rejected outright, and a promotion/demotion in
/// Postgres between issue and refresh is what the *next* access token
/// reflects, never a value a stale token or a replayed claim can carry
/// forward.
#[tokio::test]
async fn forged_access_token_is_rejected() {
    let directory = FakeDirectory::new();
    directory.add_staff("saruman", "istari", 1);
    let service = test_service(directory);

    let pair = service
        .login("saruman", "istari", None, &ctx())
        .await
        .unwrap();
    let claims = service.verify_access_token(&pair.access_token).unwrap();
    assert_eq!(claims.tier, 1);

    // Attacker re-signs the *same* claims (tier escalated to 5) with a
    // different key -- simulating "I control the JSON, not the secret".
    let forged_claims = AccessClaims { tier: 5, ..claims };
    let attacker_keys = JwtKeys::single(
        [2u8; 32],
        "test-kid",
        "https://build.loommud.com/",
        jwt::AUDIENCE,
    );
    let forged = attacker_keys.encode(&forged_claims).unwrap();

    assert!(service.verify_access_token(&forged).is_err());
}

/// Acceptance: "tier escalation attempts" -- refresh always re-derives
/// scopes from the directory's *current* tier, so a demotion takes effect
/// at the next refresh regardless of what the old access token or the
/// presented refresh token's holder might want.
#[tokio::test]
async fn refresh_reflects_the_directorys_current_tier_not_a_stale_claim() {
    let directory = FakeDirectory::new();
    directory.add_staff("boromir", "gondor", 1);
    let service = test_service(directory.clone());

    let pair = service
        .login("boromir", "gondor", None, &ctx())
        .await
        .unwrap();
    let claims = service.verify_access_token(&pair.access_token).unwrap();
    assert_eq!(claims.tier, 1);

    // An arch promotes boromir directly in the directory (Postgres, in
    // production) -- not through any token the client holds.
    directory.set_tier("boromir", 2);

    let refreshed = service.refresh(&pair.refresh_token, &ctx()).await.unwrap();
    let refreshed_claims = service
        .verify_access_token(&refreshed.access_token)
        .unwrap();
    assert_eq!(refreshed_claims.tier, 2);
    assert!(
        refreshed_claims
            .scopes
            .contains(&"domain:write".to_string())
    );

    // And a demotion takes effect just as readily.
    directory.set_tier("boromir", 0);
    let refreshed_again = service
        .refresh(&refreshed.refresh_token, &ctx())
        .await
        .unwrap();
    let claims_again = service
        .verify_access_token(&refreshed_again.access_token)
        .unwrap();
    assert_eq!(claims_again.tier, 0);
    assert!(claims_again.scopes.is_empty());
}

/// Acceptance: "expired ... refresh" refused.
#[tokio::test]
async fn expired_refresh_token_is_refused() {
    let directory = FakeDirectory::new();
    directory.add_staff("pippin", "took", 1);
    let service =
        test_service(directory).with_ttls(Duration::from_secs(600), Duration::from_millis(1));

    let pair = service.login("pippin", "took", None, &ctx()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let result = service.refresh(&pair.refresh_token, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidRefreshToken);
}

/// Acceptance (OBI-198, M-AUTH-5): "idle expiry enforced" -- a session
/// not rotated within the idle window is refused even though its 14-day
/// absolute expiry hasn't passed.
#[tokio::test]
async fn idle_expired_refresh_token_is_refused() {
    let directory = FakeDirectory::new();
    directory.add_staff("frodo", "ringbearer", 1);
    let service = test_service(directory.clone()).with_idle_ttl(Duration::from_secs(60));

    let pair = service
        .login("frodo", "ringbearer", None, &ctx())
        .await
        .unwrap();
    directory.backdate_last_used_for_test(
        &pair.refresh_token,
        OffsetDateTime::now_utc() - time::Duration::seconds(120),
    );

    let result = service.refresh(&pair.refresh_token, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidRefreshToken);
}

/// Acceptance (OBI-198, M-AUTH-5): a tier change (or TOTP reset/GitHub
/// unlink/password change/staff removal -- all funnel into the same
/// Postgres `staff_sessions_revoke_for_uid` trigger, see
/// `loom-persist/migrations/0008_staff_sessions.sql`) revokes every
/// session for the uid, not just one family.
#[tokio::test]
async fn revoke_all_for_uid_kills_every_family() {
    let directory = FakeDirectory::new();
    directory.add_staff("sam", "gaffer", 1);
    let service = test_service(directory.clone());

    let pair_a = service.login("sam", "gaffer", None, &ctx()).await.unwrap();
    let pair_b = service.login("sam", "gaffer", None, &ctx()).await.unwrap();

    directory.revoke_all_for_uid_for_test("sam");

    assert_eq!(
        service
            .refresh(&pair_a.refresh_token, &ctx())
            .await
            .unwrap_err(),
        AuthError::InvalidRefreshToken
    );
    assert_eq!(
        service
            .refresh(&pair_b.refresh_token, &ctx())
            .await
            .unwrap_err(),
        AuthError::InvalidRefreshToken
    );
}

/// Acceptance: "revoked ... refresh" refused, and a revoked-token replay
/// (stolen refresh token scenario) takes down the whole session family --
/// but a *different* family for the same uid is untouched (OBI-198:
/// family-scoped, not uid-wide).
#[tokio::test]
async fn revoked_refresh_token_is_refused_and_replay_revokes_the_family() {
    let directory = FakeDirectory::new();
    directory.add_staff("merry", "brandybuck", 1);
    let service = test_service(directory.clone());

    let pair = service
        .login("merry", "brandybuck", None, &ctx())
        .await
        .unwrap();
    service.logout(&pair.refresh_token).await.unwrap();
    assert!(directory.is_revoked(&pair.refresh_token));

    let result = service.refresh(&pair.refresh_token, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidRefreshToken);

    // Rotate a second, legitimate session *in a different family* (a
    // separate login), then simulate a thief replaying the *old*
    // rotated-out token -- every outstanding token in that token's family
    // should die, including the legitimately-rotated one, but a wholly
    // separate family for the same uid survives.
    let pair2 = service
        .login("merry", "brandybuck", None, &ctx())
        .await
        .unwrap();
    let other_family = service
        .login("merry", "brandybuck", None, &ctx())
        .await
        .unwrap();
    let rotated = service.refresh(&pair2.refresh_token, &ctx()).await.unwrap();
    // `pair2.refresh_token` is now revoked (rotated out); replaying it:
    let replay_result = service.refresh(&pair2.refresh_token, &ctx()).await;
    assert_eq!(replay_result.unwrap_err(), AuthError::InvalidRefreshToken);
    // The legitimately-rotated token is now dead too.
    let result = service.refresh(&rotated.refresh_token, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidRefreshToken);
    // A separate family for the same uid is untouched.
    let unaffected = service.refresh(&other_family.refresh_token, &ctx()).await;
    assert!(unaffected.is_ok());
}

/// Acceptance (OBI-203): a refreshed token keeps the login's `sid`,
/// `amr`, and `mfa_at` -- not a fresh `sid` per issuance and not
/// `amr: ["refresh"]`/`mfa_at: None`.
#[tokio::test]
async fn refresh_carries_forward_the_logins_sid_amr_and_mfa_at() {
    let directory = FakeDirectory::new();
    directory.add_staff("gimli", "dwarf", 3);
    let service = test_service(directory.clone());

    // Confirm directly against the directory rather than through
    // `service.totp_confirm` -- that would consume this test's one
    // deterministic real code (TOTP replay protection, OBI-195 review fix
    // 4) and leave nothing left for the login below to present.
    let enrollment = service.totp_enroll("gimli", &ctx()).await.unwrap();
    directory.confirm_totp_for_test("gimli");
    let totp = totp::totp_for_secret(&enrollment.secret_base32, "gimli").unwrap();

    let fresh_code = totp.generate_current().to_string();
    let pair = service
        .login("gimli", "dwarf", Some(&fresh_code), &ctx())
        .await
        .unwrap();
    let claims = service.verify_access_token(&pair.access_token).unwrap();
    assert_eq!(claims.amr, vec!["pwd".to_string(), "otp".to_string()]);
    assert!(claims.mfa_at.is_some());

    let refreshed = service.refresh(&pair.refresh_token, &ctx()).await.unwrap();
    let refreshed_claims = service
        .verify_access_token(&refreshed.access_token)
        .unwrap();
    // Same token family, not a fresh one.
    assert_eq!(refreshed_claims.sid, claims.sid);
    // The original login's authentication context, not "refresh".
    assert_eq!(refreshed_claims.amr, claims.amr);
    assert_eq!(refreshed_claims.mfa_at, claims.mfa_at);

    // A second rotation still carries the same family/context forward.
    let refreshed_again = service
        .refresh(&refreshed.refresh_token, &ctx())
        .await
        .unwrap();
    let claims_again = service
        .verify_access_token(&refreshed_again.access_token)
        .unwrap();
    assert_eq!(claims_again.sid, claims.sid);
    assert_eq!(claims_again.amr, claims.amr);
    assert_eq!(claims_again.mfa_at, claims.mfa_at);
}

#[tokio::test]
async fn unknown_refresh_token_is_refused() {
    let directory = FakeDirectory::new();
    let service = test_service(directory);
    let result = service.refresh("never-issued-token", &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidRefreshToken);
}

/// Acceptance: "OIDC for an unlinked GitHub user refused".
#[tokio::test]
async fn github_login_for_an_unlinked_user_is_refused() {
    let directory = FakeDirectory::new();
    let service = test_service(directory);
    let result = service.github_login(123456, None, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
}

#[tokio::test]
async fn github_login_for_a_linked_user_succeeds_and_reads_tier_from_the_directory() {
    let directory = FakeDirectory::new();
    directory.add_staff("samwise", "unused-password", 2);
    directory.link_github(42, "samwise");
    let service = test_service(directory);

    let pair = service.github_login(42, None, &ctx()).await.unwrap();
    let claims = service.verify_access_token(&pair.access_token).unwrap();
    assert_eq!(claims.sub, "samwise");
    assert_eq!(claims.tier, 2);
}

/// Acceptance (OBI-206): GitHub login shares the password path's rate
/// limiter -- repeated bad/unlinked GitHub ids lock out the same way
/// repeated bad passwords do, keyed by `github:{id}` rather than uid.
#[tokio::test]
async fn github_login_is_rate_limited_like_password_login() {
    let directory = FakeDirectory::new();
    let service = test_service(directory).with_rate_limiter(RateLimiter::with_test_tuning(
        3,
        Duration::from_secs(300),
        Duration::from_secs(300),
        100.0,
        Duration::from_secs(60),
    ));

    for _ in 0..3 {
        let result = service.github_login(555, None, &ctx()).await;
        assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
    }
    // The account-equivalent lockout now kicks in -- same response shape
    // as a locked password account, not a distinct "too many GitHub
    // attempts" error that would leak lockout state.
    let result = service.github_login(555, None, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
}

/// Acceptance (OBI-201, M-AUTH-7): "GitHub login of a T3 without TOTP is
/// refused" via the pending-token flow -- the callback can't carry a
/// `totp_code`, so it gets a pending token instead of a hard failure, and
/// that token (plus a code) completes the login without redoing OAuth.
#[tokio::test]
async fn github_login_pending_totp_completes_with_a_correct_code() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "unused-password", 3);
    directory.link_github(99, "gandalf");
    let service = test_service(directory.clone());

    let enrollment = service.totp_enroll("gandalf", &ctx()).await.unwrap();
    directory.confirm_totp_for_test("gandalf");
    let totp = totp::totp_for_secret(&enrollment.secret_base32, "gandalf").unwrap();

    let result = service.github_login(99, None, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::TotpRequired);

    let pending = service.issue_github_pending(99).unwrap();

    // A wrong code against the pending token is refused distinctly.
    let result = service
        .github_login_with_pending(&pending, Some("000000"), &ctx())
        .await;
    assert_eq!(result.unwrap_err(), AuthError::TotpInvalid);

    let fresh_code = totp.generate_current().to_string();
    let pair = service
        .github_login_with_pending(&pending, Some(&fresh_code), &ctx())
        .await
        .unwrap();
    let claims = service.verify_access_token(&pair.access_token).unwrap();
    assert_eq!(claims.sub, "gandalf");
    assert_eq!(claims.tier, 3);
}

/// A pending token signed with a different key (or for a different
/// purpose) is refused outright -- it must not be confused with an access
/// token or forgeable by anyone but this server.
#[tokio::test]
async fn github_pending_token_is_not_a_bearer_of_arbitrary_claims() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "unused-password", 1);
    directory.link_github(99, "gandalf");
    let service = test_service(directory);

    // A different (attacker-controlled) state-token key, not the
    // server's -- `AuthService` never exposes its own `StateTokenKey`,
    // only whether a token verifies against it (must-fix 2, PR #78 CTO
    // review: this signing domain is now entirely separate from the
    // EdDSA staff access-token keyset).
    let attacker_key = StateTokenKey::generate();
    let forged = attacker_key
        .encode(&GithubPendingClaims {
            github_id: 99,
            purpose: GITHUB_PENDING_PURPOSE.to_string(),
            iat: OffsetDateTime::now_utc().unix_timestamp(),
            exp: OffsetDateTime::now_utc().unix_timestamp() + 300,
        })
        .unwrap();
    let result = service
        .github_login_with_pending(&forged, None, &ctx())
        .await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidPendingToken);

    // A real access token, replayed as if it were a pending token, is also
    // refused -- `AccessClaims` has no `purpose` field, so deserialization
    // itself fails before the purpose check ever runs.
    let pair = service
        .login("gandalf", "unused-password", None, &ctx())
        .await
        .unwrap();
    let result = service
        .github_login_with_pending(&pair.access_token, None, &ctx())
        .await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidPendingToken);
}

/// The fake GitHub provider (used by the HTTP-layer test, exercised here
/// too) never fabricates a user for an unknown code.
#[tokio::test]
async fn fake_github_provider_refuses_an_unknown_code() {
    let provider = FakeGithubProvider::new().with_code("good-code", 7);
    assert!(
        provider
            .exchange_code("bad-code", "verifier")
            .await
            .is_err()
    );
    let user = provider
        .exchange_code("good-code", "verifier")
        .await
        .unwrap();
    assert_eq!(user.id, 7);
}

// -----------------------------------------------------------------------
// OBI-200: rate limiting, lockout, dummy-hash-adjacent behaviour, and
// audit_log wiring (M-AUTH-1, M-AUTH-2, M-AUTH-9).
// -----------------------------------------------------------------------

/// Acceptance: "6th failure locked out with the generic error".
#[tokio::test]
async fn sixth_failed_login_locks_the_account_with_the_generic_error() {
    let directory = FakeDirectory::new();
    directory.add_staff("frodo", "ringbearer", 1);
    let service = test_service(directory);

    for _ in 0..5 {
        let result = service.login("frodo", "wrong", None, &ctx()).await;
        assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
    }

    // 6th attempt is locked out -- even with the *correct* password, the
    // response is indistinguishable from a wrong one.
    let result = service.login("frodo", "ringbearer", None, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
}

/// A wrong TOTP code counts as a failure toward the same account lockout
/// as a wrong password ("TOTP attempts share the same limiter").
#[tokio::test]
async fn wrong_totp_codes_count_toward_the_account_lockout() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory);

    let enrollment = service.totp_enroll("gandalf", &ctx()).await.unwrap();
    let totp = totp::totp_for_secret(&enrollment.secret_base32, "gandalf").unwrap();
    let code = totp.generate_current().to_string();
    service
        .totp_confirm("gandalf", &code, &ctx())
        .await
        .unwrap();

    for _ in 0..5 {
        let result = service
            .login("gandalf", "mithrandir", Some("000000"), &ctx())
            .await;
        assert_eq!(result.unwrap_err(), AuthError::TotpInvalid);
    }

    // The account is now locked: even the correct password+code combo is
    // refused, with the same "invalid credentials" response.
    let fresh_code = totp.generate_current().to_string();
    let result = service
        .login("gandalf", "mithrandir", Some(&fresh_code), &ctx())
        .await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
}

/// OBI-204 acceptance: `login`'s wrong-password failures and
/// `totp_confirm`'s wrong-code failures land on the *same* account
/// counter -- both resolve to the one `uid:` namespaced key, so an
/// attacker can't double their effective guess budget by splitting
/// attempts across the two entry points.
#[tokio::test]
async fn wrong_login_password_and_wrong_totp_confirm_share_one_account_counter() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory);

    let enrollment = service.totp_enroll("gandalf", &ctx()).await.unwrap();
    let totp = totp::totp_for_secret(&enrollment.secret_base32, "gandalf").unwrap();
    let code = totp.generate_current().to_string();
    service
        .totp_confirm("gandalf", &code, &ctx())
        .await
        .unwrap();

    // 3 wrong login passwords...
    for _ in 0..3 {
        let result = service.login("gandalf", "wrong", None, &ctx()).await;
        assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
    }
    // ...and 2 wrong TOTP codes via totp_confirm -- 5 total against the
    // same account.
    for _ in 0..2 {
        let result = service.totp_confirm("gandalf", "000000", &ctx()).await;
        assert_eq!(result.unwrap_err(), AuthError::TotpInvalid);
    }

    // The account is now locked from the combined count -- even the
    // correct password+code combo is refused.
    let fresh_code = totp.generate_current().to_string();
    let result = service
        .login("gandalf", "mithrandir", Some(&fresh_code), &ctx())
        .await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
}

/// A missing TOTP code ("not supplied") is not a guess and must not count
/// toward the lockout.
#[tokio::test]
async fn a_missing_totp_code_does_not_count_as_a_failure() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory.clone());

    // Confirm directly against the directory rather than through
    // `service.totp_confirm` -- TOTP codes are tied to real wall-clock
    // time, so going through the real confirm flow would consume this
    // test's one available real code and leave nothing left to prove the
    // final login succeeds with (OBI-195 review fix 4 anti-replay).
    let enrollment = service.totp_enroll("gandalf", &ctx()).await.unwrap();
    directory.confirm_totp_for_test("gandalf");
    let totp = totp::totp_for_secret(&enrollment.secret_base32, "gandalf").unwrap();

    for _ in 0..10 {
        let result = service.login("gandalf", "mithrandir", None, &ctx()).await;
        assert_eq!(result.unwrap_err(), AuthError::TotpRequired);
    }

    // Still not locked -- the current code succeeds.
    let fresh_code = totp.generate_current().to_string();
    assert!(
        service
            .login("gandalf", "mithrandir", Some(&fresh_code), &ctx())
            .await
            .is_ok()
    );
}

/// OBI-204 CTO review: an in-flight reservation must never *itself* set
/// the lockout. After 4 wrong passwords, a correct password with no TOTP
/// code (`TotpRequired`, the normal two-step login flow) releases its
/// reservation; it must not leave the account locked for 15 minutes.
#[tokio::test]
async fn totp_required_after_four_failures_does_not_lock_the_account() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory.clone());

    let enrollment = service.totp_enroll("gandalf", &ctx()).await.unwrap();
    directory.confirm_totp_for_test("gandalf");
    let totp = totp::totp_for_secret(&enrollment.secret_base32, "gandalf").unwrap();

    for _ in 0..4 {
        let result = service.login("gandalf", "wrong", None, &ctx()).await;
        assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
    }
    let result = service.login("gandalf", "mithrandir", None, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::TotpRequired);

    let fresh_code = totp.generate_current().to_string();
    assert!(
        service
            .login("gandalf", "mithrandir", Some(&fresh_code), &ctx())
            .await
            .is_ok()
    );
}

/// Acceptance: "IP bucket" -- many login attempts against different
/// (nonexistent) accounts from one IP run the per-IP token bucket dry,
/// independent of any one account's own failure count.
#[tokio::test]
async fn ip_bucket_throttles_logins_across_many_accounts() {
    let directory = FakeDirectory::new();
    let service = test_service(directory).with_rate_limiter(RateLimiter::with_test_tuning(
        5,
        std::time::Duration::from_secs(900),
        std::time::Duration::from_secs(900),
        3.0,
        std::time::Duration::from_secs(3600),
    ));

    let from_ip = ctx_from("203.0.113.50");
    for i in 0..3 {
        let username = format!("nobody-{i}");
        let result = service.login(&username, "whatever", None, &from_ip).await;
        assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
    }
    let result = service.login("nobody-4", "whatever", None, &from_ip).await;
    assert_eq!(result.unwrap_err(), AuthError::RateLimited);

    // A different IP is unaffected.
    let other_ip = ctx_from("203.0.113.51");
    let result = service.login("nobody-5", "whatever", None, &other_ip).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
}

/// OBI-204 review fix: `login` checks the (cheap, no-DB) IP bucket
/// *before* resolving the username to a uid, so a throttled IP never pays
/// for that lookup.
#[tokio::test]
async fn login_checks_the_ip_bucket_before_resolving_the_account() {
    let directory = FakeDirectory::new();
    directory.add_staff("frodo", "ringbearer", 1);
    let service = test_service(directory.clone()).with_rate_limiter(RateLimiter::with_test_tuning(
        5,
        std::time::Duration::from_secs(900),
        std::time::Duration::from_secs(900),
        1.0,
        std::time::Duration::from_secs(3600),
    ));

    let from_ip = ctx_from("198.51.100.20");
    // Spends the IP bucket's one token.
    let _ = service.login("frodo", "wrong", None, &from_ip).await;
    assert_eq!(directory.resolve_uid_calls(), 1);

    // The bucket is now dry: a second attempt must be refused by the IP
    // check alone, without ever calling `resolve_uid` again.
    let result = service.login("frodo", "wrong", None, &from_ip).await;
    assert_eq!(result.unwrap_err(), AuthError::RateLimited);
    assert_eq!(directory.resolve_uid_calls(), 1);
}

/// Acceptance: "audit rows written for each event" -- login ok, login
/// fail, refresh reuse, and TOTP enrol/reset all land an audit row with
/// uid, IP, and user agent.
#[tokio::test]
async fn login_success_and_failure_are_audited() {
    let directory = FakeDirectory::new();
    directory.add_staff("frodo", "ringbearer", 1);
    let service = test_service(directory.clone());
    let from_ip = ctx_from("192.0.2.10");

    let _ = service.login("frodo", "wrong", None, &from_ip).await;
    let _ = service
        .login("frodo", "ringbearer", None, &from_ip)
        .await
        .unwrap();

    let events = directory.audit_events();
    let fail = events
        .iter()
        .find(|e| e.kind == "auth.login.fail")
        .expect("a login.fail row");
    assert_eq!(fail.verdict, "deny");
    assert_eq!(fail.ip, Some("192.0.2.10".parse().unwrap()));
    assert_eq!(fail.user_agent.as_deref(), Some("test-agent/1.0"));

    let ok = events
        .iter()
        .find(|e| e.kind == "auth.login.ok")
        .expect("a login.ok row");
    assert_eq!(ok.verdict, "allow");
    assert_eq!(ok.uid.as_deref(), Some("frodo"));
    assert_eq!(ok.ip, Some("192.0.2.10".parse().unwrap()));
}

#[tokio::test]
async fn refresh_reuse_is_audited() {
    let directory = FakeDirectory::new();
    directory.add_staff("merry", "brandybuck", 1);
    let service = test_service(directory.clone());
    let from_ip = ctx_from("192.0.2.20");

    let pair = service
        .login("merry", "brandybuck", None, &from_ip)
        .await
        .unwrap();
    let rotated = service
        .refresh(&pair.refresh_token, &from_ip)
        .await
        .unwrap();
    // Replaying the now-rotated-out token is reuse.
    let _ = service.refresh(&pair.refresh_token, &from_ip).await;

    let events = directory.audit_events();
    let reuse = events
        .iter()
        .find(|e| e.kind == "auth.refresh.reuse")
        .expect("a refresh.reuse row");
    assert_eq!(reuse.verdict, "deny");
    assert_eq!(reuse.uid.as_deref(), Some("merry"));
    assert_eq!(reuse.ip, Some("192.0.2.20".parse().unwrap()));
    let _ = rotated;
}

#[tokio::test]
async fn totp_enrol_and_reset_are_audited_distinctly() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory.clone());
    let from_ip = ctx_from("192.0.2.30");

    let _first = service.totp_enroll("gandalf", &from_ip).await.unwrap();

    // Re-enrolling before confirming is still allowed (OBI-195 review fix
    // 3 only refuses overwriting a *confirmed* secret) and is audited as
    // a reset, not a fresh enrolment.
    let second = service.totp_enroll("gandalf", &from_ip).await.unwrap();

    let events = directory.audit_events();
    assert!(events.iter().any(|e| e.kind == "auth.totp.enrol"));
    let reset = events
        .iter()
        .find(|e| e.kind == "auth.totp.reset")
        .expect("a totp.reset row");
    assert_eq!(reset.uid.as_deref(), Some("gandalf"));
    assert_eq!(reset.ip, Some("192.0.2.30".parse().unwrap()));

    // Once confirmed, a further enrol attempt is refused outright
    // (OBI-195 review fix 3) -- there is no "reset" path left through this
    // self-service endpoint; a real reset needs a dedicated, step-up-gated
    // flow (OBI-199 follow-up).
    let totp = totp::totp_for_secret(&second.secret_base32, "gandalf").unwrap();
    let code = totp.generate_current().to_string();
    service
        .totp_confirm("gandalf", &code, &from_ip)
        .await
        .unwrap();
    let result = service.totp_enroll("gandalf", &from_ip).await;
    assert_eq!(result.unwrap_err(), AuthError::TotpAlreadyEnrolled);
}

// -----------------------------------------------------------------------
// Wire-level: the same acceptance criteria exercised through the actual
// `/auth/login` HTTP route (axum router + `ConnectInfo` + `X-Forwarded-For`),
// not just `AuthService` directly.
// -----------------------------------------------------------------------
mod http_wire {
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use crate::HttpState;

    fn test_state(directory: FakeDirectory, service: AuthService) -> HttpState {
        let _ = directory;
        let (ws_accept_tx, _ws_accept_rx) = tokio::sync::mpsc::channel(1);
        HttpState::new(
            ws_accept_tx,
            loom_obs::Readiness::new(),
            loom_obs::PrometheusMetrics::new_unregistered(),
        )
        .with_auth(service)
    }

    fn login_request(xff: &str) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header("content-type", "application/json")
            .header("x-forwarded-for", xff)
            .body(Body::from(
                serde_json::json!({"username": "frodo", "password": "wrong"}).to_string(),
            ))
            .unwrap();
        // `axum::serve(...).into_make_service_with_connect_info` is what
        // inserts this extension in production; a direct `oneshot` call
        // bypasses that service wrapper, so insert it the same way here.
        let peer: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        request
    }

    async fn status_and_body(
        response: axum::response::Response,
    ) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, body)
    }

    /// Acceptance: "6th failure locked out with the generic error" --
    /// through the real `/auth/login` route, a locked account's 401 body
    /// is identical to a plain wrong-password 401.
    #[tokio::test]
    async fn sixth_failed_login_over_http_gets_the_generic_401() {
        let directory = FakeDirectory::new();
        directory.add_staff("frodo", "ringbearer", 1);
        let service = test_service(directory.clone());
        let app = crate::app(test_state(directory, service));

        for _ in 0..5 {
            let response = app
                .clone()
                .oneshot(login_request("192.0.2.99"))
                .await
                .unwrap();
            let (status, body) = status_and_body(response).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body["error"], "invalid_credentials");
        }

        let response = app.oneshot(login_request("192.0.2.99")).await.unwrap();
        let (status, body) = status_and_body(response).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_credentials");
    }

    /// `X-Forwarded-For` (the port-8080 invariant, M-AUTH-1) is what the
    /// IP bucket keys on, not the loopback `ConnectInfo` peer every
    /// `oneshot` request shares.
    #[tokio::test]
    async fn ip_throttle_is_keyed_on_x_forwarded_for() {
        let directory = FakeDirectory::new();
        let service =
            test_service(directory.clone()).with_rate_limiter(RateLimiter::with_test_tuning(
                5,
                std::time::Duration::from_secs(900),
                std::time::Duration::from_secs(900),
                2.0,
                std::time::Duration::from_secs(3600),
            ));
        let app = crate::app(test_state(directory, service));

        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(login_request("203.0.113.77"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let response = app
            .clone()
            .oneshot(login_request("203.0.113.77"))
            .await
            .unwrap();
        let (status, body) = status_and_body(response).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["error"], "rate_limited");

        // A different XFF value is unaffected -- same `ConnectInfo` peer.
        let response = app.oneshot(login_request("203.0.113.78")).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

/// OBI-195 review fix 2: TOTP must gate `refresh`, not just the original
/// password login -- a T2 promoted to T3 must stop being able to refresh
/// without a code the moment the next refresh happens.
#[tokio::test]
async fn promotion_to_t3_requires_totp_on_the_next_refresh() {
    let directory = FakeDirectory::new();
    directory.add_staff("aragorn", "strider", 2);
    let service = test_service(directory.clone());

    let pair = service
        .login("aragorn", "strider", None, &ctx())
        .await
        .unwrap();
    directory.set_tier("aragorn", 3);

    let result = service.refresh(&pair.refresh_token, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::TotpRequired);
}

/// OBI-195 review fix 2: GitHub login must gate TOTP for T3+ exactly like
/// the password path -- a linked GitHub identity does not bypass the
/// mandatory-TOTP floor.
#[tokio::test]
async fn github_login_for_t3_without_totp_is_refused() {
    let directory = FakeDirectory::new();
    directory.add_staff("elrond", "unused-password", 3);
    directory.link_github(99, "elrond");
    let service = test_service(directory);

    let result = service.github_login(99, None, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::TotpRequired);
}

/// OBI-195 review fix 2: GitHub login succeeds for a T3+ uid once a
/// correct TOTP code is supplied.
#[tokio::test]
async fn github_login_for_t3_with_totp_succeeds() {
    let directory = FakeDirectory::new();
    directory.add_staff("elrond", "unused-password", 3);
    directory.link_github(99, "elrond");
    let service = test_service(directory.clone());

    let enrollment = service.totp_enroll("elrond", &ctx()).await.unwrap();
    directory.confirm_totp_for_test("elrond");
    let totp = totp::totp_for_secret(&enrollment.secret_base32, "elrond").unwrap();

    let code = totp.generate_current().to_string();
    let pair = service.github_login(99, Some(&code), &ctx()).await.unwrap();
    let claims = service.verify_access_token(&pair.access_token).unwrap();
    assert_eq!(claims.tier, 3);
}

/// OBI-195 review fix 3: enrolling over an already-*confirmed* secret
/// using nothing but a bearer token is refused outright.
#[tokio::test]
async fn totp_enroll_refuses_to_overwrite_a_confirmed_secret() {
    let directory = FakeDirectory::new();
    directory.add_staff("gimli", "axe", 1);
    let service = test_service(directory);

    let enrollment = service.totp_enroll("gimli", &ctx()).await.unwrap();
    let totp = totp::totp_for_secret(&enrollment.secret_base32, "gimli").unwrap();
    let code = totp.generate_current().to_string();
    service.totp_confirm("gimli", &code, &ctx()).await.unwrap();

    let result = service.totp_enroll("gimli", &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::TotpAlreadyEnrolled);
}

/// OBI-195 review fix 3: enrolling is still fine before confirmation (a
/// user who started enrolling but never finished can retry).
#[tokio::test]
async fn totp_enroll_before_confirmation_can_be_retried() {
    let directory = FakeDirectory::new();
    directory.add_staff("gimli", "axe", 1);
    let service = test_service(directory);

    service.totp_enroll("gimli", &ctx()).await.unwrap();
    // Never confirmed -- re-enrolling (e.g. scanned the QR code wrong the
    // first time) must still work.
    service.totp_enroll("gimli", &ctx()).await.unwrap();
}

/// OBI-195 review fix 4: the same TOTP code can never be accepted twice,
/// even for two different logins inside the same 30s(+skew) step.
#[tokio::test]
async fn totp_code_replay_is_refused() {
    let directory = FakeDirectory::new();
    directory.add_staff("legolas", "bow", 3);
    let service = test_service(directory);

    let enrollment = service.totp_enroll("legolas", &ctx()).await.unwrap();
    let totp = totp::totp_for_secret(&enrollment.secret_base32, "legolas").unwrap();
    let code = totp.generate_current().to_string();
    service
        .totp_confirm("legolas", &code, &ctx())
        .await
        .unwrap();

    // The confirm call above already consumed this step's code -- using it
    // again at login must be refused as a replay, not accepted a second
    // time just because the signature still checks out.
    let result = service.login("legolas", "bow", Some(&code), &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::TotpInvalid);
}

/// OBI-195 review fix 5: a uid with no `staff` row at all (removed staff)
/// must never mint a token -- the old `tier_of`-based design defaulted
/// this to tier 0 and happily minted one.
#[tokio::test]
async fn refresh_for_a_removed_staff_row_is_refused_and_revokes_sessions() {
    let directory = FakeDirectory::new();
    directory.add_staff("boromir", "gondor", 1);
    let service = test_service(directory.clone());

    let pair = service
        .login("boromir", "gondor", None, &ctx())
        .await
        .unwrap();
    directory.remove_staff("boromir");

    let result = service.refresh(&pair.refresh_token, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
}

/// OBI-195 review fix 1: concurrent presentation of the same refresh
/// token can only ever rotate successfully once -- a second, racing
/// presentation always lands on reuse, never on a second success. (This
/// in-memory fake is single-threaded under its own mutex, so this mostly
/// documents the contract; the real concurrency proof is the
/// `loom-persist` integration test against live Postgres.)
#[tokio::test]
async fn concurrent_refresh_rotation_only_succeeds_once() {
    let directory = FakeDirectory::new();
    directory.add_staff("pippin", "took", 1);
    let service = test_service(directory);

    let pair = service.login("pippin", "took", None, &ctx()).await.unwrap();

    let first = service.refresh(&pair.refresh_token, &ctx()).await;
    let second = service.refresh(&pair.refresh_token, &ctx()).await;
    assert!(first.is_ok());
    assert_eq!(second.unwrap_err(), AuthError::InvalidRefreshToken);
}

// ---------------------------------------------------------------------------
// OBI-185 (P2-O2 admin UI): role management through `admin_set_tier`, and
// the audit view through `admin_audit_recent`. See
// `docs/threat-model-phase2.md` M-ADM-1 ("role mutations only through the
// existing `roles_*` security-definer functions; actor = the token's
// `sub`") and M-ADM-2 (step-up MFA + tier >= 3 for role changes).
// ---------------------------------------------------------------------------

fn fake_claims(sub: &str, tier: i16, mfa_at: Option<i64>) -> AccessClaims {
    let now_secs = now().unix_timestamp();
    AccessClaims {
        sub: sub.to_string(),
        tier,
        scopes: scopes_for_tier(tier),
        iss: "https://build.loommud.com/".to_string(),
        aud: jwt::AUDIENCE.to_string(),
        iat: now_secs,
        nbf: now_secs,
        exp: now_secs + 600,
        sid: "sid".to_string(),
        amr: vec!["pwd".to_string(), "otp".to_string()],
        mfa_at,
    }
}

/// M-ADM-2: a T3 actor with a fresh step-up may change another uid's
/// tier within `roles_set_tier`'s own rules, and the change (and its
/// audit row) actually lands.
#[tokio::test]
async fn admin_set_tier_succeeds_for_t3_with_fresh_step_up() {
    let directory = FakeDirectory::new();
    directory.add_staff("lead", "pw", 3);
    directory.add_staff("apprentice", "pw", 1);
    let service = test_service(directory.clone());

    let claims = fake_claims("lead", 3, Some(now().unix_timestamp()));
    service
        .admin_set_tier(&claims, &ctx(), "apprentice", 2, "promotion")
        .await
        .expect("T3 with fresh step-up may promote T1 -> T2");

    assert_eq!(directory.tier_of("apprentice"), Some(2));
    let events = directory.audit_events();
    assert!(
        events
            .iter()
            .any(|e| e.kind == "admin.roles.set_tier" && e.verdict == "allow"),
        "role change must be audited as allow: {events:?}"
    );
}

/// M-ADM-2: tier < 3 is refused by `AuthService` itself, before the
/// directory (and therefore the SQL function) is ever called.
#[tokio::test]
async fn admin_set_tier_forbidden_below_tier_3() {
    let directory = FakeDirectory::new();
    directory.add_staff("builder", "pw", 2);
    directory.add_staff("target", "pw", 1);
    let service = test_service(directory.clone());

    let claims = fake_claims("builder", 2, Some(now().unix_timestamp()));
    let result = service
        .admin_set_tier(&claims, &ctx(), "target", 2, "nope")
        .await;
    assert_eq!(result, Err(AdminError::Forbidden));
    assert_eq!(
        directory.admin_set_tier_calls(),
        0,
        "a forbidden caller must never reach the directory/SQL layer"
    );
    let events = directory.audit_events();
    assert!(
        events
            .iter()
            .any(|e| e.kind == "admin.roles.set_tier" && e.verdict == "deny"),
        "the forbidden attempt must still be audited: {events:?}"
    );
}

/// M-ADM-2: tier >= 3 but no fresh step-up (`mfa_at` absent or stale) is
/// refused -- a mere bearer token is not enough for a role change.
#[tokio::test]
async fn admin_set_tier_requires_fresh_step_up() {
    let directory = FakeDirectory::new();
    directory.add_staff("lead", "pw", 3);
    directory.add_staff("target", "pw", 1);
    let service = test_service(directory.clone());

    // No mfa_at at all.
    let claims = fake_claims("lead", 3, None);
    let result = service
        .admin_set_tier(&claims, &ctx(), "target", 2, "no mfa")
        .await;
    assert_eq!(result, Err(AdminError::StepUpRequired));

    // Stale mfa_at (older than the 5-minute window).
    let stale = fake_claims("lead", 3, Some(now().unix_timestamp() - 600));
    let result = service
        .admin_set_tier(&stale, &ctx(), "target", 2, "stale mfa")
        .await;
    assert_eq!(result, Err(AdminError::StepUpRequired));

    assert_eq!(directory.admin_set_tier_calls(), 0);
}

/// M-ADM-1: a request that somehow got a T5 claim is still refused for a
/// T3->T4 promotion -- `roles_set_tier`'s own Phase-1 range check (here
/// re-implemented by the fake, the real boundary in Postgres) is what
/// actually stops this, not `AuthService`'s tier floor (which only
/// enforces >= 3, not "<= 3"). This is the "even with the UI check
/// removed" acceptance test: nothing in `AuthService::admin_set_tier`
/// checks `new_tier` at all before calling the directory.
#[tokio::test]
async fn admin_set_tier_t3_to_t4_promotion_is_rejected_by_the_directory() {
    let directory = FakeDirectory::new();
    directory.add_staff("root", "pw", 5);
    directory.add_staff("target", "pw", 3);
    let service = test_service(directory.clone());

    let claims = fake_claims("root", 5, Some(now().unix_timestamp()));
    let result = service
        .admin_set_tier(&claims, &ctx(), "target", 4, "attempted T4 grant")
        .await;
    match result {
        Err(AdminError::Rejected(message)) => {
            assert!(message.contains("1-3"), "unexpected message: {message}")
        }
        other => panic!("expected AdminError::Rejected, got {other:?}"),
    }
    assert_eq!(
        directory.tier_of("target"),
        Some(3),
        "tier must be unchanged after the rejected call"
    );
}

/// M-ADM-1: the actor is always `claims.sub` -- there is no parameter on
/// `admin_set_tier` a caller-controlled body could use to override it.
/// (The HTTP-layer half of this guarantee -- a body `actor` field is a
/// 400 -- is covered by `admin::tests` in `loom-http`.)
#[tokio::test]
async fn admin_set_tier_self_promotion_is_rejected() {
    let directory = FakeDirectory::new();
    directory.add_staff("root", "pw", 5);
    let service = test_service(directory.clone());

    let claims = fake_claims("root", 5, Some(now().unix_timestamp()));
    let result = service
        .admin_set_tier(&claims, &ctx(), "root", 4, "self promotion")
        .await;
    assert!(matches!(result, Err(AdminError::Rejected(_))));
}

/// M-ADM-3/M-ADM-4: the audit view itself requires tier >= 3, and its
/// own access is audited.
#[tokio::test]
async fn admin_audit_recent_requires_tier_3_and_is_itself_audited() {
    let directory = FakeDirectory::new();
    directory.add_staff("builder", "pw", 2);
    directory.add_staff("lead", "pw", 3);
    let service = test_service(directory.clone());

    let low = fake_claims("builder", 2, Some(now().unix_timestamp()));
    assert_eq!(
        service
            .admin_audit_recent(&low, &ctx(), 10, None)
            .await
            .unwrap_err(),
        AdminError::Forbidden
    );

    let high = fake_claims("lead", 3, Some(now().unix_timestamp()));
    service
        .admin_audit_recent(&high, &ctx(), 10, None)
        .await
        .expect("T3 may view the audit log");

    let events = directory.audit_events();
    assert!(
        events.iter().any(|e| e.kind == "admin.audit.view"),
        "the audit view itself must be audited: {events:?}"
    );
}

/// M-ADM-4 (CTO review on PR #98): a directory failure on the audit view
/// itself is audited too, not just the tier-floor refusal -- every other
/// admin route's deny path (e.g. `admin_set_tier`'s `Rejected`/
/// `DirectoryUnavailable`) already does this; `admin_audit_recent` had
/// been the one exception.
#[tokio::test]
async fn admin_audit_recent_directory_failure_is_audited() {
    let directory = FakeDirectory::new();
    directory.add_staff("lead", "pw", 3);
    directory.fail_admin_audit();
    let service = test_service(directory.clone());

    let claims = fake_claims("lead", 3, Some(now().unix_timestamp()));
    let result = service.admin_audit_recent(&claims, &ctx(), 10, None).await;
    assert_eq!(result.unwrap_err(), AdminError::DirectoryUnavailable);

    let events = directory.audit_events();
    assert!(
        events
            .iter()
            .any(|e| e.kind == "admin.audit.view" && e.verdict == "deny"),
        "a directory failure on the audit view must still be audited: {events:?}"
    );
}

/// (CTO review on PR #98): the `/secure/` T5 floor for `admin_object_vars`
/// is a raw string check against an un-normalized path -- `valid_read`
/// on the world side is the real gate (it resolves the path for real),
/// so this is defense in depth only, but it should still fail *closed*
/// against the obvious bypass attempts rather than waving them through
/// as "definitely not /secure".
#[test]
fn is_or_might_be_secure_normalizes_and_fails_closed() {
    assert!(is_or_might_be_secure("/secure/master"));
    assert!(is_or_might_be_secure("//secure/master"), "repeated slashes");
    assert!(is_or_might_be_secure("/./secure/master"), "a . segment");
    assert!(
        is_or_might_be_secure("/../secure/master"),
        "a .. segment must fail closed, never be waved through"
    );
    assert!(!is_or_might_be_secure("/std/room"));
    assert!(
        !is_or_might_be_secure("/securex/room"),
        "prefix, not a segment"
    );
    assert!(
        is_or_might_be_secure("/std/../secure/master"),
        "a .. segment anywhere, not just first, must fail closed (CTO re-review \
         must-fix, PR #98 / T5 edge floor)"
    );
    assert!(
        is_or_might_be_secure("/std/x/../../secure/y"),
        "multiple .. segments must still fail closed"
    );
}
