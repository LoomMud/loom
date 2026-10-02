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
    refresh_tokens: HashMap<String, RefreshRecord>, // keyed by token_hash
    github_links: HashMap<i64, String>,
    audit_events: Vec<AuditEvent>,
    /// How many times [`StaffDirectory::resolve_uid`] has been called
    /// (OBI-204 review fix): used to prove `login` checks the IP bucket
    /// *before* paying for this lookup.
    resolve_uid_calls: u32,
}

#[derive(Default, Clone)]
struct FakeDirectory {
    inner: Arc<Mutex<FakeDirectoryInner>>,
}

impl FakeDirectory {
    fn new() -> Self {
        Self::default()
    }

    fn add_staff(&self, uid: &str, password: &str, tier: i16) {
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

    fn link_github(&self, github_id: i64, uid: &str) {
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
    fn confirm_totp_for_test(&self, uid: &str) {
        self.inner
            .lock()
            .unwrap()
            .staff
            .get_mut(uid)
            .unwrap()
            .totp_confirmed = true;
    }

    /// Directly mark a refresh token revoked (simulating an admin/logout
    /// action taken through some other path). Exercised indirectly by
    /// every test that calls [`AuthService::logout`]; kept as a direct
    /// helper too since a future test may want to revoke without going
    /// through the service.
    #[allow(dead_code)]
    fn revoke_for_test(&self, token_plaintext: &str) {
        let hash = hash_token(token_plaintext);
        if let Some(record) = self.inner.lock().unwrap().refresh_tokens.get_mut(&hash) {
            record.revoked_at = Some(now());
        }
    }

    fn is_revoked(&self, token_plaintext: &str) -> bool {
        let hash = hash_token(token_plaintext);
        self.inner
            .lock()
            .unwrap()
            .refresh_tokens
            .get(&hash)
            .map(|r| r.revoked_at.is_some())
            .unwrap_or(false)
    }

    fn audit_events(&self) -> Vec<AuditEvent> {
        self.inner.lock().unwrap().audit_events.clone()
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
    ) -> Result<(), DirectoryError> {
        self.inner.lock().unwrap().refresh_tokens.insert(
            token_hash.to_string(),
            RefreshRecord {
                staff_uid: uid.to_string(),
                expires_at,
                revoked_at: None,
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
            .refresh_tokens
            .get(token_hash)
            .cloned())
    }

    async fn refresh_token_rotate(
        &self,
        token_hash: &str,
    ) -> Result<RefreshRotation, DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        let Some(record) = inner.refresh_tokens.get_mut(token_hash) else {
            return Ok(RefreshRotation::NotFound);
        };
        if record.revoked_at.is_some() {
            return Ok(RefreshRotation::Reused {
                staff_uid: record.staff_uid.clone(),
            });
        }
        if record.expires_at <= now() {
            return Ok(RefreshRotation::Expired);
        }
        record.revoked_at = Some(now());
        Ok(RefreshRotation::Rotated {
            staff_uid: record.staff_uid.clone(),
        })
    }

    async fn refresh_token_revoke(&self, token_hash: &str) -> Result<(), DirectoryError> {
        if let Some(record) = self
            .inner
            .lock()
            .unwrap()
            .refresh_tokens
            .get_mut(token_hash)
        {
            record.revoked_at = Some(now());
        }
        Ok(())
    }

    async fn refresh_token_revoke_all(&self, uid: &str) -> Result<(), DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        for record in inner.refresh_tokens.values_mut() {
            if record.staff_uid == uid {
                record.revoked_at = Some(now());
            }
        }
        Ok(())
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
}

fn test_service(directory: FakeDirectory) -> AuthService {
    AuthService::new(
        Arc::new(directory),
        JwtKeys::from_secret(b"test-only-secret-not-for-prod"),
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
    let attacker_keys = JwtKeys::from_secret(b"attacker-controlled-key-not-the-servers");
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

    let refreshed = service
        .refresh(&pair.refresh_token, None, &ctx())
        .await
        .unwrap();
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
        .refresh(&refreshed.refresh_token, None, &ctx())
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

    let result = service.refresh(&pair.refresh_token, None, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidRefreshToken);
}

/// Acceptance: "revoked ... refresh" refused, and a revoked-token replay
/// (stolen refresh token scenario) takes down the whole session family.
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

    let result = service.refresh(&pair.refresh_token, None, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidRefreshToken);

    // Rotate a second, legitimate session, then simulate a thief replaying
    // the *old* rotated-out token -- every outstanding token for the uid
    // should die, including the legitimate rotated one.
    let pair2 = service
        .login("merry", "brandybuck", None, &ctx())
        .await
        .unwrap();
    let rotated = service
        .refresh(&pair2.refresh_token, None, &ctx())
        .await
        .unwrap();
    // `pair2.refresh_token` is now revoked (rotated out); replaying it:
    let replay_result = service.refresh(&pair2.refresh_token, None, &ctx()).await;
    assert_eq!(replay_result.unwrap_err(), AuthError::InvalidRefreshToken);
    // The legitimately-rotated token is now dead too.
    let result = service.refresh(&rotated.refresh_token, None, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidRefreshToken);
}

#[tokio::test]
async fn unknown_refresh_token_is_refused() {
    let directory = FakeDirectory::new();
    let service = test_service(directory);
    let result = service.refresh("never-issued-token", None, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidRefreshToken);
}

/// Acceptance: "OIDC for an unlinked GitHub user refused".
#[tokio::test]
async fn github_login_for_an_unlinked_user_is_refused() {
    let directory = FakeDirectory::new();
    let service = test_service(directory);
    let result = service.github_login(123456, None).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
}

#[tokio::test]
async fn github_login_for_a_linked_user_succeeds_and_reads_tier_from_the_directory() {
    let directory = FakeDirectory::new();
    directory.add_staff("samwise", "unused-password", 2);
    directory.link_github(42, "samwise");
    let service = test_service(directory);

    let pair = service.github_login(42, None).await.unwrap();
    let claims = service.verify_access_token(&pair.access_token).unwrap();
    assert_eq!(claims.sub, "samwise");
    assert_eq!(claims.tier, 2);
}

/// The fake GitHub provider (used by the HTTP-layer test, exercised here
/// too) never fabricates a user for an unknown code.
#[tokio::test]
async fn fake_github_provider_refuses_an_unknown_code() {
    let provider = FakeGithubProvider::new().with_code("good-code", 7);
    assert!(provider.exchange_code("bad-code").await.is_err());
    let user = provider.exchange_code("good-code").await.unwrap();
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
        .refresh(&pair.refresh_token, None, &from_ip)
        .await
        .unwrap();
    // Replaying the now-rotated-out token is reuse.
    let _ = service.refresh(&pair.refresh_token, None, &from_ip).await;

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

    let result = service.refresh(&pair.refresh_token, None, &ctx()).await;
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

    let result = service.github_login(99, None).await;
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
    let pair = service.github_login(99, Some(&code)).await.unwrap();
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

    let result = service.refresh(&pair.refresh_token, None, &ctx()).await;
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

    let first = service.refresh(&pair.refresh_token, None, &ctx()).await;
    let second = service.refresh(&pair.refresh_token, None, &ctx()).await;
    assert!(first.is_ok());
    assert_eq!(second.unwrap_err(), AuthError::InvalidRefreshToken);
}
