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
}

#[derive(Default)]
struct FakeDirectoryInner {
    staff: HashMap<String, FakeStaff>, // keyed by username (== uid in these tests)
    refresh_tokens: HashMap<String, RefreshRecord>, // keyed by token_hash
    github_links: HashMap<i64, String>,
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
            },
        );
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

    async fn tier_of(&self, uid: &str) -> Result<i16, DirectoryError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .staff
            .get(uid)
            .map(|s| s.tier)
            .unwrap_or(0))
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
}

fn test_service(directory: FakeDirectory) -> AuthService {
    AuthService::new(
        Arc::new(directory),
        JwtKeys::from_secret(b"test-only-secret-not-for-prod"),
    )
}

#[tokio::test]
async fn password_login_issues_a_token_with_tier_derived_scopes() {
    let directory = FakeDirectory::new();
    directory.add_staff("frodo", "ringbearer", 1);
    let service = test_service(directory);

    let pair = service.login("frodo", "ringbearer", None).await.unwrap();
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

    let result = service.login("frodo", "wrong-password", None).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
}

/// Acceptance: "T3 without TOTP refused".
#[tokio::test]
async fn t3_staff_without_confirmed_totp_is_refused_even_with_correct_password() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory);

    let result = service.login("gandalf", "mithrandir", None).await;
    assert_eq!(result.unwrap_err(), AuthError::TotpRequired);

    // Supplying *some* code still doesn't help -- there's no secret to
    // check it against.
    let result = service.login("gandalf", "mithrandir", Some("123456")).await;
    assert_eq!(result.unwrap_err(), AuthError::TotpRequired);
}

/// Acceptance: T3+ with an enrolled+confirmed secret and a correct code
/// succeeds; a wrong code is refused distinctly from "none supplied".
#[tokio::test]
async fn t3_staff_with_confirmed_totp_can_log_in_with_a_correct_code() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory.clone());

    // Enrol + confirm, same flow the HTTP handlers drive.
    let enrollment = service.totp_enroll("gandalf").await.unwrap();
    let totp = totp::totp_for_secret(&enrollment.secret_base32, "gandalf").unwrap();
    let code = totp.generate_current().to_string();
    service.totp_confirm("gandalf", &code).await.unwrap();

    // A stale/wrong code is refused distinctly from "none supplied".
    let result = service.login("gandalf", "mithrandir", Some("000000")).await;
    assert_eq!(result.unwrap_err(), AuthError::TotpInvalid);
    let result = service.login("gandalf", "mithrandir", None).await;
    assert_eq!(result.unwrap_err(), AuthError::TotpRequired);

    // The current code succeeds.
    let fresh_code = totp.generate_current().to_string();
    let pair = service
        .login("gandalf", "mithrandir", Some(&fresh_code))
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

    let pair = service.login("saruman", "istari", None).await.unwrap();
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

    let pair = service.login("boromir", "gondor", None).await.unwrap();
    let claims = service.verify_access_token(&pair.access_token).unwrap();
    assert_eq!(claims.tier, 1);

    // An arch promotes boromir directly in the directory (Postgres, in
    // production) -- not through any token the client holds.
    directory.set_tier("boromir", 2);

    let refreshed = service.refresh(&pair.refresh_token).await.unwrap();
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
    let refreshed_again = service.refresh(&refreshed.refresh_token).await.unwrap();
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

    let pair = service.login("pippin", "took", None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let result = service.refresh(&pair.refresh_token).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidRefreshToken);
}

/// Acceptance: "revoked ... refresh" refused, and a revoked-token replay
/// (stolen refresh token scenario) takes down the whole session family.
#[tokio::test]
async fn revoked_refresh_token_is_refused_and_replay_revokes_the_family() {
    let directory = FakeDirectory::new();
    directory.add_staff("merry", "brandybuck", 1);
    let service = test_service(directory.clone());

    let pair = service.login("merry", "brandybuck", None).await.unwrap();
    service.logout(&pair.refresh_token).await.unwrap();
    assert!(directory.is_revoked(&pair.refresh_token));

    let result = service.refresh(&pair.refresh_token).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidRefreshToken);

    // Rotate a second, legitimate session, then simulate a thief replaying
    // the *old* rotated-out token -- every outstanding token for the uid
    // should die, including the legitimate rotated one.
    let pair2 = service.login("merry", "brandybuck", None).await.unwrap();
    let rotated = service.refresh(&pair2.refresh_token).await.unwrap();
    // `pair2.refresh_token` is now revoked (rotated out); replaying it:
    let replay_result = service.refresh(&pair2.refresh_token).await;
    assert_eq!(replay_result.unwrap_err(), AuthError::InvalidRefreshToken);
    // The legitimately-rotated token is now dead too.
    let result = service.refresh(&rotated.refresh_token).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidRefreshToken);
}

#[tokio::test]
async fn unknown_refresh_token_is_refused() {
    let directory = FakeDirectory::new();
    let service = test_service(directory);
    let result = service.refresh("never-issued-token").await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidRefreshToken);
}

/// Acceptance: "OIDC for an unlinked GitHub user refused".
#[tokio::test]
async fn github_login_for_an_unlinked_user_is_refused() {
    let directory = FakeDirectory::new();
    let service = test_service(directory);
    let result = service.github_login(123456).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
}

#[tokio::test]
async fn github_login_for_a_linked_user_succeeds_and_reads_tier_from_the_directory() {
    let directory = FakeDirectory::new();
    directory.add_staff("samwise", "unused-password", 2);
    directory.link_github(42, "samwise");
    let service = test_service(directory);

    let pair = service.github_login(42).await.unwrap();
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
