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
    totp_secret_enc: Option<Vec<u8>>,
    totp_confirmed: bool,
    mfa_at: Option<OffsetDateTime>,
}

#[derive(Default)]
struct FakeDirectoryInner {
    staff: HashMap<String, FakeStaff>, // keyed by username (== uid in these tests)
    refresh_tokens: HashMap<String, RefreshRecord>, // keyed by token_hash
    github_links: HashMap<i64, String>,
    recovery_codes: HashMap<String, Vec<(String, bool)>>, // uid -> [(hash, used)]
    audit_events: Vec<AuditEvent>,
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
                totp_secret_enc: None,
                totp_confirmed: false,
                mfa_at: None,
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

    fn audit_events(&self) -> Vec<AuditEvent> {
        self.inner.lock().unwrap().audit_events.clone()
    }

    /// Dump every `totp_secret_enc` blob as a lossy string, simulating a
    /// raw DB dump an attacker (or an auditor) might grep -- acceptance:
    /// "DB dump has no plaintext secret".
    fn dump_totp_blobs(&self) -> Vec<String> {
        self.inner
            .lock()
            .unwrap()
            .staff
            .values()
            .filter_map(|s| s.totp_secret_enc.as_ref())
            .map(|blob| String::from_utf8_lossy(blob).to_string())
            .collect()
    }

    fn set_mfa_at(&self, uid: &str, at: Option<OffsetDateTime>) {
        self.inner
            .lock()
            .unwrap()
            .staff
            .get_mut(uid)
            .unwrap()
            .mfa_at = at;
    }
}

fn is_fresh(mfa_at: Option<OffsetDateTime>) -> bool {
    match mfa_at {
        Some(at) => now() - at <= time::Duration::try_from(STEP_UP_WINDOW).unwrap(),
        None => false,
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
            totp_secret_enc: staff.totp_secret_enc.clone(),
            totp_confirmed: staff.totp_confirmed,
            mfa_at: staff.mfa_at,
        }))
    }

    async fn verify_password(&self, uid: &str, password: &str) -> Result<bool, DirectoryError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .staff
            .get(uid)
            .map(|s| s.password == password)
            .unwrap_or(false))
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

    async fn totp_enroll(&self, uid: &str, secret_ciphertext: &[u8]) -> Result<(), DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        let staff = inner.staff.get_mut(uid).ok_or(DirectoryError)?;
        staff.totp_secret_enc = Some(secret_ciphertext.to_vec());
        staff.totp_confirmed = false;
        inner.recovery_codes.remove(uid);
        Ok(())
    }

    async fn totp_confirm(&self, uid: &str) -> Result<(), DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        let staff = inner.staff.get_mut(uid).ok_or(DirectoryError)?;
        if staff.totp_secret_enc.is_none() {
            return Err(DirectoryError);
        }
        staff.totp_confirmed = true;
        Ok(())
    }

    async fn totp_secret_for(&self, uid: &str) -> Result<Option<Vec<u8>>, DirectoryError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .staff
            .get(uid)
            .and_then(|s| s.totp_secret_enc.clone()))
    }

    async fn totp_confirmed_for(&self, uid: &str) -> Result<bool, DirectoryError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .staff
            .get(uid)
            .map(|s| s.totp_confirmed)
            .unwrap_or(false))
    }

    async fn totp_admin_reset(
        &self,
        actor: &str,
        uid: &str,
        _reason: &str,
    ) -> Result<(), DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        let actor_fresh = inner
            .staff
            .get(actor)
            .map(|a| a.tier >= 4 && is_fresh(a.mfa_at))
            .unwrap_or(false);
        if !actor_fresh {
            return Err(DirectoryError);
        }
        let staff = inner.staff.get_mut(uid).ok_or(DirectoryError)?;
        staff.totp_secret_enc = None;
        staff.totp_confirmed = false;
        inner.recovery_codes.remove(uid);
        Ok(())
    }

    async fn mfa_touch(&self, uid: &str) -> Result<(), DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        let staff = inner.staff.get_mut(uid).ok_or(DirectoryError)?;
        staff.mfa_at = Some(now());
        Ok(())
    }

    async fn mfa_at_of(&self, uid: &str) -> Result<Option<OffsetDateTime>, DirectoryError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .staff
            .get(uid)
            .and_then(|s| s.mfa_at))
    }

    async fn recovery_codes_store(
        &self,
        uid: &str,
        code_hashes: &[String],
    ) -> Result<(), DirectoryError> {
        self.inner.lock().unwrap().recovery_codes.insert(
            uid.to_string(),
            code_hashes.iter().map(|h| (h.clone(), false)).collect(),
        );
        Ok(())
    }

    async fn recovery_code_consume(
        &self,
        uid: &str,
        code_hash: &str,
    ) -> Result<bool, DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        let Some(codes) = inner.recovery_codes.get_mut(uid) else {
            return Ok(false);
        };
        for (hash, used) in codes.iter_mut() {
            if hash == code_hash && !*used {
                *used = true;
                return Ok(true);
            }
        }
        Ok(false)
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

    async fn github_link(
        &self,
        actor: &str,
        uid: &str,
        github_id: i64,
        _reason: &str,
    ) -> Result<(), DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        let actor_tier_ok = inner.staff.get(actor).map(|a| a.tier >= 4).unwrap_or(false);
        let actor_fresh = inner
            .staff
            .get(actor)
            .map(|a| is_fresh(a.mfa_at))
            .unwrap_or(false);
        if !actor_tier_ok {
            return Err(DirectoryError);
        }
        if !actor_fresh {
            return Err(DirectoryError);
        }
        if !inner.staff.contains_key(uid) {
            return Err(DirectoryError);
        }
        inner.github_links.insert(github_id, uid.to_string());
        Ok(())
    }

    async fn github_unlink(
        &self,
        actor: &str,
        uid: &str,
        _reason: &str,
    ) -> Result<(), DirectoryError> {
        let mut inner = self.inner.lock().unwrap();
        let actor_tier_ok = inner.staff.get(actor).map(|a| a.tier >= 4).unwrap_or(false);
        let actor_fresh = inner
            .staff
            .get(actor)
            .map(|a| is_fresh(a.mfa_at))
            .unwrap_or(false);
        if !actor_tier_ok || !actor_fresh {
            return Err(DirectoryError);
        }
        let key = inner
            .github_links
            .iter()
            .find(|(_, linked_uid)| *linked_uid == uid)
            .map(|(id, _)| *id);
        match key {
            Some(id) => {
                inner.github_links.remove(&id);
                Ok(())
            }
            None => Err(DirectoryError),
        }
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
        TotpCipher::new(&[42u8; 32]),
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

/// Acceptance: "T3 without TOTP refused" -- still true: it's refused,
/// just with a bootstrap enrolment token to go enrol rather than a dead
/// end (OBI-199).
#[tokio::test]
async fn t3_staff_without_confirmed_totp_is_refused_even_with_correct_password() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory);

    let result = service.login("gandalf", "mithrandir", None, &ctx()).await;
    assert!(matches!(result, Err(AuthError::EnrolmentRequired(_))));

    // Supplying *some* code still doesn't help -- there's no secret to
    // check it against, only the enrolment path.
    let result = service
        .login("gandalf", "mithrandir", Some("123456"), &ctx())
        .await;
    assert!(matches!(result, Err(AuthError::EnrolmentRequired(_))));
}

/// Acceptance (OBI-199): "T3 bootstrap enrolment works end-to-end" -- a
/// T3+ staff member with *no* TOTP ever enrolled gets a narrow enrolment
/// token from `login` (not a bare refusal with nothing to do about it),
/// and that token -- not a normal access token, which this account cannot
/// obtain -- is enough to enrol, confirm, and then log in for real.
#[tokio::test]
async fn t3_bootstrap_enrolment_works_end_to_end() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory.clone());

    let result = service.login("gandalf", "mithrandir", None, &ctx()).await;
    let Err(AuthError::EnrolmentRequired(enrol_token)) = result else {
        panic!("expected EnrolmentRequired, got {result:?}");
    };

    let enrol_claims = service.verify_access_token(&enrol_token).unwrap();
    assert_eq!(enrol_claims.sub, "gandalf");
    assert_eq!(enrol_claims.aud, ENROL_AUDIENCE);
    assert!(enrol_claims.scopes.is_empty());
    assert_eq!(
        enrol_claims.tier, 0,
        "the enrolment token itself authorizes nothing"
    );

    // The enrolment-only token's `sub` is what a real deployment's
    // `/auth/totp/enroll` handler trusts (see handlers::totp_enroll) --
    // exercise the same call the handler makes.
    let enrollment = service
        .totp_enroll(&enrol_claims.sub, "mithrandir", None, &ctx())
        .await
        .unwrap();
    let totp = totp::totp_for_secret(&enrollment.secret_base32, "gandalf").unwrap();
    let code = totp.generate_current().to_string();
    let recovery_codes = service
        .totp_confirm("gandalf", &code, &ctx())
        .await
        .unwrap();
    assert_eq!(recovery_codes.len(), RECOVERY_CODE_COUNT);

    // Now a real login succeeds with a fresh code.
    let fresh_code = totp.generate_current().to_string();
    let pair = service
        .login("gandalf", "mithrandir", Some(&fresh_code), &ctx())
        .await
        .unwrap();
    let claims = service.verify_access_token(&pair.access_token).unwrap();
    assert_eq!(claims.aud, ACCESS_AUDIENCE);
    assert_eq!(claims.tier, 3);
}

/// Acceptance (OBI-199): a wrong password at the enrolment step is
/// refused even with a valid enrolment-only token -- the token alone is
/// not sufficient, password re-entry is still required.
#[tokio::test]
async fn totp_enroll_requires_the_password_again() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory);

    let result = service
        .totp_enroll("gandalf", "wrong-password", None, &ctx())
        .await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
}

/// Acceptance (OBI-199): "recovery code single-use" -- confirming TOTP
/// issues 10 codes; each logs a user in exactly once, and a second
/// attempt with the same code is refused.
#[tokio::test]
async fn recovery_code_is_single_use() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory);

    let enrollment = service
        .totp_enroll("gandalf", "mithrandir", None, &ctx())
        .await
        .unwrap();
    let totp = totp::totp_for_secret(&enrollment.secret_base32, "gandalf").unwrap();
    let code = totp.generate_current().to_string();
    let recovery_codes = service
        .totp_confirm("gandalf", &code, &ctx())
        .await
        .unwrap();
    assert_eq!(recovery_codes.len(), RECOVERY_CODE_COUNT);

    let recovery_code = &recovery_codes[0];

    // First use succeeds (no TOTP code supplied -- the recovery code
    // alone satisfies the gate).
    let pair = service
        .login("gandalf", "mithrandir", Some(recovery_code), &ctx())
        .await
        .unwrap();
    let claims = service.verify_access_token(&pair.access_token).unwrap();
    assert_eq!(claims.tier, 3);

    // Second use of the *same* code is refused.
    let result = service
        .login("gandalf", "mithrandir", Some(recovery_code), &ctx())
        .await;
    assert_eq!(result.unwrap_err(), AuthError::TotpInvalid);

    // A different, still-unused code still works.
    let other_code = &recovery_codes[1];
    let pair = service
        .login("gandalf", "mithrandir", Some(other_code), &ctx())
        .await
        .unwrap();
    assert_eq!(
        service
            .verify_access_token(&pair.access_token)
            .unwrap()
            .tier,
        3
    );
}

/// Acceptance (OBI-199): "DB dump has no plaintext secret" -- whatever
/// `totp_secret_enc` blob ends up in the (fake) directory never contains
/// the plaintext base32 secret as a substring.
#[tokio::test]
async fn totp_secret_is_never_stored_in_plaintext() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory.clone());

    let enrollment = service
        .totp_enroll("gandalf", "mithrandir", None, &ctx())
        .await
        .unwrap();

    for blob in directory.dump_totp_blobs() {
        assert!(
            !blob.contains(&enrollment.secret_base32),
            "the stored blob must never contain the plaintext secret"
        );
    }
}

/// Acceptance (OBI-199): "link without fresh mfa_at refused" -- an actor
/// with the right tier (T4+) but a stale (or absent) `mfa_at` cannot link
/// a GitHub identity; only a recent step-up succeeds.
#[tokio::test]
async fn github_link_without_fresh_step_up_is_refused() {
    let directory = FakeDirectory::new();
    directory.add_staff("elrond", "vilya", 4); // T4 arch, no mfa_at yet
    directory.add_staff("legolas", "mirkwood", 1);
    let service = test_service(directory.clone());

    // No step-up at all yet.
    let result = service
        .github_link("elrond", "legolas", 99, "onboarding")
        .await;
    assert_eq!(result.unwrap_err(), AuthError::StepUpRequired);
    assert!(service.github_login(99).await.is_err());

    // A stale mfa_at (older than the 5-minute window) still refuses.
    directory.set_mfa_at("elrond", Some(now() - time::Duration::minutes(10)));
    let result = service
        .github_link("elrond", "legolas", 99, "onboarding")
        .await;
    assert_eq!(result.unwrap_err(), AuthError::StepUpRequired);

    // A fresh step-up (simulating a just-verified TOTP code) allows it.
    directory.set_mfa_at("elrond", Some(now()));
    service
        .github_link("elrond", "legolas", 99, "onboarding")
        .await
        .unwrap();
    let pair = service.github_login(99).await.unwrap();
    assert_eq!(
        service.verify_access_token(&pair.access_token).unwrap().sub,
        "legolas"
    );
}

/// Acceptance (OBI-199): unlink is now possible at all, and is just as
/// step-up-gated as link.
#[tokio::test]
async fn github_unlink_requires_step_up_and_then_removes_the_link() {
    let directory = FakeDirectory::new();
    directory.add_staff("elrond", "vilya", 4);
    directory.add_staff("legolas", "mirkwood", 1);
    directory.link_github(99, "legolas");
    let service = test_service(directory.clone());

    let result = service
        .github_unlink("elrond", "legolas", "offboarding")
        .await;
    assert_eq!(result.unwrap_err(), AuthError::StepUpRequired);

    directory.set_mfa_at("elrond", Some(now()));
    service
        .github_unlink("elrond", "legolas", "offboarding")
        .await
        .unwrap();
    assert!(service.github_login(99).await.is_err());
}

/// Acceptance: T3+ with an enrolled+confirmed secret and a correct code
/// succeeds; a wrong code is refused distinctly from "none supplied".
#[tokio::test]
async fn t3_staff_with_confirmed_totp_can_log_in_with_a_correct_code() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory.clone());

    // Enrol + confirm, same flow the HTTP handlers drive.
    let enrollment = service
        .totp_enroll("gandalf", "mithrandir", None, &ctx())
        .await
        .unwrap();
    let totp = totp::totp_for_secret(&enrollment.secret_base32, "gandalf").unwrap();
    let code = totp.generate_current().to_string();
    service
        .totp_confirm("gandalf", &code, &ctx())
        .await
        .unwrap();

    // A stale/wrong code is refused distinctly from "none supplied".
    let result = service
        .login("gandalf", "mithrandir", Some("000000"), &ctx())
        .await;
    assert_eq!(result.unwrap_err(), AuthError::TotpInvalid);
    let result = service.login("gandalf", "mithrandir", None, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::TotpRequired);

    // The current code succeeds.
    let fresh_code = totp.generate_current().to_string();
    let pair = service
        .login("gandalf", "mithrandir", Some(&fresh_code), &ctx())
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

    let result = service.refresh(&pair.refresh_token, &ctx()).await;
    assert_eq!(result.unwrap_err(), AuthError::InvalidRefreshToken);

    // Rotate a second, legitimate session, then simulate a thief replaying
    // the *old* rotated-out token -- every outstanding token for the uid
    // should die, including the legitimate rotated one.
    let pair2 = service
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

    let enrollment = service
        .totp_enroll("gandalf", "mithrandir", None, &ctx())
        .await
        .unwrap();
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

/// A missing TOTP code ("not supplied") is not a guess and must not count
/// toward the lockout.
#[tokio::test]
async fn a_missing_totp_code_does_not_count_as_a_failure() {
    let directory = FakeDirectory::new();
    directory.add_staff("gandalf", "mithrandir", 3);
    let service = test_service(directory);

    let enrollment = service
        .totp_enroll("gandalf", "mithrandir", None, &ctx())
        .await
        .unwrap();
    let totp = totp::totp_for_secret(&enrollment.secret_base32, "gandalf").unwrap();
    let code = totp.generate_current().to_string();
    service
        .totp_confirm("gandalf", &code, &ctx())
        .await
        .unwrap();

    for _ in 0..10 {
        let result = service.login("gandalf", "mithrandir", None, &ctx()).await;
        assert_eq!(result.unwrap_err(), AuthError::TotpRequired);
    }

    // Still not locked -- a fresh code succeeds.
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

    let first = service
        .totp_enroll("gandalf", "mithrandir", None, &from_ip)
        .await
        .unwrap();
    let totp = totp::totp_for_secret(&first.secret_base32, "gandalf").unwrap();
    let code = totp.generate_current().to_string();
    service
        .totp_confirm("gandalf", &code, &from_ip)
        .await
        .unwrap();

    // Re-enrolling over an already-confirmed secret is a reset: it has a
    // fresh step-up already (totp_confirm just touched mfa_at), and needs
    // a valid code against the current secret.
    let reset_code = totp.generate_current().to_string();
    let _ = service
        .totp_enroll("gandalf", "mithrandir", Some(&reset_code), &from_ip)
        .await
        .unwrap();

    let events = directory.audit_events();
    assert!(events.iter().any(|e| e.kind == "auth.totp.enrol"));
    let reset = events
        .iter()
        .find(|e| e.kind == "auth.totp.reset")
        .expect("a totp.reset row");
    assert_eq!(reset.uid.as_deref(), Some("gandalf"));
    assert_eq!(reset.ip, Some("192.0.2.30".parse().unwrap()));
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
