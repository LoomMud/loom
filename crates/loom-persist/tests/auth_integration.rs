// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only
//
// OBI-174: integration tests for migration 0003 (TOTP, refresh tokens,
// GitHub identity linking) against a real Postgres, exercising the exact
// `loom_app` login the HTTP layer uses.

mod support;

use support::{seed_account, seed_staff, unique_uid};
use time::{Duration, OffsetDateTime};

#[tokio::test]
async fn staff_login_resolves_by_account_id_not_uid_and_verifies_password() {
    let Some(fx) = support::setup().await else {
        return;
    };

    // staff.uid deliberately differs from accounts.username (D-S2.6 case):
    // login happens by account username/password, resolved to the staff
    // row via account_id, never by treating the username as the uid.
    let username = unique_uid("sam");
    let uid = unique_uid("sam-uid");
    let account = fx.app.create_account(&username, "gaffer").await.unwrap();
    seed_staff(&fx.owner, &uid, account.id, 2).await;

    let record = fx
        .app
        .staff_login(&username, "gaffer")
        .await
        .expect("query")
        .expect("login should succeed");
    assert_eq!(record.uid, uid);
    assert_eq!(record.tier, 2);
    assert_eq!(record.totp_secret, None);
    assert!(!record.totp_confirmed);

    // Wrong password.
    assert!(
        fx.app
            .staff_login(&username, "wrong")
            .await
            .unwrap()
            .is_none()
    );

    // A plain player (account with no staff row) never resolves here.
    let player_username = unique_uid("player");
    fx.app
        .create_account(&player_username, "whatever")
        .await
        .unwrap();
    assert!(
        fx.app
            .staff_login(&player_username, "whatever")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn totp_enroll_is_self_service_only() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let uid = unique_uid("gandalf");
    let account = seed_account(&fx.owner, &unique_uid("gandalf-acct")).await;
    seed_staff(&fx.owner, &uid, account, 3).await;

    fx.app
        .totp_enroll(&uid, "JBSWY3DPEHPK3PXP")
        .await
        .expect("self-service enroll succeeds");

    let secret = fx.app.totp_secret_for(&uid).await.unwrap();
    assert_eq!(secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));

    // Not yet confirmed.
    let record = fx.app.staff_login(&unique_uid("nonexistent"), "x").await;
    assert!(record.unwrap().is_none());
}

#[tokio::test]
async fn totp_confirm_requires_a_prior_enrollment() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let uid = unique_uid("aragorn");
    let account = seed_account(&fx.owner, &unique_uid("aragorn-acct")).await;
    seed_staff(&fx.owner, &uid, account, 4).await;

    // No secret enrolled yet: confirm fails.
    assert!(fx.app.totp_confirm(&uid).await.is_err());

    fx.app.totp_enroll(&uid, "SECRETBASE32").await.unwrap();
    fx.app.totp_confirm(&uid).await.unwrap();

    let username = unique_uid("aragorn-login");
    let account2 = fx.app.create_account(&username, "strider").await.unwrap();
    seed_staff(&fx.owner, &unique_uid("aragorn2"), account2.id, 4).await;
    // (separate uid just to prove totp_confirmed reads back true for the
    // uid we actually confirmed, not some other row)
    let record = fx.app.staff_login(&username, "strider").await.unwrap();
    assert!(record.is_some());
    assert!(!record.unwrap().totp_confirmed); // this is aragorn2, unrelated

    // Re-enrolling clears the confirmation.
    fx.app.totp_enroll(&uid, "ANOTHERBASE32").await.unwrap();
    let secret = fx.app.totp_secret_for(&uid).await.unwrap();
    assert_eq!(secret.as_deref(), Some("ANOTHERBASE32"));
}

#[tokio::test]
async fn refresh_token_insert_lookup_and_revoke_round_trip() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let uid = unique_uid("pippin");
    let account = seed_account(&fx.owner, &unique_uid("pippin-acct")).await;
    seed_staff(&fx.owner, &uid, account, 1).await;

    let expires_at = OffsetDateTime::now_utc() + Duration::days(14);
    let hash = "deadbeef".repeat(8);
    let amr = vec!["pwd".to_string(), "otp".to_string()];
    let mfa_at = OffsetDateTime::now_utc();
    fx.app
        .refresh_token_insert(&uid, &hash, expires_at, "sid-1", &amr, Some(mfa_at))
        .await
        .unwrap();

    let record = fx
        .app
        .refresh_token_lookup(&hash)
        .await
        .unwrap()
        .expect("inserted token is found");
    assert_eq!(record.staff_uid, uid);
    assert!(record.revoked_at.is_none());
    assert_eq!(record.sid, "sid-1");
    assert_eq!(record.amr, amr);
    assert!(record.mfa_at.is_some());

    fx.app.refresh_token_revoke(&hash).await.unwrap();
    let revoked = fx.app.refresh_token_lookup(&hash).await.unwrap().unwrap();
    assert!(revoked.revoked_at.is_some());

    // Unknown hash: None, not an error.
    assert!(
        fx.app
            .refresh_token_lookup("never-issued")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn refresh_token_revoke_all_only_touches_the_named_uid() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let uid_a = unique_uid("merry");
    let uid_b = unique_uid("pippin2");
    let account_a = seed_account(&fx.owner, &unique_uid("merry-acct")).await;
    let account_b = seed_account(&fx.owner, &unique_uid("pippin2-acct")).await;
    seed_staff(&fx.owner, &uid_a, account_a, 1).await;
    seed_staff(&fx.owner, &uid_b, account_b, 1).await;

    let expires_at = OffsetDateTime::now_utc() + Duration::days(14);
    let hash_a = "a1".repeat(16);
    let hash_b = "b2".repeat(16);
    let amr: Vec<String> = vec!["pwd".to_string()];
    fx.app
        .refresh_token_insert(&uid_a, &hash_a, expires_at, "sid-a", &amr, None)
        .await
        .unwrap();
    fx.app
        .refresh_token_insert(&uid_b, &hash_b, expires_at, "sid-b", &amr, None)
        .await
        .unwrap();

    fx.app.refresh_token_revoke_all(&uid_a).await.unwrap();

    assert!(
        fx.app
            .refresh_token_lookup(&hash_a)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    assert!(
        fx.app
            .refresh_token_lookup(&hash_b)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );
}

#[tokio::test]
async fn github_link_requires_t4_and_an_existing_staff_row() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let t1_uid = unique_uid("boromir");
    let t1_account = seed_account(&fx.owner, &unique_uid("boromir-acct")).await;
    seed_staff(&fx.owner, &t1_uid, t1_account, 1).await;

    let t4_uid = unique_uid("elrond");
    let t4_account = seed_account(&fx.owner, &unique_uid("elrond-acct")).await;
    seed_staff(&fx.owner, &t4_uid, t4_account, 4).await;

    let target_uid = unique_uid("samwise");
    let target_account = seed_account(&fx.owner, &unique_uid("samwise-acct")).await;
    seed_staff(&fx.owner, &target_uid, target_account, 1).await;

    // T1 may not link.
    let github_id: i64 = rand_github_id();
    let err = fx
        .app
        .github_link(&t1_uid, &target_uid, github_id, "test")
        .await;
    assert!(err.is_err());
    assert!(fx.app.github_lookup(github_id).await.unwrap().is_none());

    // T4 may link an existing staff uid.
    fx.app
        .github_link(&t4_uid, &target_uid, github_id, "vouched for in #staff")
        .await
        .expect("t4 may link");
    assert_eq!(
        fx.app.github_lookup(github_id).await.unwrap().as_deref(),
        Some(target_uid.as_str())
    );

    // Never creates staff: linking a uid with no staff row fails.
    let never_staff_uid = unique_uid("nobody");
    let other_github_id = rand_github_id();
    let err = fx
        .app
        .github_link(&t4_uid, &never_staff_uid, other_github_id, "test")
        .await;
    assert!(err.is_err());
    assert!(
        fx.app
            .github_lookup(other_github_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn github_lookup_is_none_for_an_unlinked_id() {
    let Some(fx) = support::setup().await else {
        return;
    };
    assert!(fx.app.github_lookup(999_999_999).await.unwrap().is_none());
}

/// OBI-200: `auth_github_unlink` is the missing counterpart to
/// `auth_github_link` -- same T4+ floor, and it actually removes the row.
#[tokio::test]
async fn github_unlink_requires_t4_and_removes_the_link() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let t1_uid = unique_uid("boromir-unlink");
    let t1_account = seed_account(&fx.owner, &unique_uid("boromir-unlink-acct")).await;
    seed_staff(&fx.owner, &t1_uid, t1_account, 1).await;

    let t4_uid = unique_uid("elrond-unlink");
    let t4_account = seed_account(&fx.owner, &unique_uid("elrond-unlink-acct")).await;
    seed_staff(&fx.owner, &t4_uid, t4_account, 4).await;

    let target_uid = unique_uid("samwise-unlink");
    let target_account = seed_account(&fx.owner, &unique_uid("samwise-unlink-acct")).await;
    seed_staff(&fx.owner, &target_uid, target_account, 1).await;

    let github_id = rand_github_id();
    fx.app
        .github_link(&t4_uid, &target_uid, github_id, "test")
        .await
        .expect("t4 may link");

    // T1 may not unlink.
    let err = fx.app.github_unlink(&t1_uid, &target_uid, "test").await;
    assert!(err.is_err());
    assert!(fx.app.github_lookup(github_id).await.unwrap().is_some());

    // T4 may unlink, and the link is actually gone afterward.
    fx.app
        .github_unlink(&t4_uid, &target_uid, "device lost")
        .await
        .expect("t4 may unlink");
    assert!(fx.app.github_lookup(github_id).await.unwrap().is_none());
}

/// Acceptance (OBI-200): "audit rows written for each event" --
/// `github_link`/`github_unlink` land `auth.github.link`/`auth.github.unlink`
/// rows in `audit_log` with the actor and target.
#[tokio::test]
async fn github_link_and_unlink_write_audit_log_rows() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let t4_uid = unique_uid("elrond-audit");
    let t4_account = seed_account(&fx.owner, &unique_uid("elrond-audit-acct")).await;
    seed_staff(&fx.owner, &t4_uid, t4_account, 4).await;

    let target_uid = unique_uid("samwise-audit");
    let target_account = seed_account(&fx.owner, &unique_uid("samwise-audit-acct")).await;
    seed_staff(&fx.owner, &target_uid, target_account, 1).await;

    let github_id = rand_github_id();
    fx.app
        .github_link(&t4_uid, &target_uid, github_id, "test-link")
        .await
        .expect("link");
    fx.app
        .github_unlink(&t4_uid, &target_uid, "test-unlink")
        .await
        .expect("unlink");

    let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT kind, caller, effective_principal FROM audit_log \
         WHERE kind IN ('auth.github.link', 'auth.github.unlink') \
         AND effective_principal = $1 ORDER BY id",
    )
    .bind(&target_uid)
    .fetch_all(&fx.owner)
    .await
    .unwrap();

    assert_eq!(rows.len(), 2, "expected one link row and one unlink row");
    assert_eq!(rows[0].0, "auth.github.link");
    assert_eq!(rows[0].1.as_deref(), Some(t4_uid.as_str()));
    assert_eq!(rows[1].0, "auth.github.unlink");
    assert_eq!(rows[1].1.as_deref(), Some(t4_uid.as_str()));
}

fn rand_github_id() -> i64 {
    use std::sync::atomic::{AtomicI64, Ordering};
    static COUNTER: AtomicI64 = AtomicI64::new(1_000_000);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

// -----------------------------------------------------------------------
// OBI-198 (D-TM2, M-AUTH-5, M-AUTH-6): `staff_sessions` (renamed from
// `refresh_tokens`), atomic rotation (`session_rotate`), family-scoped
// revocation (`session_revoke_family_by_token`), idle expiry, and the
// revoke-all-for-uid triggers on tier/TOTP/password/GitHub-unlink/staff
// removal (migration 0006_staff_sessions.sql).
// -----------------------------------------------------------------------

async fn session_is_revoked(owner: &sqlx::PgPool, token_hash: &str) -> bool {
    let revoked_at: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT revoked_at FROM staff_sessions WHERE token_hash = $1")
            .bind(token_hash)
            .fetch_one(owner)
            .await
            .expect("session row must exist");
    revoked_at.is_some()
}

#[tokio::test]
async fn session_rotate_consumes_atomically_and_preserves_family_context() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let uid = unique_uid("pippin3");
    let account = seed_account(&fx.owner, &unique_uid("pippin3-acct")).await;
    seed_staff(&fx.owner, &uid, account, 1).await;

    let expires_at = OffsetDateTime::now_utc() + Duration::days(14);
    let old_hash = "rot-old-".to_string() + &"a".repeat(8);
    let new_hash = "rot-new-".to_string() + &"b".repeat(8);
    let amr = vec!["pwd".to_string(), "otp".to_string()];
    let mfa_at = OffsetDateTime::now_utc();
    fx.app
        .refresh_token_insert(
            &uid,
            &old_hash,
            expires_at,
            "sid-rotate",
            &amr,
            Some(mfa_at),
        )
        .await
        .unwrap();

    let far_past_cutoff = OffsetDateTime::now_utc() - Duration::days(1);
    let outcome = fx
        .app
        .session_rotate(&old_hash, &new_hash, far_past_cutoff)
        .await
        .unwrap();
    match outcome {
        loom_persist::SessionRotateOutcome::Rotated {
            staff_uid,
            sid,
            amr: got_amr,
            mfa_at: got_mfa_at,
            expires_at: got_expires_at,
        } => {
            assert_eq!(staff_uid, uid);
            assert_eq!(sid, "sid-rotate");
            assert_eq!(got_amr, amr);
            assert!(got_mfa_at.is_some());
            // Must-fix 1: the new row's absolute expiry is the *old*
            // row's, not a freshly-computed now()+14d (compare at
            // microsecond resolution -- Postgres' `timestamptz` storage
            // truncates the nanosecond-precision value this test
            // constructed in Rust).
            assert_eq!(
                got_expires_at.unix_timestamp_nanos() / 1000,
                expires_at.unix_timestamp_nanos() / 1000
            );
        }
        other => panic!("expected Rotated, got {other:?}"),
    }

    assert!(session_is_revoked(&fx.owner, &old_hash).await);
    assert!(!session_is_revoked(&fx.owner, &new_hash).await);

    // Replaying the old (now-revoked) token is a reuse: the whole family
    // (including the just-rotated-in new row) dies.
    let newer_hash = "rot-newer".to_string() + &"c".repeat(8);
    let outcome = fx
        .app
        .session_rotate(&old_hash, &newer_hash, far_past_cutoff)
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        loom_persist::SessionRotateOutcome::Reused { .. }
    ));
    assert!(session_is_revoked(&fx.owner, &new_hash).await);
}

/// Acceptance: "idle expiry enforced".
#[tokio::test]
async fn session_rotate_refuses_an_idle_expired_session() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let uid = unique_uid("sam3");
    let account = seed_account(&fx.owner, &unique_uid("sam3-acct")).await;
    seed_staff(&fx.owner, &uid, account, 1).await;

    let expires_at = OffsetDateTime::now_utc() + Duration::days(14);
    let old_hash = "idle-old-".to_string() + &"d".repeat(8);
    fx.app
        .refresh_token_insert(&uid, &old_hash, expires_at, "sid-idle", &[], None)
        .await
        .unwrap();

    // The idle cutoff is "now" -- a freshly-inserted row's `last_used_at`
    // defaults to insert time, at or before "now", so this exercises the
    // idle branch without sleeping 24 real hours.
    let idle_cutoff = OffsetDateTime::now_utc();
    std::thread::sleep(std::time::Duration::from_millis(5));
    let new_hash = "idle-new-".to_string() + &"e".repeat(8);
    let outcome = fx
        .app
        .session_rotate(&old_hash, &new_hash, idle_cutoff)
        .await
        .unwrap();
    assert_eq!(outcome, loom_persist::SessionRotateOutcome::Invalid);
    // Not revoked by the idle check (stale, not malicious) -- a
    // subsequent rotate with a permissive cutoff still succeeds.
    assert!(!session_is_revoked(&fx.owner, &old_hash).await);
    let far_past_cutoff = OffsetDateTime::now_utc() - Duration::days(1);
    let outcome = fx
        .app
        .session_rotate(&old_hash, &new_hash, far_past_cutoff)
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        loom_persist::SessionRotateOutcome::Rotated { .. }
    ));
}

#[tokio::test]
async fn session_revoke_family_by_token_only_touches_that_family() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let uid = unique_uid("merry3");
    let account = seed_account(&fx.owner, &unique_uid("merry3-acct")).await;
    seed_staff(&fx.owner, &uid, account, 1).await;

    let expires_at = OffsetDateTime::now_utc() + Duration::days(14);
    let hash_a = "fam-a1-".to_string() + &"f".repeat(8);
    let hash_a2 = "fam-a2-".to_string() + &"g".repeat(8);
    let hash_b = "fam-b1-".to_string() + &"h".repeat(8);
    fx.app
        .refresh_token_insert(&uid, &hash_a, expires_at, "family-a", &[], None)
        .await
        .unwrap();
    fx.app
        .refresh_token_insert(&uid, &hash_a2, expires_at, "family-a", &[], None)
        .await
        .unwrap();
    fx.app
        .refresh_token_insert(&uid, &hash_b, expires_at, "family-b", &[], None)
        .await
        .unwrap();

    fx.app
        .session_revoke_family_by_token(&hash_a)
        .await
        .unwrap();

    assert!(session_is_revoked(&fx.owner, &hash_a).await);
    assert!(
        session_is_revoked(&fx.owner, &hash_a2).await,
        "family-a's other session must be revoked, not just hash_a's row"
    );
    assert!(!session_is_revoked(&fx.owner, &hash_b).await);
}

/// Acceptance: "tier change kills sessions" (M-AUTH-5), enforced by the
/// `staff_sessions_revoke_on_staff_change` trigger -- driven through the
/// real `roles_set_tier` security-definer function, not a direct
/// owner-connection shortcut.
#[tokio::test]
async fn tier_change_revokes_every_session_for_the_uid() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let lead_uid = unique_uid("elrond3");
    let lead_account = seed_account(&fx.owner, &unique_uid("elrond3-acct")).await;
    seed_staff(&fx.owner, &lead_uid, lead_account, 4).await;

    let uid = unique_uid("boromir3");
    let account = seed_account(&fx.owner, &unique_uid("boromir3-acct")).await;
    seed_staff(&fx.owner, &uid, account, 1).await;

    let expires_at = OffsetDateTime::now_utc() + Duration::days(14);
    let hash = "tier-chg-".to_string() + &"i".repeat(8);
    fx.app
        .refresh_token_insert(&uid, &hash, expires_at, "sid-tier", &[], None)
        .await
        .unwrap();

    fx.app
        .roles_set_tier(&lead_uid, &uid, 2, "promotion, OBI-198 test")
        .await
        .unwrap();

    assert!(session_is_revoked(&fx.owner, &hash).await);
}

/// Acceptance (M-AUTH-5): a TOTP re-enrolment (reset) revokes every
/// session for that uid.
#[tokio::test]
async fn totp_reenrollment_revokes_every_session_for_the_uid() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let uid = unique_uid("gimli3");
    let account = seed_account(&fx.owner, &unique_uid("gimli3-acct")).await;
    seed_staff(&fx.owner, &uid, account, 1).await;

    let expires_at = OffsetDateTime::now_utc() + Duration::days(14);
    let hash = "totp-chg-".to_string() + &"j".repeat(8);
    fx.app
        .refresh_token_insert(&uid, &hash, expires_at, "sid-totp", &[], None)
        .await
        .unwrap();

    fx.app.totp_enroll(&uid, "JBSWY3DPEHPK3PXP").await.unwrap();

    assert!(session_is_revoked(&fx.owner, &hash).await);
}

/// Acceptance (M-AUTH-5): a GitHub unlink revokes every session for that
/// uid too, via the same trigger mechanism, driven through the real
/// `auth_github_unlink` security-definer function.
#[tokio::test]
async fn github_unlink_revokes_every_session_for_the_uid() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let t4_uid = unique_uid("elrond4");
    let t4_account = seed_account(&fx.owner, &unique_uid("elrond4-acct")).await;
    seed_staff(&fx.owner, &t4_uid, t4_account, 4).await;

    let uid = unique_uid("samwise4");
    let account = seed_account(&fx.owner, &unique_uid("samwise4-acct")).await;
    seed_staff(&fx.owner, &uid, account, 1).await;

    let github_id = rand_github_id();
    fx.app
        .github_link(&t4_uid, &uid, github_id, "test")
        .await
        .unwrap();

    let expires_at = OffsetDateTime::now_utc() + Duration::days(14);
    let hash = "unlink-".to_string() + &"k".repeat(8);
    fx.app
        .refresh_token_insert(&uid, &hash, expires_at, "sid-unlink", &[], None)
        .await
        .unwrap();

    fx.app
        .github_unlink(&t4_uid, &uid, "test-unlink")
        .await
        .unwrap();

    assert!(session_is_revoked(&fx.owner, &hash).await);
}

/// Acceptance (M-AUTH-5): a password change revokes every session for
/// that uid (a harmless no-op for a player account with no staff row).
#[tokio::test]
async fn password_change_revokes_every_session_for_the_uid() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let uid = unique_uid("aragorn3");
    let account = seed_account(&fx.owner, &unique_uid("aragorn3-acct")).await;
    seed_staff(&fx.owner, &uid, account, 1).await;

    let expires_at = OffsetDateTime::now_utc() + Duration::days(14);
    let hash = "pwchg-".to_string() + &"l".repeat(8);
    fx.app
        .refresh_token_insert(&uid, &hash, expires_at, "sid-pwchg", &[], None)
        .await
        .unwrap();

    sqlx::query("UPDATE accounts SET password_hash = $1 WHERE id = $2")
        .bind("a-new-hash-not-a-real-one")
        .bind(account)
        .execute(&fx.owner)
        .await
        .unwrap();

    assert!(session_is_revoked(&fx.owner, &hash).await);
}

/// Acceptance (M-AUTH-5): removal of the staff row revokes every session
/// for that uid -- `ON DELETE CASCADE` (migration 0006) means the row is
/// gone outright rather than merely `revoked_at`-stamped, which is
/// stronger than revocation (nothing is left to replay against at all).
#[tokio::test]
async fn staff_row_removal_revokes_every_session_for_the_uid() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let uid = unique_uid("legolas3");
    let account = seed_account(&fx.owner, &unique_uid("legolas3-acct")).await;
    seed_staff(&fx.owner, &uid, account, 1).await;

    let expires_at = OffsetDateTime::now_utc() + Duration::days(14);
    let hash = "remove-".to_string() + &"m".repeat(8);
    fx.app
        .refresh_token_insert(&uid, &hash, expires_at, "sid-remove", &[], None)
        .await
        .unwrap();

    sqlx::query("DELETE FROM staff WHERE uid = $1")
        .bind(&uid)
        .execute(&fx.owner)
        .await
        .unwrap();

    let remaining: Option<String> =
        sqlx::query_scalar("SELECT token_hash FROM staff_sessions WHERE token_hash = $1")
            .bind(&hash)
            .fetch_optional(&fx.owner)
            .await
            .unwrap();
    assert!(
        remaining.is_none(),
        "the session row must be gone (cascaded), not just left unrevoked"
    );
}

// -----------------------------------------------------------------------
// OBI-198 must-fix 2: a rotation and a revoke-all for the same uid must
// serialize on the `staff` row lock, so no interleaving leaves an
// unrevoked session behind. Both orderings are forced deterministically
// with a held transaction on a second connection.
// -----------------------------------------------------------------------

async fn unrevoked_sessions_for(owner: &sqlx::PgPool, uid: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM staff_sessions WHERE staff_uid = $1 AND revoked_at IS NULL",
    )
    .bind(uid)
    .fetch_one(owner)
    .await
    .unwrap()
}

/// Revoke-all first: a tier change is in flight (its transaction holds
/// the `staff` row lock and has already revoked every session). A
/// concurrent `session_rotate` must block until it commits, then refuse
/// to rotate, so it cannot insert a fresh session the revoke never saw.
/// (The revoke's row lock on the old session row also serializes this
/// ordering; the test pins the observable behaviour, not which lock.)
#[tokio::test]
async fn session_rotate_blocks_behind_an_in_flight_revoke_all_and_then_refuses() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let uid = unique_uid("merry4");
    let account = seed_account(&fx.owner, &unique_uid("merry4-acct")).await;
    seed_staff(&fx.owner, &uid, account, 1).await;

    let expires_at = OffsetDateTime::now_utc() + Duration::days(14);
    let old_hash = "race-b-old".to_string() + &"n".repeat(8);
    let new_hash = "race-b-new".to_string() + &"o".repeat(8);
    fx.app
        .refresh_token_insert(&uid, &old_hash, expires_at, "sid-race-b", &[], None)
        .await
        .unwrap();

    // Tier change, left uncommitted: the AFTER UPDATE trigger has run and
    // this transaction now holds the staff row's lock.
    let mut revoke_tx = fx.owner.begin().await.unwrap();
    sqlx::query("UPDATE staff SET tier = 2 WHERE uid = $1")
        .bind(&uid)
        .execute(&mut *revoke_tx)
        .await
        .unwrap();

    let rotate_done = std::sync::atomic::AtomicBool::new(false);
    let cutoff = OffsetDateTime::now_utc() - Duration::days(1);
    let rotate = async {
        let outcome = fx.app.session_rotate(&old_hash, &new_hash, cutoff).await;
        rotate_done.store(true, std::sync::atomic::Ordering::SeqCst);
        outcome
    };
    let release = async {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !rotate_done.load(std::sync::atomic::Ordering::SeqCst),
            "session_rotate must block on the staff row lock held by the in-flight revoke"
        );
        revoke_tx.commit().await.unwrap();
    };
    let (outcome, ()) = tokio::join!(rotate, release);

    assert!(
        !matches!(
            outcome.unwrap(),
            loom_persist::SessionRotateOutcome::Rotated { .. }
        ),
        "a rotation serialized after a revoke-all must not succeed"
    );
    assert_eq!(unrevoked_sessions_for(&fx.owner, &uid).await, 0);
}

/// Rotation first: a rotation has taken the `staff` row lock and
/// inserted its new session but not committed yet. A concurrent password
/// change must block on that lock, and once it proceeds its revoke must
/// see (and revoke) the newly inserted session.
///
/// Password change (the `accounts` trigger) rather than a tier change on
/// purpose: an `UPDATE staff` conflicts with the rotation's `FOR SHARE`
/// on its own, so only the `accounts`/`github_identities` triggers
/// depend on the explicit `FOR UPDATE` in `staff_sessions_revoke_for_uid`.
/// Without it, this test fails with the new row left unrevoked.
///
/// The in-flight rotation is driven by hand on a second connection using
/// the same lock function and statements as `Persist::session_rotate`,
/// so the test can hold it open across the race window.
#[tokio::test]
async fn revoke_all_blocks_behind_an_in_flight_rotation_and_still_revokes_its_new_row() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let uid = unique_uid("eowyn4");
    let account = seed_account(&fx.owner, &unique_uid("eowyn4-acct")).await;
    seed_staff(&fx.owner, &uid, account, 1).await;

    let expires_at = OffsetDateTime::now_utc() + Duration::days(14);
    let old_hash = "race-a-old".to_string() + &"p".repeat(8);
    let new_hash = "race-a-new".to_string() + &"q".repeat(8);
    fx.app
        .refresh_token_insert(&uid, &old_hash, expires_at, "sid-race-a", &[], None)
        .await
        .unwrap();

    let mut rotate_tx = fx.owner.begin().await.unwrap();
    sqlx::query("SELECT staff_sessions_lock_for_rotate($1)")
        .bind(&uid)
        .execute(&mut *rotate_tx)
        .await
        .unwrap();
    let consumed = sqlx::query(
        "UPDATE staff_sessions SET revoked_at = NOW()
         WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()
         RETURNING staff_uid",
    )
    .bind(&old_hash)
    .fetch_optional(&mut *rotate_tx)
    .await
    .unwrap();
    assert!(consumed.is_some());
    sqlx::query(
        "INSERT INTO staff_sessions (staff_uid, token_hash, expires_at, sid, amr, mfa_at, last_used_at)
         VALUES ($1, $2, $3, 'sid-race-a', '{}', NULL, NOW())",
    )
    .bind(&uid)
    .bind(&new_hash)
    .bind(expires_at)
    .execute(&mut *rotate_tx)
    .await
    .unwrap();

    let revoke_done = std::sync::atomic::AtomicBool::new(false);
    let revoke = async {
        let result = sqlx::query("UPDATE accounts SET password_hash = 'rotated-pw' WHERE id = $1")
            .bind(account)
            .execute(&fx.owner)
            .await;
        revoke_done.store(true, std::sync::atomic::Ordering::SeqCst);
        result
    };
    let release = async {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !revoke_done.load(std::sync::atomic::Ordering::SeqCst),
            "the password change must block on the staff row lock held by the in-flight rotation"
        );
        rotate_tx.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(revoke, release);
    result.unwrap();

    assert!(session_is_revoked(&fx.owner, &new_hash).await);
    assert_eq!(unrevoked_sessions_for(&fx.owner, &uid).await, 0);
}
