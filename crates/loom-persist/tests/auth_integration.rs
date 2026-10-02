// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only
//
// OBI-174/OBI-199/OBI-200: integration tests for migrations 0003-0005
// (TOTP ciphertext storage, recovery codes, `mfa_at` step-up, refresh
// tokens, GitHub identity link/unlink, and audit_log wiring) against a
// real Postgres, exercising the exact `loom_app` login the HTTP layer
// uses.

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
    assert_eq!(record.totp_secret_enc, None);
    assert!(!record.totp_confirmed);
    assert_eq!(record.mfa_at, None);

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

    // 0005: only the ciphertext blob is ever stored -- this is a
    // deliberately *not* base32-shaped blob to make clear loom-persist
    // never interprets it, it just stores whatever loom-http hands it.
    let ciphertext = b"\x00not-a-real-ciphertext-blob\xff";
    fx.app
        .totp_enroll(&uid, ciphertext)
        .await
        .expect("self-service enroll succeeds");

    let stored = fx.app.totp_secret_for(&uid).await.unwrap();
    assert_eq!(stored.as_deref(), Some(ciphertext.as_slice()));
    assert!(!fx.app.totp_confirmed_for(&uid).await.unwrap());

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

    fx.app.totp_enroll(&uid, b"secret-one").await.unwrap();
    fx.app.totp_confirm(&uid).await.unwrap();
    assert!(fx.app.totp_confirmed_for(&uid).await.unwrap());

    let username = unique_uid("aragorn-login");
    let account2 = fx.app.create_account(&username, "strider").await.unwrap();
    seed_staff(&fx.owner, &unique_uid("aragorn2"), account2.id, 4).await;
    // (separate uid just to prove totp_confirmed reads back true for the
    // uid we actually confirmed, not some other row)
    let record = fx.app.staff_login(&username, "strider").await.unwrap();
    assert!(record.is_some());
    assert!(!record.unwrap().totp_confirmed); // this is aragorn2, unrelated

    // Re-enrolling clears the confirmation.
    fx.app.totp_enroll(&uid, b"secret-two").await.unwrap();
    let stored = fx.app.totp_secret_for(&uid).await.unwrap();
    assert_eq!(stored.as_deref(), Some(b"secret-two".as_slice()));
    assert!(!fx.app.totp_confirmed_for(&uid).await.unwrap());
}

#[tokio::test]
async fn mfa_touch_updates_mfa_at() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let uid = unique_uid("frodo");
    let account = seed_account(&fx.owner, &unique_uid("frodo-acct")).await;
    seed_staff(&fx.owner, &uid, account, 1).await;

    assert!(fx.app.mfa_at_of(&uid).await.unwrap().is_none());
    fx.app.mfa_touch(&uid).await.unwrap();
    assert!(fx.app.mfa_at_of(&uid).await.unwrap().is_some());
}

#[tokio::test]
async fn recovery_codes_round_trip_and_are_single_use() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let uid = unique_uid("sam-recovery");
    let account = seed_account(&fx.owner, &unique_uid("sam-recovery-acct")).await;
    seed_staff(&fx.owner, &uid, account, 1).await;

    let hashes: Vec<String> = (0..10).map(|i| format!("hash-{i}-{uid}")).collect();
    fx.app.recovery_codes_store(&uid, &hashes).await.unwrap();

    // First use of a code succeeds exactly once.
    assert!(
        fx.app
            .recovery_code_consume(&uid, &hashes[0])
            .await
            .unwrap()
    );
    assert!(
        !fx.app
            .recovery_code_consume(&uid, &hashes[0])
            .await
            .unwrap()
    );

    // A different, still-unused code works.
    assert!(
        fx.app
            .recovery_code_consume(&uid, &hashes[1])
            .await
            .unwrap()
    );

    // Re-storing (re-enrolment) replaces the whole set -- an old code is
    // no longer valid even if it was never used.
    let new_hashes: Vec<String> = (0..10).map(|i| format!("newhash-{i}-{uid}")).collect();
    fx.app
        .recovery_codes_store(&uid, &new_hashes)
        .await
        .unwrap();
    assert!(
        !fx.app
            .recovery_code_consume(&uid, &hashes[2])
            .await
            .unwrap()
    );
    assert!(
        fx.app
            .recovery_code_consume(&uid, &new_hashes[2])
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn totp_admin_reset_requires_t4_and_fresh_step_up() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let admin_uid = unique_uid("elrond-admin");
    let admin_account = seed_account(&fx.owner, &unique_uid("elrond-admin-acct")).await;
    seed_staff(&fx.owner, &admin_uid, admin_account, 4).await;

    let target_uid = unique_uid("gimli-target");
    let target_account = seed_account(&fx.owner, &unique_uid("gimli-target-acct")).await;
    seed_staff(&fx.owner, &target_uid, target_account, 3).await;
    fx.app.totp_enroll(&target_uid, b"secret").await.unwrap();
    fx.app.totp_confirm(&target_uid).await.unwrap();

    // No step-up yet: refused.
    assert!(
        fx.app
            .totp_admin_reset(&admin_uid, &target_uid, "lost device")
            .await
            .is_err()
    );

    // Step up, then it succeeds and clears the target's enrolment.
    fx.app.mfa_touch(&admin_uid).await.unwrap();
    fx.app
        .totp_admin_reset(&admin_uid, &target_uid, "lost device")
        .await
        .expect("t4 with fresh mfa_at may reset");
    assert_eq!(fx.app.totp_secret_for(&target_uid).await.unwrap(), None);
    assert!(!fx.app.totp_confirmed_for(&target_uid).await.unwrap());
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
    fx.app
        .refresh_token_insert(&uid, &hash, expires_at)
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
    fx.app
        .refresh_token_insert(&uid_a, &hash_a, expires_at)
        .await
        .unwrap();
    fx.app
        .refresh_token_insert(&uid_b, &hash_b, expires_at)
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
async fn github_link_requires_t4_an_existing_staff_row_and_fresh_step_up() {
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

    // T1 may not link, even with a fresh step-up.
    fx.app.mfa_touch(&t1_uid).await.unwrap();
    let github_id: i64 = rand_github_id();
    let err = fx
        .app
        .github_link(&t1_uid, &target_uid, github_id, "test")
        .await;
    assert!(err.is_err());
    assert!(fx.app.github_lookup(github_id).await.unwrap().is_none());

    // T4 without a fresh step-up may not link either (OBI-199).
    let err = fx
        .app
        .github_link(&t4_uid, &target_uid, github_id, "vouched for in #staff")
        .await;
    assert!(err.is_err(), "T4 without a fresh mfa_at must be refused");
    assert!(fx.app.github_lookup(github_id).await.unwrap().is_none());

    // T4 with a fresh step-up may link an existing staff uid.
    fx.app.mfa_touch(&t4_uid).await.unwrap();
    fx.app
        .github_link(&t4_uid, &target_uid, github_id, "vouched for in #staff")
        .await
        .expect("t4 with fresh step-up may link");
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

/// OBI-199/OBI-200: `auth_github_unlink` is the counterpart to
/// `auth_github_link` -- same T4+ floor plus fresh step-up, and it
/// actually removes the row.
#[tokio::test]
async fn github_unlink_requires_t4_and_fresh_step_up_then_removes_the_link() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let t1_uid = unique_uid("boromir-unlink");
    let t1_account = seed_account(&fx.owner, &unique_uid("boromir-unlink-acct")).await;
    seed_staff(&fx.owner, &t1_uid, t1_account, 1).await;

    let t4_uid = unique_uid("elrond-unlink");
    let t4_account = seed_account(&fx.owner, &unique_uid("elrond-unlink-acct")).await;
    seed_staff(&fx.owner, &t4_uid, t4_account, 4).await;

    let t4_uid_no_stepup = unique_uid("gandalf-unlink");
    let t4_account_no_stepup = seed_account(&fx.owner, &unique_uid("gandalf-unlink-acct")).await;
    seed_staff(&fx.owner, &t4_uid_no_stepup, t4_account_no_stepup, 4).await;

    let target_uid = unique_uid("samwise-unlink");
    let target_account = seed_account(&fx.owner, &unique_uid("samwise-unlink-acct")).await;
    seed_staff(&fx.owner, &target_uid, target_account, 1).await;

    fx.app.mfa_touch(&t4_uid).await.unwrap();
    let github_id = rand_github_id();
    fx.app
        .github_link(&t4_uid, &target_uid, github_id, "test")
        .await
        .expect("t4 with fresh step-up may link");

    // T1 may not unlink, even with a fresh step-up.
    fx.app.mfa_touch(&t1_uid).await.unwrap();
    let err = fx.app.github_unlink(&t1_uid, &target_uid, "test").await;
    assert!(err.is_err());
    assert!(fx.app.github_lookup(github_id).await.unwrap().is_some());

    // T4 without a fresh step-up may not unlink either.
    let err = fx
        .app
        .github_unlink(&t4_uid_no_stepup, &target_uid, "test")
        .await;
    assert!(err.is_err());
    assert!(fx.app.github_lookup(github_id).await.unwrap().is_some());

    // T4 with a fresh step-up may unlink, and the link is actually gone
    // afterward.
    fx.app
        .github_unlink(&t4_uid, &target_uid, "device lost")
        .await
        .expect("t4 with fresh step-up may unlink");
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

    fx.app.mfa_touch(&t4_uid).await.unwrap();
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
