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

fn rand_github_id() -> i64 {
    use std::sync::atomic::{AtomicI64, Ordering};
    static COUNTER: AtomicI64 = AtomicI64::new(1_000_000);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
