// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only
//
// OBI-276 (CTO review of LoomMud/loom#102/OBI-237): a staff uid must never
// be a reserved driver principal (`root`, `mudlib`, anything with a `:`).
// Covers every path that creates/promotes a staff row (`roles_set_tier`,
// `roles_propose_tier`, `roles_approve_proposal`) and the login/token-issue
// defence in depth against a row that already carries a reserved uid.
//
// Deliberately one test function, not several: every case here exercises
// the literal uids `root`/`mudlib`/`domain:x` (the predicate is defined on
// exact/shape matches, so it can't use `unique_uid`-style randomised
// names), and `cargo test` runs every `#[tokio::test]` in this binary
// concurrently against the same database -- two tests both racing to
// create an account/staff row named `root` would be flaky for reasons
// that have nothing to do with the behaviour under test.

mod support;

use support::{seed_account, seed_staff, unique_uid};

/// Create (or reuse) an account for one of the literal reserved uids this
/// test exercises. `ON CONFLICT DO NOTHING` rather than a plain `INSERT`:
/// this test function itself reuses the same three names across several
/// sub-cases.
async fn seed_reserved_account(owner: &sqlx::PgPool, username: &str) {
    sqlx::query(
        "INSERT INTO accounts (username, password_hash) VALUES ($1, 'unused-in-tests') \
         ON CONFLICT (username) DO NOTHING",
    )
    .bind(username)
    .execute(owner)
    .await
    .expect("seed reserved-name account");
}

#[tokio::test]
async fn reserved_uids_refused_throughout_the_staff_lifecycle() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let reserved_names = ["root", "mudlib", "domain:x"];

    // --- roles_set_tier (the T1-3 promotion path, the common case) -----
    let actor_uid = unique_uid("lead");
    let actor_account = seed_account(&fx.owner, &actor_uid).await;
    seed_staff(&fx.owner, &actor_uid, actor_account, 4).await;

    for reserved in reserved_names {
        seed_reserved_account(&fx.owner, reserved).await;
        let result = fx
            .app
            .roles_set_tier(&actor_uid, reserved, 2, "attempt to staff a reserved uid")
            .await;
        assert!(result.is_err(), "roles_set_tier must refuse uid {reserved}");
        let tier = support::staff_tier(&fx.owner, reserved).await;
        assert_eq!(tier, None, "{reserved} must never get a staff row");
    }

    // --- roles_propose_tier (the two-root T4/T5 path's first half) -----
    let root_uid = unique_uid("root-proposer");
    let root_account = seed_account(&fx.owner, &root_uid).await;
    seed_staff(&fx.owner, &root_uid, root_account, 5).await;

    for reserved in reserved_names {
        let result = fx
            .app
            .roles_propose_tier(&root_uid, reserved, 4, "attempt to staff a reserved uid")
            .await;
        assert!(
            result.is_err(),
            "roles_propose_tier must refuse uid {reserved}"
        );
    }

    // --- roles_approve_proposal: belt-and-braces (migration 0006) ------
    // Even a proposal naming a reserved uid inserted directly (bypassing
    // the Rust-side `roles_propose_tier` guard entirely, as a pre-existing
    // row from before this fix might) is refused at approval time, so it
    // can never land in `staff`.
    let approver_uid = unique_uid("root-approver");
    let approver_account = seed_account(&fx.owner, &approver_uid).await;
    seed_staff(&fx.owner, &approver_uid, approver_account, 5).await;

    // Dynamic (unchecked) query, not the `query_scalar!` macro:
    // `role_proposals` deliberately has no GRANT to `loom_app` at all
    // (0002_roles_s2.sql), and the macro's compile-time `DESCRIBE` runs as
    // whatever role `DATABASE_URL` names in CI/this test run (`loom_app`).
    let proposal_id: i64 = sqlx::query_scalar(
        "INSERT INTO role_proposals (target_uid, new_tier, proposer, reason)
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind("mudlib")
    .bind(4i16)
    .bind(&root_uid)
    .bind("pre-existing proposal against a reserved uid")
    .fetch_one(&fx.owner)
    .await
    .expect("seed a pre-existing proposal");

    let result = fx
        .app
        .roles_approve_proposal(&approver_uid, proposal_id)
        .await;
    assert!(
        result.is_err(),
        "roles_approve_proposal must refuse a reserved target_uid"
    );
    let tier = support::staff_tier(&fx.owner, "mudlib").await;
    assert_eq!(tier, None, "mudlib must never get a staff row");

    // --- roles_bootstrap_root: owner-only root bootstrap (0001_init.sql) -
    // The only way to create a T4/T5 staff row in Phase 1. An operator
    // bootstrapping the first root is exactly the caller most likely to
    // pick the uid `root` -- this must be refused at the source, not
    // merely left to the login-time guards below (CTO review fix).
    for reserved in reserved_names {
        let account_id: uuid::Uuid =
            sqlx::query_scalar("SELECT id FROM accounts WHERE username = $1")
                .bind(reserved)
                .fetch_one(&fx.owner)
                .await
                .expect("reserved-name account already seeded above");
        // Dynamic (unchecked) query: `roles_bootstrap_root` has no GRANT
        // to `loom_app` at all (0001_init.sql), so the compile-time
        // `DESCRIBE` under `DATABASE_URL` (`loom_app` in CI) would fail
        // the same way the `role_proposals` insert above would.
        let result = sqlx::query("SELECT roles_bootstrap_root($1, $2)")
            .bind(reserved)
            .bind(account_id)
            .execute(&fx.owner)
            .await;
        assert!(
            result.is_err(),
            "roles_bootstrap_root must refuse uid {reserved}"
        );
        let tier = support::staff_tier(&fx.owner, reserved).await;
        assert_eq!(
            tier, None,
            "{reserved} must never get a staff row via roles_bootstrap_root"
        );
    }

    // --- a pre-existing reserved-uid staff row cannot authenticate -----
    // Simulates a row created before this fix shipped: seeded directly as
    // loom_owner, bypassing every guard above entirely.
    let username = unique_uid("attacker");
    let account = fx.app.create_account(&username, "hunter2").await.unwrap();
    sqlx::query("DELETE FROM staff WHERE uid = 'root'")
        .execute(&fx.owner)
        .await
        .expect("clear any stray root staff row from a prior run");
    seed_staff(&fx.owner, "root", account.id, 5).await;

    // `staff_login` (the password path): refused even with the right
    // password, exactly like a login against a nonexistent/non-staff
    // username.
    let login = fx
        .app
        .staff_login(&username, "hunter2")
        .await
        .expect("query should not error");
    assert!(
        login.is_none(),
        "login against a reserved-uid row must be refused"
    );

    // `staff_uid_for_username` (the rate-limiter key lookup): also `None`,
    // so the login path's rate limiting falls back to a username-only key
    // rather than ever handing a reserved uid back to the HTTP layer.
    let resolved = fx
        .app
        .staff_uid_for_username(&username)
        .await
        .expect("query should not error");
    assert_eq!(resolved, None);

    // `staff_auth_status` (used at every token issue/refresh): `None`,
    // same as a removed/nonexistent staff row.
    let status = fx
        .app
        .staff_auth_status("root")
        .await
        .expect("query should not error");
    assert_eq!(status, None);
}
