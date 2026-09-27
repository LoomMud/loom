// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use loom_persist::{DbEvent, DbRequest, GrantKind, ObjectState, spawn_db_worker};
use serde_json::json;
use std::time::Duration;
use support::{seed_account, seed_domain, seed_domain_member, seed_staff, staff_tier, unique_uid};
use time::OffsetDateTime;

#[tokio::test]
async fn account_create_and_login_round_trip() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let username = unique_uid("ranger");
    let account = fx
        .app
        .create_account(&username, "anduril")
        .await
        .expect("create account");

    let login = fx
        .app
        .verify_login(&username, "anduril")
        .await
        .expect("verify login")
        .expect("login should succeed");
    assert_eq!(login.id, account.id);

    let denied = fx
        .app
        .verify_login(&username, "wrong-password")
        .await
        .expect("wrong-password query");
    assert!(denied.is_none());
}

#[tokio::test]
async fn object_state_round_trip_with_key() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let object_path = format!("/players/legolas/{}", uuid::Uuid::new_v4());
    let state = ObjectState {
        object_path: object_path.clone(),
        key: "inventory".to_string(),
        program_path: "/obj/player".to_string(),
        program_version: 7,
        schema_hash: "abc123".to_string(),
        state: json!({"hp": 98, "title": "Greenleaf"}),
    };

    fx.app
        .save_object_state(&state)
        .await
        .expect("save object state");

    let loaded = fx
        .app
        .load_object_state(&object_path, "inventory")
        .await
        .expect("load object state")
        .expect("object exists");
    assert_eq!(loaded, state);

    // A different key under the same object_path is a distinct record
    // (design §8.1: PRIMARY KEY (object_path, key)).
    let other_key = fx
        .app
        .load_object_state(&object_path, "")
        .await
        .expect("load default-key object state");
    assert!(other_key.is_none());
}

#[tokio::test]
async fn async_worker_returns_event_while_world_ticks_continue() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let (request_tx, mut event_rx) = spawn_db_worker(fx.app.pool().clone(), 8);
    request_tx
        .send(DbRequest::Sleep {
            correlation_id: 42,
            duration_ms: 300,
        })
        .await
        .expect("enqueue sleep query");

    let mut ticks = 0_u32;
    let mut interval = tokio::time::interval(Duration::from_millis(25));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                ticks += 1;
            }
            maybe_event = event_rx.recv() => {
                match maybe_event.expect("worker should emit result") {
                    DbEvent::SleepDone { correlation_id } => {
                        assert_eq!(correlation_id, 42);
                        break;
                    }
                    DbEvent::QueryFailed { correlation_id, message } => {
                        panic!("sleep query failed for {correlation_id}: {message}");
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(2)) => {
                panic!("timed out waiting for db callback event");
            }
        }
    }

    assert!(
        ticks >= 5,
        "world loop should continue ticking during slow query"
    );
}

/// D-27.7: a direct write to `staff` must fail for `loom_app` -- an actual
/// attempted INSERT, not a `has_table_privilege` check.
#[tokio::test]
async fn direct_insert_into_staff_is_denied_for_loom_app() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let username = unique_uid("wannabe-admin");
    let account = fx
        .app
        .create_account(&username, "sneaky")
        .await
        .expect("create account");

    let result = sqlx::query("INSERT INTO staff (uid, account_id, tier) VALUES ($1, $2, 5)")
        .bind(&username)
        .bind(account.id)
        .execute(fx.app.pool())
        .await;

    let err = result.expect_err("direct INSERT INTO staff must fail for loom_app");
    let message = err.to_string().to_lowercase();
    assert!(
        message.contains("permission denied"),
        "expected a permission-denied error, got: {message}"
    );
}

/// D-27.7: a T3 domain lead promotes a T1 member of its own domain to T2;
/// the call succeeds and a `role_changes` row is written.
#[tokio::test]
async fn t3_lead_promotes_t1_to_t2_in_own_domain() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let domain = unique_uid("domain-start");
    seed_domain(&fx.owner, &domain, "wip").await;

    let lead_uid = unique_uid("lead");
    let lead_account = seed_account(&fx.owner, &lead_uid).await;
    seed_staff(&fx.owner, &lead_uid, lead_account, 3).await;
    seed_domain_member(&fx.owner, &domain, &lead_uid, "lead").await;

    let apprentice_uid = unique_uid("apprentice");
    let apprentice_account = seed_account(&fx.owner, &apprentice_uid).await;
    seed_staff(&fx.owner, &apprentice_uid, apprentice_account, 1).await;
    seed_domain_member(&fx.owner, &domain, &apprentice_uid, "member").await;

    fx.app
        .roles_set_tier(&lead_uid, &apprentice_uid, 2, "promoted for garden work")
        .await
        .expect("T3 lead promotes T1 to T2 within its own domain");

    let tier = staff_tier(&fx.owner, &apprentice_uid)
        .await
        .expect("apprentice should have a staff row");
    assert_eq!(tier, 2);

    let audit_row = sqlx::query!(
        "SELECT old_tier, new_tier, actor FROM role_changes
         WHERE uid = $1 ORDER BY at DESC LIMIT 1",
        apprentice_uid,
    )
    .fetch_one(&fx.owner)
    .await
    .expect("role_changes row should exist");
    assert_eq!(audit_row.old_tier, Some(1));
    assert_eq!(audit_row.new_tier, Some(2));
    assert_eq!(audit_row.actor, lead_uid);
}

/// D-27.7: a T3 lead cannot promote someone in a domain it does not lead.
#[tokio::test]
async fn t3_promotion_outside_domain_fails() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let led_domain = unique_uid("domain-led");
    let other_domain = unique_uid("domain-other");
    seed_domain(&fx.owner, &led_domain, "wip").await;
    seed_domain(&fx.owner, &other_domain, "wip").await;

    let lead_uid = unique_uid("lead");
    let lead_account = seed_account(&fx.owner, &lead_uid).await;
    seed_staff(&fx.owner, &lead_uid, lead_account, 3).await;
    seed_domain_member(&fx.owner, &led_domain, &lead_uid, "lead").await;

    let outsider_uid = unique_uid("outsider");
    let outsider_account = seed_account(&fx.owner, &outsider_uid).await;
    seed_staff(&fx.owner, &outsider_uid, outsider_account, 1).await;
    seed_domain_member(&fx.owner, &other_domain, &outsider_uid, "member").await;

    let result = fx
        .app
        .roles_set_tier(&lead_uid, &outsider_uid, 2, "should be rejected")
        .await;
    assert!(
        result.is_err(),
        "T3 lead must not promote members of a domain it does not lead"
    );

    let tier = staff_tier(&fx.owner, &outsider_uid).await;
    assert_eq!(
        tier,
        Some(1),
        "tier must be unchanged after the denied call"
    );
}

/// D-27.7: a T2 builder cannot promote itself.
#[tokio::test]
async fn t2_self_promotion_fails() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let builder_uid = unique_uid("builder");
    let builder_account = seed_account(&fx.owner, &builder_uid).await;
    seed_staff(&fx.owner, &builder_uid, builder_account, 2).await;

    let result = fx
        .app
        .roles_set_tier(&builder_uid, &builder_uid, 3, "self-promotion attempt")
        .await;
    assert!(result.is_err(), "self-promotion must be rejected");

    let tier = staff_tier(&fx.owner, &builder_uid).await;
    assert_eq!(
        tier,
        Some(2),
        "tier must be unchanged after the denied call"
    );
}

/// D-27.7: `roles_set_tier` never grants T4 (or T5); Phase 1 has no
/// driver-reachable path to arch/root.
#[tokio::test]
async fn t4_granting_t4_fails() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let arch_uid = unique_uid("arch");
    let arch_account = seed_account(&fx.owner, &arch_uid).await;
    seed_staff(&fx.owner, &arch_uid, arch_account, 4).await;

    let target_uid = unique_uid("target");
    seed_account(&fx.owner, &target_uid).await;

    let result = fx
        .app
        .roles_set_tier(&arch_uid, &target_uid, 4, "attempted T4 grant")
        .await;
    assert!(
        result.is_err(),
        "roles_set_tier must reject T4 grants in Phase 1"
    );

    let tier = staff_tier(&fx.owner, &target_uid).await;
    assert_eq!(tier, None, "target must remain a player (no staff row)");
}

/// D-27.7: an expired grant is ignored by the read helper (`active_grants`).
#[tokio::test]
async fn expired_grant_is_ignored_by_active_grants_view() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let granter_uid = unique_uid("granter");
    let granter_account = seed_account(&fx.owner, &granter_uid).await;
    seed_staff(&fx.owner, &granter_uid, granter_account, 4).await;

    let target_uid = unique_uid("apprentice-grant");
    let target_account = seed_account(&fx.owner, &target_uid).await;
    seed_staff(&fx.owner, &target_uid, target_account, 1).await;

    // A still-valid grant, made through the security definer function.
    let future = OffsetDateTime::now_utc() + Duration::from_secs(3600);
    fx.app
        .roles_grant(
            &granter_uid,
            &target_uid,
            GrantKind::Path,
            "/domains/start/wip",
            future,
            "temporary path exception",
        )
        .await
        .expect("valid future-expiry grant should succeed");

    // An already-expired grant, seeded directly (the function itself
    // refuses a past expiry, so this simulates one that lapsed).
    sqlx::query!(
        "INSERT INTO grants (uid, kind, target, granted_by, expires_at)
         VALUES ($1, 'efun', 'snoop', $2, NOW() - INTERVAL '1 hour')",
        target_uid,
        granter_uid,
    )
    .execute(&fx.owner)
    .await
    .expect("seed expired grant");

    let active = fx
        .app
        .active_grants(&target_uid)
        .await
        .expect("read active grants");

    assert!(
        active
            .iter()
            .any(|(kind, target)| kind == "path" && target == "/domains/start/wip"),
        "the unexpired grant should be visible: {active:?}"
    );
    assert!(
        !active.iter().any(|(kind, _)| kind == "efun"),
        "the expired grant must not appear in active_grants: {active:?}"
    );
}
