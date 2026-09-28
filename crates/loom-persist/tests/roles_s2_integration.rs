// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-119 (S2a, design note OBI-36 §1, §5, §6): migration 0002 coverage --
//! the two-root proposal flow, the `loom_app` DML fence on the new tables,
//! `roles_changed` NOTIFY delivery, and `load_roles_snapshot`.

mod support;

use loom_persist::{AuditRow, GrantKind};
use std::time::Duration;
use support::{seed_account, seed_domain, seed_domain_member, seed_staff, staff_tier, unique_uid};
use time::OffsetDateTime;
use tokio::time::timeout;

/// A single root cannot grant itself T4/T5: it can propose, but approving
/// its own proposal is refused, so no tier change ever lands.
#[tokio::test]
async fn single_root_cannot_apply_its_own_proposal() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let root_uid = unique_uid("root-solo");
    let root_account = seed_account(&fx.owner, &root_uid).await;
    seed_staff(&fx.owner, &root_uid, root_account, 5).await;

    let target_uid = unique_uid("arch-candidate");
    seed_account(&fx.owner, &target_uid).await;

    let proposal_id = fx
        .app
        .roles_propose_tier(&root_uid, &target_uid, 4, "promote to arch")
        .await
        .expect("a T5 root may propose a T4 grant");

    let approve = fx.app.roles_approve_proposal(&root_uid, proposal_id).await;
    assert!(
        approve.is_err(),
        "the proposer must not be able to approve its own proposal"
    );

    let tier = staff_tier(&fx.owner, &target_uid).await;
    assert_eq!(
        tier, None,
        "target must remain a player: a single root cannot grant T4/T5"
    );
}

/// The target of a proposal may not approve it, even if it is itself a T5
/// root (e.g. a demotion proposal against a root who is still T5 at call
/// time).
#[tokio::test]
async fn proposal_target_cannot_approve() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let proposer_uid = unique_uid("root-proposer");
    let proposer_account = seed_account(&fx.owner, &proposer_uid).await;
    seed_staff(&fx.owner, &proposer_uid, proposer_account, 5).await;

    let target_uid = unique_uid("root-target");
    let target_account = seed_account(&fx.owner, &target_uid).await;
    seed_staff(&fx.owner, &target_uid, target_account, 5).await;

    let proposal_id = fx
        .app
        .roles_propose_tier(&proposer_uid, &target_uid, 3, "demote out of root")
        .await
        .expect("a T5 root may propose demoting another T5 root");

    let approve = fx
        .app
        .roles_approve_proposal(&target_uid, proposal_id)
        .await;
    assert!(
        approve.is_err(),
        "the target of a proposal must not be able to approve it"
    );

    let tier = staff_tier(&fx.owner, &target_uid).await;
    assert_eq!(tier, Some(5), "target's tier must be unchanged");
}

/// An expired proposal is rejected even by a valid second root.
#[tokio::test]
async fn expired_proposal_is_rejected() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let proposer_uid = unique_uid("root-proposer-exp");
    let proposer_account = seed_account(&fx.owner, &proposer_uid).await;
    seed_staff(&fx.owner, &proposer_uid, proposer_account, 5).await;

    let approver_uid = unique_uid("root-approver-exp");
    let approver_account = seed_account(&fx.owner, &approver_uid).await;
    seed_staff(&fx.owner, &approver_uid, approver_account, 5).await;

    let target_uid = unique_uid("arch-candidate-exp");
    seed_account(&fx.owner, &target_uid).await;

    // Seed an already-expired proposal directly (the function itself
    // always sets a future expiry, so this simulates one that lapsed).
    let proposal_id: i64 = sqlx::query_scalar(
        "INSERT INTO role_proposals (target_uid, new_tier, proposer, reason, expires_at)
         VALUES ($1, 4, $2, 'promote to arch', NOW() - INTERVAL '1 hour')
         RETURNING id",
    )
    .bind(&target_uid)
    .bind(&proposer_uid)
    .fetch_one(&fx.owner)
    .await
    .expect("seed expired proposal");

    let approve = fx
        .app
        .roles_approve_proposal(&approver_uid, proposal_id)
        .await;
    assert!(approve.is_err(), "an expired proposal must be rejected");

    let tier = staff_tier(&fx.owner, &target_uid).await;
    assert_eq!(tier, None, "target must remain a player");
}

/// A second, distinct root applies the proposal; `role_changes` names both
/// roots and the proposal id.
#[tokio::test]
async fn second_root_applies_proposal_and_role_changes_names_both_roots() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let proposer_uid = unique_uid("root-a");
    let proposer_account = seed_account(&fx.owner, &proposer_uid).await;
    seed_staff(&fx.owner, &proposer_uid, proposer_account, 5).await;

    let approver_uid = unique_uid("root-b");
    let approver_account = seed_account(&fx.owner, &approver_uid).await;
    seed_staff(&fx.owner, &approver_uid, approver_account, 5).await;

    let target_uid = unique_uid("arch-candidate-ok");
    seed_account(&fx.owner, &target_uid).await;

    let proposal_id = fx
        .app
        .roles_propose_tier(&proposer_uid, &target_uid, 4, "promote to arch")
        .await
        .expect("propose T4 grant");

    fx.app
        .roles_approve_proposal(&approver_uid, proposal_id)
        .await
        .expect("a second, distinct root approves the proposal");

    let tier = staff_tier(&fx.owner, &target_uid)
        .await
        .expect("target should now have a staff row");
    assert_eq!(tier, 4);

    let reason: String = sqlx::query_scalar(
        "SELECT reason FROM role_changes WHERE uid = $1 ORDER BY at DESC LIMIT 1",
    )
    .bind(&target_uid)
    .fetch_one(&fx.owner)
    .await
    .expect("role_changes row should exist");
    assert!(
        reason.contains(&proposer_uid) && reason.contains(&approver_uid),
        "role_changes reason must name both roots: {reason}"
    );

    // A second approval attempt on the same (now-applied) proposal fails.
    let reapply = fx
        .app
        .roles_approve_proposal(&approver_uid, proposal_id)
        .await;
    assert!(
        reapply.is_err(),
        "an already-applied proposal must not re-apply"
    );
}

/// E1.3 (OBI-37), two-root rule: a single root cannot bypass the proposal
/// flow through `roles_set_tier` -- not to grant T4 or T5, and not to
/// demote an existing arch. Positive control: the same root sets a player
/// to T3 directly.
#[tokio::test]
async fn a_single_root_cannot_move_anyone_into_or_out_of_t4_t5_directly() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let root_uid = unique_uid("root-direct");
    let root_account = seed_account(&fx.owner, &root_uid).await;
    seed_staff(&fx.owner, &root_uid, root_account, 5).await;

    let player_uid = unique_uid("player-direct");
    seed_account(&fx.owner, &player_uid).await;

    let arch_uid = unique_uid("arch-direct");
    let arch_account = seed_account(&fx.owner, &arch_uid).await;
    seed_staff(&fx.owner, &arch_uid, arch_account, 4).await;

    for tier in [4, 5] {
        let r = fx
            .app
            .roles_set_tier(&root_uid, &player_uid, tier, "direct grant")
            .await;
        assert!(
            r.is_err(),
            "roles_set_tier must refuse a direct T{tier} grant"
        );
    }
    assert_eq!(staff_tier(&fx.owner, &player_uid).await, None);

    let r = fx
        .app
        .roles_set_tier(&root_uid, &arch_uid, 3, "direct demotion")
        .await;
    assert!(r.is_err(), "roles_set_tier must refuse demoting an arch");
    assert_eq!(staff_tier(&fx.owner, &arch_uid).await, Some(4));

    fx.app
        .roles_set_tier(&root_uid, &player_uid, 3, "direct T3 grant")
        .await
        .expect("a root may set T1-T3 directly");
    assert_eq!(staff_tier(&fx.owner, &player_uid).await, Some(3));
}

/// E1.3 (OBI-37), two-root rule: an arch (T4) can neither propose nor
/// approve a T4/T5 change. Positive control: a root's proposal, approved
/// by a second root, applies.
#[tokio::test]
async fn only_roots_may_propose_or_approve_a_two_root_change() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let arch_uid = unique_uid("arch-proposer");
    let arch_account = seed_account(&fx.owner, &arch_uid).await;
    seed_staff(&fx.owner, &arch_uid, arch_account, 4).await;

    let root_a = unique_uid("root-a2");
    let root_a_account = seed_account(&fx.owner, &root_a).await;
    seed_staff(&fx.owner, &root_a, root_a_account, 5).await;

    let root_b = unique_uid("root-b2");
    let root_b_account = seed_account(&fx.owner, &root_b).await;
    seed_staff(&fx.owner, &root_b, root_b_account, 5).await;

    let target_uid = unique_uid("arch-candidate-2");
    seed_account(&fx.owner, &target_uid).await;

    let r = fx
        .app
        .roles_propose_tier(&arch_uid, &target_uid, 4, "arch proposes")
        .await;
    assert!(r.is_err(), "an arch must not be able to propose");

    let proposal_id = fx
        .app
        .roles_propose_tier(&root_a, &target_uid, 4, "promote to arch")
        .await
        .expect("a root may propose");

    let r = fx.app.roles_approve_proposal(&arch_uid, proposal_id).await;
    assert!(r.is_err(), "an arch must not be able to approve");
    assert_eq!(staff_tier(&fx.owner, &target_uid).await, None);

    fx.app
        .roles_approve_proposal(&root_b, proposal_id)
        .await
        .expect("a second, distinct root approves");
    assert_eq!(staff_tier(&fx.owner, &target_uid).await, Some(4));
}

/// `loom_app` cannot write the new tables directly -- only through the
/// `roles_*` security-definer functions -- except `INSERT` on `audit_log`.
#[tokio::test]
async fn loom_app_cannot_dml_new_tables_except_insert_audit_log() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let target_uid = unique_uid("direct-proposal-target");
    seed_account(&fx.owner, &target_uid).await;

    let denied = |result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>, what: &str| {
        let err = result.expect_err(&format!("{what} must be denied for loom_app"));
        let message = err.to_string().to_lowercase();
        assert!(
            message.contains("permission denied"),
            "expected permission-denied for {what}, got: {message}"
        );
    };

    denied(
        sqlx::query(
            "INSERT INTO role_proposals (target_uid, new_tier, proposer, reason)
             VALUES ($1, 4, 'someone', 'direct insert')",
        )
        .bind(&target_uid)
        .execute(fx.app.pool())
        .await,
        "direct INSERT into role_proposals",
    );

    denied(
        sqlx::query("SELECT * FROM audit_log")
            .execute(fx.app.pool())
            .await,
        "direct SELECT on audit_log",
    );

    // The one exception: INSERT on audit_log succeeds.
    sqlx::query("INSERT INTO audit_log (kind, verdict) VALUES ('quota_breach', 'deny')")
        .execute(fx.app.pool())
        .await
        .expect("loom_app may INSERT into audit_log");

    denied(
        sqlx::query("UPDATE audit_log SET verdict = 'allow'")
            .execute(fx.app.pool())
            .await,
        "direct UPDATE on audit_log",
    );

    denied(
        sqlx::query("DELETE FROM audit_log")
            .execute(fx.app.pool())
            .await,
        "direct DELETE on audit_log",
    );
}

/// A write through any `roles_*` function produces a `roles_changed`
/// notification that `listen_roles_changed` receives.
#[tokio::test]
async fn roles_changed_notification_is_delivered_on_a_roles_write() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let mut rx = fx
        .app
        .listen_roles_changed()
        .await
        .expect("listen on roles_changed");

    // Give the listener a moment to finish LISTEN before we write.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let lead_uid = unique_uid("notify-lead");
    let lead_account = seed_account(&fx.owner, &lead_uid).await;
    seed_staff(&fx.owner, &lead_uid, lead_account, 4).await;

    let target_uid = unique_uid("notify-target");
    let target_account = seed_account(&fx.owner, &target_uid).await;
    seed_staff(&fx.owner, &target_uid, target_account, 1).await;

    fx.app
        .roles_set_tier(&lead_uid, &target_uid, 2, "trigger a notify")
        .await
        .expect("roles_set_tier should succeed");

    // Other tests run concurrently against the same database and may also
    // be writing roles tables, so drain notifications until we see the one
    // this write should have produced (`staff`), rather than assuming ours
    // is the very next payload.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            remaining > Duration::ZERO,
            "timed out waiting for a 'staff' roles_changed notification"
        );
        let payload = timeout(remaining, rx.recv())
            .await
            .expect("should receive a roles_changed notification before the timeout")
            .expect("channel should still be open");
        if payload == "staff" {
            break;
        }
    }
}

/// `load_roles_snapshot` round-trips seeded rows and excludes expired
/// grants.
#[tokio::test]
async fn load_roles_snapshot_round_trips_and_excludes_expired_grants() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let domain = unique_uid("domain-snapshot");
    seed_domain(&fx.owner, &domain, "wip").await;

    let arch_uid = unique_uid("arch-snapshot");
    let arch_account = seed_account(&fx.owner, &arch_uid).await;
    seed_staff(&fx.owner, &arch_uid, arch_account, 4).await;
    seed_domain_member(&fx.owner, &domain, &arch_uid, "lead").await;

    let builder_uid = unique_uid("builder-snapshot");
    let builder_account = seed_account(&fx.owner, &builder_uid).await;
    seed_staff(&fx.owner, &builder_uid, builder_account, 1).await;

    let future = OffsetDateTime::now_utc() + Duration::from_secs(3600);
    fx.app
        .roles_grant(
            &arch_uid,
            &builder_uid,
            GrantKind::Path,
            "/domains/start/wip",
            future,
            "snapshot fixture: active grant",
        )
        .await
        .expect("seed an active grant");

    // An already-expired grant, seeded directly.
    sqlx::query!(
        "INSERT INTO grants (uid, kind, target, granted_by, expires_at)
         VALUES ($1, 'efun', 'snoop', $2, NOW() - INTERVAL '1 hour')",
        builder_uid,
        arch_uid,
    )
    .execute(&fx.owner)
    .await
    .expect("seed an expired grant");

    let snapshot = fx
        .app
        .load_roles_snapshot()
        .await
        .expect("load the roles snapshot");

    assert!(
        snapshot
            .staff
            .iter()
            .any(|s| s.uid == arch_uid && s.tier == 4),
        "arch should be present in the snapshot's staff rows"
    );
    assert!(
        snapshot
            .staff
            .iter()
            .any(|s| s.uid == builder_uid && s.tier == 1),
        "builder should be present in the snapshot's staff rows"
    );
    assert!(
        snapshot
            .domains
            .iter()
            .any(|d| d.name == domain && d.state == "wip"),
        "seeded domain should be present"
    );
    assert!(
        snapshot
            .domain_members
            .iter()
            .any(|m| m.domain == domain && m.uid == arch_uid && m.role == "lead"),
        "seeded domain membership should be present"
    );
    assert!(
        !snapshot.tier_policy.is_empty(),
        "tier_policy is seeded by 0001_init.sql and must round-trip"
    );

    let grants_for_builder: Vec<_> = snapshot
        .active_grants
        .iter()
        .filter(|g| g.uid == builder_uid)
        .collect();
    assert!(
        grants_for_builder
            .iter()
            .any(|g| g.kind == "path" && g.target == "/domains/start/wip"),
        "the unexpired grant should be present: {grants_for_builder:?}"
    );
    assert!(
        !grants_for_builder.iter().any(|g| g.kind == "efun"),
        "the expired grant must be excluded: {grants_for_builder:?}"
    );

    // Other tests run concurrently against the same database and may hold
    // their own active grants, so we can't assert this is *the* earliest
    // grant overall -- only that the snapshot's reported minimum is
    // internally consistent and no later than our own grant's expiry.
    let expected_min = snapshot.active_grants.iter().map(|g| g.expires_at).min();
    assert_eq!(
        snapshot.earliest_grant_expiry, expected_min,
        "earliest_grant_expiry must be the minimum expires_at across active_grants"
    );
    assert!(
        snapshot.earliest_grant_expiry.is_some_and(|e| e <= future),
        "earliest_grant_expiry must be no later than our own active grant's expiry"
    );
}

/// `insert_audit_batch` writes every row in one round trip.
#[tokio::test]
async fn insert_audit_batch_writes_all_rows() {
    let Some(fx) = support::setup().await else {
        return;
    };

    let marker = unique_uid("audit-batch");
    let rows = vec![
        AuditRow {
            at: OffsetDateTime::now_utc(),
            kind: "efun_call".to_string(),
            caller: Some(format!("/obj/{marker}-a")),
            effective_principal: Some("builder-1".to_string()),
            apply: Some("valid_efun".to_string()),
            class: Some(2),
            argument: Some("shutdown".to_string()),
            guard_set: vec!["builder-1".to_string(), "mudlib".to_string()],
            verdict: "deny".to_string(),
            detail: Some(format!("{marker} row 1")),
        },
        AuditRow {
            at: OffsetDateTime::now_utc(),
            kind: "compile".to_string(),
            caller: None,
            effective_principal: Some("root".to_string()),
            apply: None,
            class: None,
            argument: Some("/domains/start/room.wf".to_string()),
            guard_set: vec![],
            verdict: "allow".to_string(),
            detail: Some(format!("{marker} row 2")),
        },
    ];

    fx.app
        .insert_audit_batch(&rows)
        .await
        .expect("insert_audit_batch should succeed");

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE detail LIKE $1")
        .bind(format!("{marker}%"))
        .fetch_one(&fx.owner)
        .await
        .expect("count inserted audit rows");
    assert_eq!(count, 2, "both audit rows should have been inserted");
}
