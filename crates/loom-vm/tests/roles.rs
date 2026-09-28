// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-36 (S2b): `RolesSnapshot` + `World::set_roles_snapshot`, the
//! secure-only read efuns, and the async mutation efuns' actor rule
//! (design note D-S2.1/D-S2.2).

mod common;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::Arc;

use common::{FakeHost, fixture};
use loom_vm::{RolesMutations, RolesSnapshot, Value, World};

fn seeded() -> RolesSnapshot {
    RolesSnapshot::from_seed_json(
        r#"{
            "staff": {"frodo": 3, "sam": 1},
            "domain_members": {"shire": {"frodo": "lead", "sam": "member"}},
            "tier_policy": {"3": {"max_ticks_exec": 2000000}},
            "grants": [{"uid": "sam", "kind": "efun", "target": "write_file", "expires_at": null}]
        }"#,
    )
    .expect("seed parses")
}

fn boot() -> (World, FakeHost) {
    let root = fixture("roles");
    let world = World::boot(&root).expect("boot");
    (world, FakeHost::default())
}

#[test]
fn non_secure_caller_of_read_efuns_is_a_runtime_error() {
    let (mut world, mut host) = boot();
    world.set_roles_snapshot(Arc::new(seeded()));
    let ob = world
        .load_object("/builders/appr/obj", &mut host)
        .expect("load");
    let e = world
        .call(ob, "call_roles_tier", vec![Value::str("frodo")], &mut host)
        .unwrap_err();
    assert!(e.contains("only code under /secure"), "{e}");
}

#[test]
fn secure_caller_can_read_every_field_of_the_snapshot() {
    let (mut world, mut host) = boot();
    world.set_roles_snapshot(Arc::new(seeded()));
    let roles = world.load_object("/secure/roles", &mut host).expect("load");

    let v = world
        .call(roles, "tier", vec![Value::str("frodo")], &mut host)
        .unwrap();
    assert_eq!(v.as_str(), None);
    assert!(matches!(v, Value::Int(3)));

    assert!(matches!(
        world
            .call(roles, "tier", vec![Value::str("nobody")], &mut host)
            .unwrap(),
        Value::Int(0)
    ));

    assert!(matches!(
        world
            .call(
                roles,
                "is_member",
                vec![Value::str("sam"), Value::str("shire")],
                &mut host
            )
            .unwrap(),
        Value::Bool(true)
    ));
    assert!(matches!(
        world
            .call(
                roles,
                "is_lead",
                vec![Value::str("sam"), Value::str("shire")],
                &mut host
            )
            .unwrap(),
        Value::Bool(false)
    ));
    assert!(matches!(
        world
            .call(
                roles,
                "is_lead",
                vec![Value::str("frodo"), Value::str("shire")],
                &mut host
            )
            .unwrap(),
        Value::Bool(true)
    ));

    assert!(matches!(
        world
            .call(
                roles,
                "has_grant",
                vec![
                    Value::str("sam"),
                    Value::str("efun"),
                    Value::str("write_file")
                ],
                &mut host
            )
            .unwrap(),
        Value::Bool(true)
    ));
    assert!(matches!(
        world
            .call(
                roles,
                "has_grant",
                vec![
                    Value::str("sam"),
                    Value::str("efun"),
                    Value::str("read_file")
                ],
                &mut host
            )
            .unwrap(),
        Value::Bool(false)
    ));

    let domains = world
        .call(roles, "domains", vec![Value::str("sam")], &mut host)
        .unwrap();
    let names: Vec<&str> = domains
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["shire"]);

    let policy = world
        .call(roles, "policy", vec![Value::Int(3)], &mut host)
        .unwrap();
    let m = policy.as_map().unwrap();
    assert!(matches!(
        m.get(&Value::str("max_ticks_exec")),
        Some(Value::Int(2_000_000))
    ));
    let empty_policy = world
        .call(roles, "policy", vec![Value::Int(0)], &mut host)
        .unwrap();
    assert_eq!(empty_policy.as_map().unwrap().entries.len(), 0);
}

/// The central integration test: a snapshot swap flushes the security
/// cache, and the *next* execution sees the new tier -- not a stale
/// `valid_write` decision cached against the old snapshot.
#[test]
fn snapshot_swap_flushes_the_security_cache_and_the_next_write_sees_the_new_tier() {
    let (mut world, mut host) = boot();
    world.set_roles_snapshot(Arc::new(
        RolesSnapshot::from_seed_json(r#"{"staff": {"bob": 1}}"#).unwrap(),
    ));
    world.connect(1, &mut host);
    host.take(1);
    world.input(1, "become bob", &mut host);
    host.take(1);

    // Tier 1 < 2: valid_write denies, and the decision is cached.
    world.input(1, "writefile /builders/bob/a.txt hi", &mut host);
    let out = host.take(1);
    assert!(out.contains("denied"), "{out:?}");
    assert!(world.security().denials >= 1);

    // Swap in a snapshot where bob is tier 3: `set_roles_snapshot` must
    // flush the cache, or this would still read the stale denial.
    world.set_roles_snapshot(Arc::new(
        RolesSnapshot::from_seed_json(r#"{"staff": {"bob": 3}}"#).unwrap(),
    ));
    world.input(1, "writefile /builders/bob/a.txt hi", &mut host);
    assert_eq!(
        host.take(1),
        "true\n",
        "the new tier must apply immediately"
    );
}

/// Test-double `RolesMutations` recording every call it received, so the
/// actor-rule tests below can assert exactly what `actor` the driver
/// passed -- never a string read from Weft. `Rc<RefCell<_>>`-backed so the
/// test keeps a handle to the log after handing the trait object to
/// `World::set_roles_backend` (which takes ownership of it).
type SetTierCall = (String, String, i64, String); // (actor, target, tier, reason)

#[derive(Clone, Default)]
struct RecordingBackend {
    set_tier_calls: Rc<RefCell<VecDeque<SetTierCall>>>,
}

impl RolesMutations for RecordingBackend {
    fn set_tier(&mut self, _id: u64, actor: &str, target: &str, tier: i64, reason: &str) -> bool {
        self.set_tier_calls.borrow_mut().push_back((
            actor.to_string(),
            target.to_string(),
            tier,
            reason.to_string(),
        ));
        true
    }
    fn set_member(
        &mut self,
        _id: u64,
        _actor: &str,
        _domain: &str,
        _target: &str,
        _role: &str,
        _reason: &str,
    ) -> bool {
        true
    }
    fn grant(
        &mut self,
        _id: u64,
        _actor: &str,
        _target: &str,
        _kind: &str,
        _what: &str,
        _expires_at: Option<i64>,
        _reason: &str,
    ) -> bool {
        true
    }
    fn revoke_grant(
        &mut self,
        _id: u64,
        _actor: &str,
        _target: &str,
        _kind: &str,
        _what: &str,
        _reason: &str,
    ) -> bool {
        true
    }
    fn propose_tier(
        &mut self,
        _id: u64,
        _actor: &str,
        _target: &str,
        _tier: i64,
        _reason: &str,
    ) -> bool {
        true
    }
    fn approve(&mut self, _id: u64, _actor: &str, _proposal_id: i64) -> bool {
        true
    }
}

/// AC: "from input by a T3: the actor is the T3 euid", and "a Weft string
/// is never used as the actor" -- the recorded actor is the interactive's
/// own euid (`become`'s `seteuid`), never `target` ("root") or `reason`
/// ("haha"), even though both are attacker-controlled Weft strings passed
/// straight to the mutation efun.
#[test]
fn mutation_actor_is_the_interactives_euid_from_input_never_a_weft_string() {
    let (mut world, mut host) = boot();
    let backend = RecordingBackend::default();
    let log = backend.set_tier_calls.clone();
    world.set_roles_backend(Box::new(backend));
    world.connect(1, &mut host);
    host.take(1);
    world.input(1, "become t3lead", &mut host);
    host.take(1);

    world.input(1, "settier root 5 haha", &mut host);
    let out = host.take(1);
    assert!(out.starts_with("req "), "{out:?}");

    let calls = log.borrow();
    assert_eq!(calls.len(), 1);
    let (actor, target, tier, reason) = &calls[0];
    assert_eq!(actor, "t3lead", "actor must be the interactive's own euid");
    assert_eq!(
        target, "root",
        "target is the Weft-supplied string, unrelated to actor"
    );
    assert_eq!(*tier, 5);
    assert_eq!(reason, "haha");
    assert_ne!(
        actor, target,
        "the actor must never be laundered from a Weft-supplied string argument"
    );
}

#[test]
fn mutation_efun_is_refused_from_a_call_out() {
    let (mut world, mut host) = boot();
    world.connect(1, &mut host);
    host.take(1);
    world.input(1, "become t3lead", &mut host);
    host.take(1);

    world.input(1, "schedcall", &mut host);
    host.take(1);
    // The scheduled call_out fires with no `input_actor` at all (it is
    // not started by player input), so `roles_set_tier` must refuse it.
    for _ in 0..3 {
        world.tick(&mut host);
    }
    world.input(1, "mutation_error", &mut host);
    let out = host.take(1);
    assert!(
        out.contains("refused"),
        "call_out must not be able to act as the roles actor: {out:?}"
    );
}

#[test]
fn mutation_efun_is_refused_when_the_actors_euid_has_left_the_guard_set() {
    let (mut world, mut host) = boot();
    world.connect(1, &mut host);
    host.take(1);
    world.input(1, "become t3lead", &mut host);
    host.take(1);

    // `/secure/roles`'s `set_tier_after_cut` calls `unguarded`, which
    // restarts the guard at its own (root) euid -- dropping t3lead's
    // euid that `World::input` captured as the actor at the cut, even
    // though `input_actor` itself is unchanged. The mutation must still
    // be refused.
    world.input(1, "cutsettier", &mut host);
    let out = host.take(1);
    assert!(
        out.contains("refused"),
        "a cut that drops the actor's euid from the guard set must still refuse: {out:?}"
    );
}
