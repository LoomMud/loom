// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 0 exit criterion, language half: walk between two rooms and
//! `update` a room's description live without disconnecting.

mod common;

use common::{FakeHost, fixture};
use loom_vm::{Value, World};

const HALL: &str = "domains/start/hall.wf";

#[test]
fn walk_update_room_live_without_disconnect() {
    let root = fixture("tworoom");
    let mut world = World::boot(&root).expect("boot");
    let mut host = FakeHost::default();

    // Connect: master connect() -> player clone, bound, logon() moves to hall.
    world.connect(1, &mut host);
    let out = host.take(1);
    assert!(out.contains("Welcome to Loom!"), "{out}");
    assert!(out.contains("The Great Hall"), "{out}");
    assert!(out.contains("A vast hall with a vaulted ceiling."), "{out}");
    let player = world.connection_object(1).expect("bound");
    assert!(
        world
            .object_name(player)
            .unwrap()
            .starts_with("/std/player#")
    );

    // Walk north and back.
    world.input(1, "go north", &mut host);
    let out = host.take(1);
    assert!(out.contains("The Yard"), "{out}");
    assert!(out.contains("A muddy yard"), "{out}");
    world.input(1, "go south", &mut host);
    assert!(host.take(1).contains("The Great Hall"));
    world.input(1, "name frodo", &mut host);
    host.take(1);

    let hall = world
        .find_object("/domains/start/hall")
        .expect("hall loaded");
    assert_eq!(world.environment(player), Some(hall));
    assert_eq!(world.program_version("/domains/start/hall"), Some(1));
    assert!(matches!(world.var(player, "moves"), Some(Value::Int(2))));

    // Rewrite the room: new description plus a new variable.
    let src = std::fs::read_to_string(root.join(HALL)).unwrap();
    let src = src
        .replace(
            "A vast hall with a vaulted ceiling.",
            "A vast hall, freshly repainted in gold.",
        )
        .replace(
            "pub override fn long()",
            "var paint: string = \"gold\"\n\npub override fn long()",
        );
    std::fs::write(root.join(HALL), src).unwrap();

    // `update` from inside the game, via the player's own command.
    world.input(1, "update /domains/start/hall", &mut host);
    let out = host.take(1);
    assert_eq!(out, "Updated /domains/start/hall.\n");
    world.input(1, "look", &mut host);
    let out = host.take(1);
    assert!(out.contains("freshly repainted in gold"), "{out}");
    assert!(!out.contains("vaulted ceiling"), "{out}");
    // Inherited state set by create() survived (create() is not re-run).
    assert!(out.contains("The Great Hall"), "{out}");
    assert!(out.contains("Exits: north"), "{out}");

    // Same room object, new program version, new variable initialised.
    assert_eq!(world.find_object("/domains/start/hall"), Some(hall));
    assert_eq!(world.program_version("/domains/start/hall"), Some(2));
    assert!(world.var(hall, "paint").as_ref().and_then(Value::as_str) == Some("gold"));

    // Player untouched: same id, same variables, still bound and in the hall.
    assert_eq!(world.connection_object(1), Some(player));
    assert_eq!(world.environment(player), Some(hall));
    assert!(matches!(world.var(player, "moves"), Some(Value::Int(2))));
    assert!(world.var(player, "name").as_ref().and_then(Value::as_str) == Some("frodo"));
    assert!(host.closed.is_empty());

    // A broken edit is rejected with diagnostics; the old program keeps running.
    std::fs::write(
        root.join(HALL),
        "inherit /std/room\n\npub override fn long() -> string {\n    return \"oops\" +\n}\n",
    )
    .unwrap();
    world.input(1, "update /domains/start/hall", &mut host);
    let out = host.take(1);
    assert!(out.contains("/domains/start/hall.wf:5:1: error"), "{out}");
    assert_eq!(world.program_version("/domains/start/hall"), Some(2));
    world.input(1, "look", &mut host);
    assert!(host.take(1).contains("freshly repainted in gold"));
    assert_eq!(world.connection_object(1), Some(player));

    // Link errors (not just syntax) are rejected too.
    std::fs::write(
        root.join(HALL),
        "inherit /std/room\n\nfn long() -> string {\n    return \"no override\"\n}\n",
    )
    .unwrap();
    world.input(1, "update /domains/start/hall", &mut host);
    let out = host.take(1);
    assert!(
        out.contains("redefines a function inherited from /std/room"),
        "{out}"
    );
    assert!(out.contains("help: write `override fn long(…)`"), "{out}");
    assert_eq!(world.program_version("/domains/start/hall"), Some(2));

    // Walking still works after all that.
    world.input(1, "go north", &mut host);
    assert!(host.take(1).contains("The Yard"));
    world.disconnect(1, &mut host);
    assert_eq!(world.connection_object(1), None);
}

#[test]
fn recompiling_a_parent_upgrades_dependents_and_clones() {
    let root = fixture("tworoom");
    let mut world = World::boot(&root).expect("boot");
    let mut host = FakeHost::default();
    world.connect(1, &mut host);
    world.connect(2, &mut host);
    world.input(1, "go north", &mut host);
    host.out.clear();
    let (p1, p2) = (
        world.connection_object(1).unwrap(),
        world.connection_object(2).unwrap(),
    );

    // Change the base room: new look() format, a removed and an added var.
    let room = root.join("std/room.wf");
    let src = std::fs::read_to_string(&room).unwrap();
    let src = src.replace(
        "Exits: {join(names, \", \")}",
        "Ways out: {join(names, \" and \")}",
    );
    std::fs::write(&room, src).unwrap();
    assert_eq!(world.compile_object("/std/room", &mut host), Ok(vec![]));
    assert_eq!(world.program_version("/std/room"), Some(2));
    assert_eq!(world.program_version("/domains/start/hall"), Some(2));
    assert_eq!(world.program_version("/domains/start/yard"), Some(2));

    world.input(1, "look", &mut host);
    let out = host.take(1);
    assert!(
        out.contains("The Yard") && out.contains("Ways out: south"),
        "{out}"
    );
    world.input(2, "look", &mut host);
    let out = host.take(2);
    assert!(
        out.contains("The Great Hall") && out.contains("Ways out: north"),
        "{out}"
    );

    // Player clones: recompile their program, both switch, state kept.
    world.input(1, "name sam", &mut host);
    let pl = root.join("std/player.wf");
    let src = std::fs::read_to_string(&pl).unwrap();
    let src = src.replace(
        "send(self, \"What?\\n\")",
        "send(self, $\"Eh, {name}?\\n\")",
    );
    std::fs::write(&pl, src).unwrap();
    host.out.clear();
    world.input(2, "update /std/player", &mut host);
    assert_eq!(host.take(2), "Updated /std/player.\n");
    world.input(1, "dance", &mut host);
    assert_eq!(host.take(1), "Eh, sam?\n");
    world.input(2, "dance", &mut host);
    assert_eq!(host.take(2), "Eh, guest?\n");
    assert_eq!(world.connection_object(1), Some(p1));
    assert_eq!(world.connection_object(2), Some(p2));
    assert_eq!(
        world.object_program_version(p1),
        Some(("/std/player".into(), 2))
    );
}

#[test]
fn failing_dependent_rejects_the_whole_set() {
    let root = fixture("tworoom");
    let mut world = World::boot(&root).expect("boot");
    let mut host = FakeHost::default();
    world.connect(1, &mut host);
    world.input(1, "go north", &mut host); // loads the yard
    host.out.clear();
    // Rename long() in the base: hall/yard's `override fn long` now overrides nothing.
    let room = root.join("std/room.wf");
    let src = std::fs::read_to_string(&room).unwrap();
    std::fs::write(&room, src.replace("long()", "long_desc()")).unwrap();
    let err = world
        .compile_object("/std/room", &mut host)
        .expect_err("must fail");
    // Deviation from the tree-walker (spec r5, flagged not hidden):
    // `bcvm::registry::Compiler::recompile` doesn't wrap a failing
    // dependent's diagnostic with "{path} changed, but dependent {d.path}
    // no longer compiles" the way `crate::world::Exec::recompile` used to
    // — it surfaces the dependent's own rendered diagnostic as-is. The
    // all-or-nothing behaviour (nothing is installed) is unchanged.
    assert!(err.contains("/domains/start/"), "{err}");
    assert!(err.contains("overrides nothing"), "{err}");
    assert_eq!(world.program_version("/std/room"), Some(1));
    assert_eq!(world.program_version("/domains/start/hall"), Some(1));
    world.input(1, "look", &mut host);
    assert!(host.take(1).contains("A muddy yard"));
}

#[test]
fn failing_initialiser_rolls_back_the_upgrade() {
    let root = fixture("tworoom");
    let mut world = World::boot(&root).expect("boot");
    let mut host = FakeHost::default();
    world.connect(1, &mut host);
    host.out.clear();
    let hall = world.find_object("/domains/start/hall").unwrap();
    std::fs::write(
        root.join(HALL),
        "inherit /std/room\n\nvar boom: int = 1 / 0\n\npub override fn long() -> string {\n    return \"new\"\n}\n",
    )
    .unwrap();
    // Spec r5 amendment (§7.2 step 6.4): a per-object migration failure is
    // reported, not fatal — `compile_object` itself still succeeds (the
    // new program installs), but the one instance whose `$init` failed
    // rolls back to its old version instead of the whole recompile being
    // rejected.
    let warnings = world
        .compile_object("/domains/start/hall", &mut host)
        .expect("install itself must not fail");
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("division by zero"), "{warnings:?}");
    // The registry-level program did install (spec r5: only the failing
    // *object's* migration rolled back, not the whole recompile) — new
    // clones from here on get v2; this pre-existing instance stays on v1.
    assert_eq!(world.program_version("/domains/start/hall"), Some(2));
    assert_eq!(
        world.object_program_version(hall),
        Some(("/domains/start/hall".into(), 1))
    );
    assert!(world.var(hall, "boom").is_none());
    world.input(1, "look", &mut host);
    assert!(host.take(1).contains("vaulted ceiling"));
}
