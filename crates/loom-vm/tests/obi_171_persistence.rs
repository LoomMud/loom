// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-171 (spec §8.1/§7.3): `save_object`/`restore_object` end to end
//! through [`World`] -- persistent-only scope, a round trip into a fresh
//! object, a missing save reporting `false` instead of erroring, and the
//! headline acceptance criterion: a save written under one program
//! version restores correctly into a *later* version via the same §7.3
//! by-name migration path hot reload uses (lossless carryover where the
//! type still conforms, `upgrade(from_version, old)` where it doesn't).
//!
//! The third acceptance test ("crash during write leaves the old save
//! intact") is covered at the `loom_vm::fileio` unit level
//! (`crash_before_rename_leaves_the_previous_save_intact`), which drives
//! the exact write-then-rename window `save_object` depends on without
//! needing to actually kill a process mid-syscall; this file does not
//! duplicate it.

mod common;

use common::{FakeHost, fixture};
use loom_vm::world::Limits;
use loom_vm::{Value, World};

const PLAYER: &str = "std/player.wf";

const PLAYER_V2: &str = r#"
persistent var hp: string = "unset"
persistent var title: string = "adventurer"
persistent var stats: {string: string} = { "str": "10", "dex": "10" }
persistent var shield: int = 0
var not_persistent: int = 999

pub fn logon() {
    send(self, "ok\n")
}

pub fn net_dead() {
}

pub fn upgrade(from_version: int, old: {string: any}) {
    if "hp" in old {
        hp = $"migrated from v{from_version}"
    }
    if "stats" in old {
        stats = { "str": "unknown", "dex": "unknown" }
    }
}

pub fn process_input(line: string) {
    let words = split(trim(line), " ")
    let verb = words[0]
    if verb == "gethp" {
        send(self, $"{hp}\n")
    } else if verb == "gettitle" {
        send(self, $"{title}\n")
    } else if verb == "getstats" {
        let a = stats["str"] ?? ""
        let b = stats["dex"] ?? ""
        send(self, $"{a} {b}\n")
    } else if verb == "getshield" {
        send(self, $"{shield}\n")
    } else if verb == "getnotpersistent" {
        send(self, $"{not_persistent}\n")
    } else if verb == "savefile" and len(words) == 2 {
        send(self, $"{save_object(words[1])}\n")
    } else if verb == "restorefile" and len(words) == 2 {
        send(self, $"{restore_object(words[1])}\n")
    } else if verb == "update" and len(words) == 2 {
        let err = compile_object(words[1])
        if err == null {
            send(self, "updated\n")
        } else {
            send(self, $"{err}\n")
        }
    } else {
        send(self, "What?\n")
    }
}
"#;

#[test]
fn round_trip_restores_only_persistent_vars_into_a_fresh_object() {
    let root = fixture("persist");
    let mut world = World::boot(&root).expect("boot");
    world.set_save_root(common::scratch("persist-saves-roundtrip"));
    let mut host = FakeHost::default();

    world.connect(1, &mut host);
    host.take(1);
    world.input(1, "sethp 55", &mut host);
    host.take(1);
    world.input(1, "setstats 7 8", &mut host);
    host.take(1);
    world.input(1, "setnotpersistent 123", &mut host);
    host.take(1);
    world.input(1, "savefile /bob", &mut host);
    assert_eq!(host.take(1), "true\n");

    world.connect(2, &mut host);
    host.take(2);
    world.input(2, "setnotpersistent 777", &mut host);
    host.take(2);
    world.input(2, "restorefile /bob", &mut host);
    assert_eq!(host.take(2), "true\n");

    world.input(2, "gethp", &mut host);
    assert_eq!(host.take(2), "55\n", "persistent scalar var restored");
    world.input(2, "getstats", &mut host);
    assert_eq!(
        host.take(2),
        "7 8\n",
        "persistent map var restored key-by-key"
    );
    world.input(2, "gettitle", &mut host);
    assert_eq!(
        host.take(2),
        "adventurer\n",
        "a persistent var never touched after create() still saved/restores its value"
    );
    world.input(2, "getnotpersistent", &mut host);
    assert_eq!(
        host.take(2),
        "777\n",
        "a non-`persistent` var must never be saved or restored"
    );
}

#[test]
fn driver_autosaves_periodically_and_on_disconnect() {
    let root = fixture("persist");
    let limits = Limits {
        autosave_interval_ticks: 3,
        ..Limits::default()
    };
    let mut world = World::boot_with_limits(&root, limits).expect("boot");
    world.set_save_root(common::scratch("persist-saves-autosave"));
    let mut host = FakeHost::default();

    world.connect(1, &mut host);
    host.take(1);
    world.input(1, "getautosavecount", &mut host);
    assert_eq!(
        host.take(1),
        "0\n",
        "no autosave has run yet right after connecting"
    );

    // Three ticks hits the (test-shortened) autosave interval exactly
    // once: the driver-level hook (spec §8.1 "every 5 min") fires without
    // the mudlib doing anything beyond defining `autosave()`.
    world.tick(&mut host);
    world.tick(&mut host);
    world.tick(&mut host);
    world.input(1, "getautosavecount", &mut host);
    assert_eq!(
        host.take(1),
        "1\n",
        "World::tick must call autosave() once every autosave_interval_ticks \
         for every connected object"
    );

    // Disconnect (both an explicit `quit`-style close and a real net-dead
    // drop land on `World::disconnect`, spec §8.1's other two triggers)
    // must itself call `autosave()` one more time before unbinding --
    // checked directly on the object's own var rather than through a
    // connection (there is no connection left to read a reply from).
    let player = world.connection_object(1).expect("bound");
    world.disconnect(1, &mut host);
    assert!(
        matches!(world.var(player, "autosave_count"), Some(Value::Int(2))),
        "disconnect (quit or net-dead) must call autosave() once more, \
         on top of the one periodic tick-driven call above"
    );
}

#[test]
fn restoring_a_save_that_does_not_exist_returns_false_not_an_error() {
    let root = fixture("persist");
    let mut world = World::boot(&root).expect("boot");
    world.set_save_root(common::scratch("persist-saves-missing"));
    let mut host = FakeHost::default();

    world.connect(1, &mut host);
    host.take(1);
    world.input(1, "restorefile /nobody-home", &mut host);
    assert_eq!(host.take(1), "false\n");
}

/// The headline acceptance criterion: save under v1, evolve the program
/// (a type change on a plain var *and* a struct field change), `update`
/// it live, then restore the v1 save into a brand-new v2 instance. The
/// scalar var whose type changed must go through `upgrade(from_version,
/// old)` (spec §7.3's "restoring an old save into a new program runs the
/// same migration path"); the struct field that survives carries over
/// by name, and the one it gained fills in from its own default.
#[test]
fn a_save_from_an_older_program_version_migrates_through_upgrade_on_restore() {
    let root = fixture("persist");
    let mut world = World::boot(&root).expect("boot");
    world.set_save_root(common::scratch("persist-saves-upgrade"));
    let mut host = FakeHost::default();

    world.connect(1, &mut host);
    host.take(1);
    world.input(1, "sethp 42", &mut host);
    host.take(1);
    world.input(1, "setstats 33 44", &mut host);
    host.take(1);
    world.input(1, "savefile /alice", &mut host);
    assert_eq!(host.take(1), "true\n");
    assert_eq!(world.program_version("/std/player"), Some(1));

    std::fs::write(root.join(PLAYER), PLAYER_V2).unwrap();
    world.input(1, "update /std/player", &mut host);
    assert_eq!(host.take(1), "updated\n");

    world.connect(2, &mut host);
    host.take(2);
    assert_eq!(world.program_version("/std/player"), Some(2));
    world.input(2, "restorefile /alice", &mut host);
    assert_eq!(host.take(2), "true\n");

    world.input(2, "gethp", &mut host);
    assert_eq!(
        host.take(2),
        "migrated from v1\n",
        "hp: int -> string is lossy; upgrade(1, old) must have run with \
         old[\"hp\"] == the saved int"
    );
    world.input(2, "getstats", &mut host);
    assert_eq!(
        host.take(2),
        "unknown unknown\n",
        "stats: {{string: int}} -> {{string: string}} is lossy (every \
         value's type changed); upgrade(1, old) must have run with \
         old[\"stats\"] == the saved map"
    );
    world.input(2, "getshield", &mut host);
    assert_eq!(
        host.take(2),
        "0\n",
        "a brand new persistent var the save has nothing for keeps its \
         own create()-time default"
    );
}
