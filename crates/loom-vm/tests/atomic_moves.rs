// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `atomic fn` journaling of inventory moves (spec r5 §5.2.1, CTO review
//! of OBI-32): `move_to` is the spec's headline `atomic` use case
//! (`transfer_to`), so a failing `atomic fn` must undo it exactly, not
//! just object-variable writes.

mod common;

use common::FakeHost;
use loom_vm::World;

fn run_files(files: &[(&str, &str)]) -> Result<String, String> {
    let root = common::scratch("atomic_moves");
    for (path, src) in files {
        let p = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, src).unwrap();
    }
    let mut world = World::boot(&root).map_err(|e| e.to_string())?;
    let master = world.find_object("/secure/master").unwrap();
    let v = world.call(master, "main", vec![], &mut FakeHost::default())?;
    Ok(world.display(&v))
}

fn ok(files: &[(&str, &str)]) -> String {
    run_files(files).unwrap_or_else(|e| panic!("unexpected error:\n{e}"))
}

const THING: &str = "pub fn go(dest: object) {\n  move_to(dest)\n}\natomic fn go_then_fail(dest: object) {\n  move_to(dest)\n  throw \"boom\"\n}\n";
const ROOM: &str = "fn create() {}\n";

/// (a): an existing item moved by an `atomic fn` that then throws ends up
/// back in its original room, at its original inventory index (not just
/// "somewhere in A" — appended at the end would also pass a weaker
/// count-only check), and the destination room is left untouched.
#[test]
fn atomic_move_of_an_existing_item_rolls_back_to_its_original_slot() {
    let master = r#"
fn main() -> any {
    let room_a = clone_object("/obj/room")
    let room_b = clone_object("/obj/room")
    let item1 = clone_object("/obj/thing")
    let item2 = clone_object("/obj/thing")
    let item3 = clone_object("/obj/thing")
    item1.go(room_a)
    item2.go(room_a)
    item3.go(room_a)
    try {
        item2.go_then_fail(room_b)
    } catch e {
    }
    return [inventory(room_a), inventory(room_b)]
}
"#;
    let r = ok(&[
        ("/secure/master.wf", master),
        ("/obj/thing.wf", THING),
        ("/obj/room.wf", ROOM),
    ]);
    assert_eq!(
        r, "[[/obj/thing#3, /obj/thing#4, /obj/thing#5], []]",
        "item2 must be back at index 1 in room_a (not merely present), and room_b must be unchanged"
    );
}

/// (b): `clone_object` + `move_to(room)` + `throw` inside one `atomic fn`
/// must leave the room's inventory exactly as it was before the call —
/// not just missing the clone's *variables* (already covered by the
/// pre-existing `Clone` journal entry) but with no dangling id left in
/// `room.inventory` either, which is what happens if the `Move` undo does
/// not run before the `Clone` undo deletes the object.
#[test]
fn atomic_clone_and_move_then_fail_leaves_the_room_inventory_unchanged() {
    let master = r#"
atomic fn clone_and_move_then_fail(room: object) {
    let c = clone_object("/obj/thing")
    c.go(room)
    throw "boom"
}

fn main() -> any {
    let room_a = clone_object("/obj/room")
    let resident = clone_object("/obj/thing")
    resident.go(room_a)
    let before = inventory(room_a)
    try {
        clone_and_move_then_fail(room_a)
    } catch e {
    }
    let after = inventory(room_a)
    return [before, after]
}
"#;
    let r = ok(&[
        ("/secure/master.wf", master),
        ("/obj/thing.wf", THING),
        ("/obj/room.wf", ROOM),
    ]);
    // `before` and `after` must render identically: same single
    // resident, no dangling clone id left over from the rolled-back
    // clone_object + move_to.
    assert_eq!(
        r, "[[/obj/thing#2], [/obj/thing#2]]",
        "room_a's inventory must be unchanged: got {r}"
    );
}
