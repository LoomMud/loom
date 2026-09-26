// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! `disconnect(ob)`: a mudlib-initiated close (the `quit` command).

mod common;

use common::{FakeHost, scratch};
use loom_vm::World;

const MASTER: &str = "pub fn connect() -> object {\n    return clone_object(\"/std/player\")\n}\n";
const PLAYER: &str = r#"var dead: int = 0

pub fn logon() {
    send(self, "hi\n")
}

pub fn process_input(line: string) {
    if trim(line) == "quit" {
        send(self, "bye\n")
        disconnect(self)
        disconnect(null)
    } else {
        send(self, $"dead={dead}\n")
    }
}

pub fn net_dead() {
    dead += 1
}

pub fn deaths() -> int {
    return dead
}
"#;

#[test]
fn disconnect_closes_the_bound_connection_only() {
    let root = scratch("disconnect");
    for (path, src) in [("secure/master.wf", MASTER), ("std/player.wf", PLAYER)] {
        let p = root.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, src).unwrap();
    }
    let mut world = World::boot(&root).expect("boot");
    let mut host = FakeHost::default();
    world.connect(1, &mut host);
    world.connect(2, &mut host);
    assert_eq!(host.take(1), "hi\n");
    assert_eq!(host.take(2), "hi\n");

    world.input(1, "quit", &mut host);
    assert_eq!(host.take(1), "bye\n");
    assert_eq!(host.closed, vec![1]);

    // The network layer reports the close; net_dead() runs exactly once.
    let player = world
        .connection_object(1)
        .expect("still bound until reported");
    world.disconnect(1, &mut host);
    world.disconnect(1, &mut host);
    assert!(world.connection_object(1).is_none());
    let deaths = world
        .call(player, "deaths", vec![], &mut host)
        .expect("call");
    assert_eq!(world.display(&deaths), "1");

    // The other connection is untouched.
    world.input(2, "look", &mut host);
    assert_eq!(host.take(2), "dead=0\n");
    assert_eq!(host.closed, vec![1]);
}
