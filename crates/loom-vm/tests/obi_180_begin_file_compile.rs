// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `World::begin_file_compile` (OBI-180 M-FS-5, CTO review of PR #119 on
//! `c29c7a3`, must-fix 1): a `/api/v1/files/compile` driver entry point
//! that authorizes on the world thread -- the same `authorize(P1,
//! Operation::Compile)` call and audit record `compile_object`'s
//! synchronous efun arm makes -- but hands the actual compile off to
//! `loom-vm`'s background compile-worker thread (OBI-90, D-P1.5) instead
//! of running it inside the authorizing `World::exec`.

mod common;

use std::time::Duration;

use common::{FakeHost, on_world_thread, scratch};
use loom_vm::World;

/// `valid_compile` mirrors `valid_write`'s "own `/builders/<uid>/**`
/// only" policy (plus `arch`, who may compile anywhere) -- enough to
/// prove `begin_file_compile` runs the real master apply, not a
/// hardcoded Rust ACL (spec D-TM5), same reasoning as
/// `obi_180_file_efun_channel.rs`'s `MASTER`.
const MASTER: &str = r#"
fn valid_efun(name: string, class: int, ob: object) -> bool {
    return true
}

fn valid_read(path: string, ob: object, op: string) -> bool {
    return true
}

fn valid_write(path: string, ob: object, op: string) -> bool {
    return true
}

fn valid_compile(path: string, ob: object) -> bool {
    let who = effective_principal()
    let parts = split(path, "/")
    if who == "arch" {
        return true
    }
    return len(parts) >= 3 and parts[1] == "builders" and parts[2] == who
}
"#;

fn boot(tag: &str) -> (World, FakeHost, std::path::PathBuf) {
    let root = scratch(tag);
    let p = root.join("secure/master.wf");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, MASTER).unwrap();
    let world = World::boot(&root).expect("boot");
    (world, FakeHost::default(), root)
}

fn write_program(root: &std::path::Path, rel: &str, src: &str) {
    let p = root.join(rel.trim_start_matches('/'));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, src).unwrap();
}

/// A clean compile authorizes, runs off the world thread, and installs
/// once `take_finished_recompiles` is drained.
#[test]
fn a_clean_compile_authorizes_and_installs_off_the_world_thread() {
    on_world_thread(|| {
        let (mut world, mut host, root) = boot("begin-compile-clean");
        write_program(&root, "/builders/frodo/a.wf", "var x: int = 1\n");
        world.load_object("/builders/frodo/a", &mut host).unwrap();

        write_program(&root, "/builders/frodo/a.wf", "var x: int = 2\n");
        let token = world
            .begin_file_compile("frodo", "/builders/frodo/a", &mut host)
            .expect("frodo may compile under their own workroom");

        let mut results = Vec::new();
        for _ in 0..200 {
            world.tick(&mut host);
            results = world.take_finished_recompiles();
            if !results.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, token);
        assert_eq!(results[0].1, Ok(()));
        assert_eq!(world.program_version("/builders/frodo/a"), Some(2));
    });
}

/// `begin_file_compile` for a path a uid may not compile refuses at the
/// authorize step, before any background compile ever starts -- same
/// `Err` shape `call_file_efun` already gives `/api/v1/files/*` for a
/// refused `read_file`/`write_file` (M-FS-3's HTTP-layer 404 mapping).
#[test]
fn a_refused_path_never_starts_a_background_compile() {
    on_world_thread(|| {
        let (mut world, mut host, root) = boot("begin-compile-refused");
        write_program(&root, "/builders/frodo/secret.wf", "var x: int = 0\n");

        let err = world
            .begin_file_compile("sam", "/builders/frodo/secret", &mut host)
            .expect_err("sam may not compile frodo's workroom");
        assert!(err.contains("permission denied"), "got: {err}");

        // Nothing queued -- draining immediately finds no results, ever
        // (not just "not yet").
        world.tick(&mut host);
        assert!(world.take_finished_recompiles().is_empty());
    });
}

/// A reserved principal is refused outright, same as `call_file_efun`.
#[test]
fn a_reserved_principal_is_refused_outright() {
    on_world_thread(|| {
        let (mut world, mut host, _root) = boot("begin-compile-reserved");
        let err = world
            .begin_file_compile("root", "/builders/frodo/a", &mut host)
            .expect_err("root is a reserved principal");
        assert!(err.contains("reserved principal"), "got: {err}");
    });
}
