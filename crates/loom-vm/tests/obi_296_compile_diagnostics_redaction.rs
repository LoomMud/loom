// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `World::take_finished_recompiles` diagnostics redaction (OBI-296
//! T-FS-3, follow-up from the CTO review of PR #119/OBI-180): a builder
//! driving `POST /api/v1/files/compile` must never see the path,
//! identifiers, or source fragments of a program their uid cannot
//! `valid_read`, even though the rebuilt set (`World::begin_file_compile`
//! -> `loom-vm`'s background compile-worker thread) covers inherited
//! ancestors and every dependent of the path they asked to compile --
//! widening the blast radius of what a single compile can surface far
//! past the one path the uid actually authorized.
//!
//! `run_recompile` (`loom_vm::bcvm::compile_worker`) stops at the first
//! failing path in that rebuilt set, so each scenario below only ever
//! has exactly one failing dependent -- the other scenario's diagnostic
//! never gets a chance to run.

mod common;

use std::time::Duration;

use common::{on_world_thread, scratch, FakeHost};
use loom_vm::World;

/// `valid_read` denies everything under `/secure` to anyone but `root`
/// (the only thing this redaction depends on); `valid_compile` mirrors
/// `obi_180_begin_file_compile.rs`'s "own `/builders/<uid>/**` only".
const MASTER: &str = r#"
fn valid_efun(name: string, class: int, ob: object) -> bool {
    return true
}

fn valid_read(path: string, ob: object, op: string) -> bool {
    let who = effective_principal()
    if who == "root" {
        return true
    }
    let parts = split(path, "/")
    if len(parts) >= 2 and parts[1] == "secure" {
        return false
    }
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

/// Drives `world` until `begin_file_compile`'s `token` shows up in
/// `take_finished_recompiles`, returning its result.
fn await_compile(
    world: &mut World,
    host: &mut FakeHost,
    token: loom_vm::world::RecompileToken,
) -> Result<(), String> {
    for _ in 0..200 {
        world.tick(host);
        for (t, result) in world.take_finished_recompiles() {
            if t == token {
                return result;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("background compile never finished");
}

/// Acceptance criterion 1: `frodo` compiles their own
/// `/builders/frodo/base.wf`; `/secure/x.wf` inherits it and fails to
/// compile. Frodo's uid cannot `valid_read` `/secure/x`, so the
/// diagnostic must come back fully redacted -- no `/secure` path, no
/// identifier from that file's source.
#[test]
fn a_dependent_frodo_cannot_valid_read_is_fully_redacted() {
    on_world_thread(|| {
        let (mut world, mut host, root) = boot("redact-unreadable-dep");
        write_program(&root, "/builders/frodo/base.wf", "var x: int = 1\n");
        write_program(
            &root,
            "/secure/x.wf",
            "inherit /builders/frodo/base\n\npub fn boom() -> int {\n    return 1\n}\n",
        );
        // Load the dependent first, while it still compiles cleanly, so
        // it's a real dependent of `base` (OBI-156: `run_recompile` also
        // picks up never-loaded ancestors, but a *dependent* has to
        // already be registered to be found by
        // `ProgramSnapshot::dependents_of`) -- then break it, so the
        // *recompile* `begin_file_compile` triggers is what fails, not
        // this initial load.
        world.load_object("/secure/x", &mut host).unwrap();
        write_program(
            &root,
            "/secure/x.wf",
            "inherit /builders/frodo/base\n\npub fn boom() -> int {\n    return frodos_super_secret_token_value\n}\n",
        );

        let token = world
            .begin_file_compile("frodo", "/builders/frodo/base", &mut host)
            .expect("frodo may compile their own workroom");
        let err = await_compile(&mut world, &mut host, token).expect_err("x.wf fails to compile");

        assert_eq!(err, "<redacted>: compile failed", "got: {err}");
        assert!(!err.contains("secure"), "got: {err}");
        assert!(
            !err.contains("frodos_super_secret_token_value"),
            "got: {err}"
        );
    });
}

/// Acceptance criterion 2: the same shape, but the failing dependent is
/// readable to frodo (plain `/builders/frodo/**`, not `/secure`) -- its
/// diagnostics must come back in full, path and identifier included,
/// exactly as before this redaction existed.
#[test]
fn a_readable_dependents_diagnostics_are_shown_in_full() {
    on_world_thread(|| {
        let (mut world, mut host, root) = boot("redact-readable-dep");
        write_program(&root, "/builders/frodo/base.wf", "var x: int = 1\n");
        write_program(
            &root,
            "/builders/frodo/dep.wf",
            "inherit /builders/frodo/base\n\npub fn boom() -> int {\n    return 1\n}\n",
        );
        world.load_object("/builders/frodo/dep", &mut host).unwrap();
        write_program(
            &root,
            "/builders/frodo/dep.wf",
            "inherit /builders/frodo/base\n\npub fn boom() -> int {\n    return totally_public_undefined_name\n}\n",
        );

        let token = world
            .begin_file_compile("frodo", "/builders/frodo/base", &mut host)
            .expect("frodo may compile their own workroom");
        let err = await_compile(&mut world, &mut host, token).expect_err("dep.wf fails to compile");

        assert!(err.contains("/builders/frodo/dep"), "got: {err}");
        assert!(err.contains("totally_public_undefined_name"), "got: {err}");
    });
}
