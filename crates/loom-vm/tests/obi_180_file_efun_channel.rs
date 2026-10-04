// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `World::call_file_efun` (OBI-180 M-FS-1): a driver-initiated
//! `read_file`/`write_file` call, entered with a guard set of exactly
//! `{uid}` and no live object call frame, must go through the *same*
//! `security::normalize_file_path` -> `authorize()`/master `valid_*` ->
//! `fileio` pipeline an LPC-originated call gets -- this is the seam
//! `/api/v1/files/*` and the `/lsp` route's `ReadAuthorizer` are built on.

mod common;

use common::{FakeHost, scratch};
use loom_vm::{Value, World};

/// A small master policy with simple domain ownership (own
/// `/builders/<uid>/**` read/write OK, elsewhere refused, `/secure/**`
/// refused for everyone but root) -- enough to prove the channel applies
/// real master policy, not a hardcoded Rust ACL (spec D-TM5).
const MASTER: &str = r#"
fn valid_efun(name: string, class: int, ob: object) -> bool {
    return true
}

fn valid_read(path: string, ob: object, op: string) -> bool {
    let who = effective_principal()
    let parts = split(path, "/")
    if len(parts) < 2 or parts[1] == "secure" {
        return false
    }
    if who == "arch" {
        return true
    }
    return len(parts) >= 3 and parts[1] == "builders" and parts[2] == who
}

fn valid_write(path: string, ob: object, op: string) -> bool {
    return valid_read(path, ob, op)
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

#[test]
fn own_workroom_read_and_write_are_allowed() {
    let (mut world, mut host, root) = boot("fileop-own");
    let v = world
        .call_file_efun(
            "glorfindel",
            "write_file",
            vec![
                Value::str("/builders/glorfindel/notes.wf"),
                Value::str("hello"),
            ],
            &mut host,
        )
        .expect("write should be allowed in the caller's own workroom");
    assert!(matches!(v, Value::Bool(true)));
    assert!(root.join("builders/glorfindel/notes.wf").exists());

    let v = world
        .call_file_efun(
            "glorfindel",
            "read_file",
            vec![Value::str("/builders/glorfindel/notes.wf")],
            &mut host,
        )
        .expect("read should be allowed in the caller's own workroom");
    assert_eq!(v.as_str(), Some("hello"));
}

#[test]
fn another_builders_workroom_is_refused() {
    let (mut world, mut host, root) = boot("fileop-elsewhere");
    // Seed a file as `arch` (who may write anywhere per the test policy),
    // then confirm a different uid can't read or write it.
    world
        .call_file_efun(
            "arch",
            "write_file",
            vec![Value::str("/builders/frodo/secret.wf"), Value::str("ring")],
            &mut host,
        )
        .expect("arch may write anywhere");
    assert!(root.join("builders/frodo/secret.wf").exists());

    let err = world
        .call_file_efun(
            "glorfindel",
            "read_file",
            vec![Value::str("/builders/frodo/secret.wf")],
            &mut host,
        )
        .unwrap_err();
    assert!(err.contains("permission denied"), "{err}");

    let err = world
        .call_file_efun(
            "glorfindel",
            "write_file",
            vec![Value::str("/builders/frodo/pwned.wf"), Value::str("x")],
            &mut host,
        )
        .unwrap_err();
    assert!(err.contains("permission denied"), "{err}");
    assert!(!root.join("builders/frodo/pwned.wf").exists());
}

#[test]
fn secure_is_refused_for_a_non_root_uid() {
    let (mut world, mut host, _root) = boot("fileop-secure");
    let err = world
        .call_file_efun(
            "glorfindel",
            "read_file",
            vec![Value::str("/secure/master.wf")],
            &mut host,
        )
        .unwrap_err();
    assert!(err.contains("permission denied"), "{err}");
}

#[test]
fn reserved_principals_are_refused_outright_before_any_apply_runs() {
    let (mut world, mut host, _root) = boot("fileop-reserved");
    for reserved in ["root", "mudlib", "staff:ops"] {
        let err = world
            .call_file_efun(
                reserved,
                "read_file",
                vec![Value::str("/builders/arch/x.wf")],
                &mut host,
            )
            .unwrap_err();
        assert!(err.contains("reserved principal"), "{reserved}: {err}");
    }
}

#[test]
fn the_channel_is_audited_like_any_other_valid_write_decision() {
    let (mut world, mut host, _root) = boot("fileop-audit");
    world
        .call_file_efun(
            "glorfindel",
            "write_file",
            vec![Value::str("/builders/glorfindel/a.wf"), Value::str("x")],
            &mut host,
        )
        .unwrap();
    let last = world.audit_log().last().unwrap().clone();
    assert!(last.allowed);
    assert_eq!(last.apply, "valid_write");
    let guard: Vec<&str> = last
        .guard
        .euids()
        .map(|s| world.principal_name(s))
        .collect();
    assert_eq!(guard, vec!["glorfindel"], "guard set is exactly {{uid}}");
}
