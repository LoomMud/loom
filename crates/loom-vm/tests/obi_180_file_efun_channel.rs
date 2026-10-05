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

// ---------------------------------------------------------------------
// World::call_file_write_if_match (OBI-180 M-FS-6, CTO review must-fix 1
// & 2): the atomic compare-and-swap PUT's HTTP layer sends instead of a
// separate read-then-write pair, so the lost-update window can't open.
// ---------------------------------------------------------------------

use loom_vm::world::{FileCasOutcome, FileMatchPrecondition};

/// `sha256(contents)`, hex-encoded -- mirrors `loom_http::files::etag_for`
/// (minus the quoting) so these tests can build a correct `If-Match`
/// without depending on loom-http.
fn hex_sha256(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(s.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn create_succeeds_when_if_none_match_star_and_the_file_is_absent() {
    let (mut world, mut host, root) = boot("cas-create-ok");
    let outcome = world
        .call_file_write_if_match(
            "glorfindel",
            "/builders/glorfindel/new.wf",
            FileMatchPrecondition::IfNoneMatchStar,
            "int x;",
            &mut host,
        )
        .expect("create should be allowed");
    assert_eq!(outcome, FileCasOutcome::Written);
    assert_eq!(
        std::fs::read_to_string(root.join("builders/glorfindel/new.wf")).unwrap(),
        "int x;"
    );
}

#[test]
fn create_is_precondition_failed_when_if_none_match_star_and_the_file_exists() {
    let (mut world, mut host, root) = boot("cas-create-exists");
    world
        .call_file_efun(
            "glorfindel",
            "write_file",
            vec![
                Value::str("/builders/glorfindel/a.wf"),
                Value::str("original"),
            ],
            &mut host,
        )
        .unwrap();
    let outcome = world
        .call_file_write_if_match(
            "glorfindel",
            "/builders/glorfindel/a.wf",
            FileMatchPrecondition::IfNoneMatchStar,
            "clobber",
            &mut host,
        )
        .expect("the call itself is authorized, just refused by the precondition");
    assert_eq!(outcome, FileCasOutcome::PreconditionFailed);
    // The file must be untouched -- a failed precondition must never
    // write anyway.
    assert_eq!(
        std::fs::read_to_string(root.join("builders/glorfindel/a.wf")).unwrap(),
        "original"
    );
}

#[test]
fn update_succeeds_when_if_match_matches_the_current_etag() {
    let (mut world, mut host, root) = boot("cas-update-ok");
    world
        .call_file_efun(
            "glorfindel",
            "write_file",
            vec![Value::str("/builders/glorfindel/a.wf"), Value::str("v1")],
            &mut host,
        )
        .unwrap();
    let etag = hex_sha256("v1");
    let outcome = world
        .call_file_write_if_match(
            "glorfindel",
            "/builders/glorfindel/a.wf",
            FileMatchPrecondition::IfMatch(etag),
            "v2",
            &mut host,
        )
        .expect("update should be allowed");
    assert_eq!(outcome, FileCasOutcome::Written);
    assert_eq!(
        std::fs::read_to_string(root.join("builders/glorfindel/a.wf")).unwrap(),
        "v2"
    );
}

#[test]
fn update_is_precondition_failed_when_if_match_is_stale() {
    let (mut world, mut host, root) = boot("cas-update-stale");
    world
        .call_file_efun(
            "glorfindel",
            "write_file",
            vec![Value::str("/builders/glorfindel/a.wf"), Value::str("v1")],
            &mut host,
        )
        .unwrap();
    // Someone else's concurrent write landed first -- our `If-Match`
    // (computed against the original "v1") is now stale.
    world
        .call_file_efun(
            "glorfindel",
            "write_file",
            vec![
                Value::str("/builders/glorfindel/a.wf"),
                Value::str("v1-raced"),
            ],
            &mut host,
        )
        .unwrap();
    let stale_etag = hex_sha256("v1");
    let outcome = world
        .call_file_write_if_match(
            "glorfindel",
            "/builders/glorfindel/a.wf",
            FileMatchPrecondition::IfMatch(stale_etag),
            "v2",
            &mut host,
        )
        .expect("the call itself is authorized, just refused by the precondition");
    assert_eq!(outcome, FileCasOutcome::PreconditionFailed);
    assert_eq!(
        std::fs::read_to_string(root.join("builders/glorfindel/a.wf")).unwrap(),
        "v1-raced",
        "a failed precondition must never overwrite the raced write"
    );
}

#[test]
fn update_is_precondition_failed_when_if_match_given_but_the_file_is_absent() {
    let (mut world, mut host, _root) = boot("cas-update-absent");
    let outcome = world
        .call_file_write_if_match(
            "glorfindel",
            "/builders/glorfindel/never-existed.wf",
            FileMatchPrecondition::IfMatch(hex_sha256("anything")),
            "v1",
            &mut host,
        )
        .expect("the call itself is authorized, just refused by the precondition");
    assert_eq!(outcome, FileCasOutcome::PreconditionFailed);
}

/// CTO review must-fix 2: a refused read must propagate as `Err`, never
/// silently fall through to an unconditional write.
#[test]
fn a_refused_read_is_an_error_not_a_fallthrough_write() {
    let (mut world, mut host, root) = boot("cas-refused-read-no-fallthrough");
    let err = world
        .call_file_write_if_match(
            "glorfindel",
            "/secure/master.wf",
            FileMatchPrecondition::IfNoneMatchStar,
            "pwned",
            &mut host,
        )
        .unwrap_err();
    assert!(err.contains("permission denied"), "{err}");
    // Must never have written -- there is no "write anyway" path here.
    assert_ne!(
        std::fs::read_to_string(root.join("secure/master.wf")).unwrap(),
        "pwned"
    );
}

#[test]
fn cas_reserved_principals_are_refused_outright() {
    let (mut world, mut host, _root) = boot("cas-reserved");
    for reserved in ["root", "mudlib", "staff:ops"] {
        let err = world
            .call_file_write_if_match(
                reserved,
                "/builders/arch/x.wf",
                FileMatchPrecondition::IfNoneMatchStar,
                "x",
                &mut host,
            )
            .unwrap_err();
        assert!(err.contains("reserved principal"), "{reserved}: {err}");
    }
}

#[test]
fn cas_write_is_audited_like_any_other_valid_write_decision() {
    let (mut world, mut host, _root) = boot("cas-audit");
    world
        .call_file_write_if_match(
            "glorfindel",
            "/builders/glorfindel/a.wf",
            FileMatchPrecondition::IfNoneMatchStar,
            "x",
            &mut host,
        )
        .unwrap();
    let last = world.audit_log().last().unwrap().clone();
    assert!(last.allowed);
    assert_eq!(last.apply, "valid_write");
}

/// Non-blocking review item 1: `call_file_efun`'s `efun` argument is
/// restricted to the file-op allowlist, not a general driver-side efun
/// runner.
#[test]
fn call_file_efun_refuses_an_efun_outside_the_allowlist() {
    let (mut world, mut host, _root) = boot("efun-allowlist");
    let err = world
        .call_file_efun("glorfindel", "seteuid", vec![Value::str("root")], &mut host)
        .unwrap_err();
    assert!(err.contains("not a file-op efun"), "{err}");
}
