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

// ---------------------------------------------------------------------
// World::list_dir (OBI-180 M-FS-3): a directory listing filtered by
// valid_read, the same master policy as every other file op above.
// ---------------------------------------------------------------------

#[test]
fn list_dir_returns_entries_in_own_workroom() {
    let (mut world, mut host, _root) = boot("list-dir-own");
    world
        .call_file_efun(
            "glorfindel",
            "write_file",
            vec![Value::str("/builders/glorfindel/a.wf"), Value::str("a")],
            &mut host,
        )
        .unwrap();
    world
        .call_file_efun(
            "glorfindel",
            "write_file",
            vec![Value::str("/builders/glorfindel/b.wf"), Value::str("b")],
            &mut host,
        )
        .unwrap();
    let entries = world
        .list_dir("glorfindel", "/builders/glorfindel", &mut host)
        .expect("own workroom listing should be allowed")
        .expect("the directory exists");
    assert_eq!(entries.names, vec!["a.wf".to_string(), "b.wf".to_string()]);
    assert!(!entries.truncated);
}

#[test]
fn list_dir_in_another_builders_workroom_is_none() {
    let (mut world, mut host, _root) = boot("list-dir-elsewhere");
    world
        .call_file_efun(
            "arch",
            "write_file",
            vec![Value::str("/builders/frodo/secret.wf"), Value::str("ring")],
            &mut host,
        )
        .unwrap();
    let entries = world
        .list_dir("glorfindel", "/builders/frodo", &mut host)
        .expect("the call itself is authorized, just refused by valid_read");
    assert_eq!(
        entries, None,
        "a refused listing looks exactly like a missing directory (M-FS-3)"
    );
}

#[test]
fn list_dir_on_a_missing_directory_is_none() {
    let (mut world, mut host, _root) = boot("list-dir-missing");
    let entries = world
        .list_dir(
            "glorfindel",
            "/builders/glorfindel/never-created",
            &mut host,
        )
        .expect("the call itself is authorized");
    assert_eq!(entries, None);
}

#[test]
fn list_dir_secure_is_none_for_a_non_root_uid() {
    let (mut world, mut host, _root) = boot("list-dir-secure");
    let entries = world
        .list_dir("glorfindel", "/secure", &mut host)
        .expect("the call itself is authorized, just refused by valid_read");
    assert_eq!(entries, None);
}

/// Per-entry filtering (M-FS-3): a listing can authorize for its own
/// directory yet still hide individual entries the master's `valid_read`
/// refuses for that specific child path. The test master policy doesn't
/// have a case that applies here (own-workroom entries are always
/// readable by their owner, elsewhere is refused wholesale by the
/// directory-level check above), so this proves the *shape* with `arch`
/// (who can read everywhere per the test policy) listing a directory
/// that mixes `arch`'s own files with another builder's, confirming
/// both show up when the master says yes to both.
#[test]
fn list_dir_shows_every_entry_the_master_allows() {
    let (mut world, mut host, _root) = boot("list-dir-arch");
    world
        .call_file_efun(
            "arch",
            "write_file",
            vec![Value::str("/builders/frodo/a.wf"), Value::str("a")],
            &mut host,
        )
        .unwrap();
    world
        .call_file_efun(
            "arch",
            "write_file",
            vec![Value::str("/builders/frodo/b.wf"), Value::str("b")],
            &mut host,
        )
        .unwrap();
    let entries = world
        .list_dir("arch", "/builders/frodo", &mut host)
        .unwrap()
        .expect("arch may read anywhere per the test master policy");
    assert_eq!(entries.names, vec!["a.wf".to_string(), "b.wf".to_string()]);
}

#[test]
fn list_dir_reserved_principals_are_refused_outright() {
    let (mut world, mut host, _root) = boot("list-dir-reserved");
    for reserved in ["root", "mudlib", "staff:ops"] {
        let err = world
            .list_dir(reserved, "/builders/arch", &mut host)
            .unwrap_err();
        match err {
            loom_vm::world::ListDirError::Refused(msg) => {
                assert!(msg.contains("reserved principal"), "{reserved}: {msg}");
            }
            other => panic!("{reserved}: expected Refused, got {other:?}"),
        }
    }
}

/// CTO review on PR #117, must-fix 2: a `valid_read` that throws on one
/// entry must fail the *whole* listing, never silently drop just that
/// entry and return a shorter-but-successful-looking list.
#[test]
fn list_dir_errors_instead_of_silently_dropping_an_entry_whose_valid_read_throws() {
    const THROWING_MASTER: &str = r#"
fn valid_efun(name: string, class: int, ob: object) -> bool {
    return true
}

fn valid_read(path: string, ob: object, op: string) -> bool {
    if path == "/builders/glorfindel/bad.wf" {
        random(0)
    }
    return true
}

fn valid_write(path: string, ob: object, op: string) -> bool {
    return true
}
"#;
    let root = scratch("list-dir-throwing-entry");
    let p = root.join("secure/master.wf");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, THROWING_MASTER).unwrap();
    let mut world = World::boot(&root).expect("boot");
    let mut host = FakeHost::default();

    world
        .call_file_efun(
            "glorfindel",
            "write_file",
            vec![
                Value::str("/builders/glorfindel/good.wf"),
                Value::str("fine"),
            ],
            &mut host,
        )
        .unwrap();
    world
        .call_file_efun(
            "glorfindel",
            "write_file",
            vec![
                Value::str("/builders/glorfindel/bad.wf"),
                Value::str("boom"),
            ],
            &mut host,
        )
        .unwrap();

    let err = world
        .list_dir("glorfindel", "/builders/glorfindel", &mut host)
        .expect_err(
            "a valid_read that throws on one entry must fail the whole listing, \
             never silently return the other entries alone",
        );
    assert!(
        matches!(err, loom_vm::world::ListDirError::Internal(_)),
        "{err:?}"
    );
}

/// CTO review on PR #117, should-fix 1: a directory with more than
/// `MAX_LIST_ENTRIES` entries is truncated, not left to exhaust the
/// exec's tick budget evaluating every one of them.
#[test]
fn list_dir_truncates_past_the_cap() {
    let (mut world, mut host, _root) = boot("list-dir-truncate");
    let over_the_cap = loom_vm::world::MAX_LIST_ENTRIES + 10;
    for i in 0..over_the_cap {
        world
            .call_file_efun(
                "glorfindel",
                "write_file",
                vec![
                    Value::str(&format!("/builders/glorfindel/f{i:05}.wf")),
                    Value::str("x"),
                ],
                &mut host,
            )
            .unwrap();
    }
    let result = world
        .list_dir("glorfindel", "/builders/glorfindel", &mut host)
        .unwrap()
        .expect("own workroom listing should be allowed");
    assert_eq!(result.names.len(), loom_vm::world::MAX_LIST_ENTRIES);
    assert!(result.truncated);
}

/// CTO review on PR #117, should-fix 2: dotfiles (e.g. a live mudlib
/// checkout's own `.git`, OBI-190) never show up in a listing, even for
/// a uid whose `valid_read` would allow everything.
#[test]
fn list_dir_hides_dotfiles() {
    let (mut world, mut host, root) = boot("list-dir-dotfiles");
    world
        .call_file_efun(
            "glorfindel",
            "write_file",
            vec![
                Value::str("/builders/glorfindel/visible.wf"),
                Value::str("v"),
            ],
            &mut host,
        )
        .unwrap();
    std::fs::create_dir_all(root.join("builders/glorfindel/.git")).unwrap();
    let result = world
        .list_dir("glorfindel", "/builders/glorfindel", &mut host)
        .unwrap()
        .expect("own workroom listing should be allowed");
    assert_eq!(result.names, vec!["visible.wf".to_string()]);
}
