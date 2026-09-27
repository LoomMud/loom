// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Stack-based privilege check + master `valid_*` applies (OBI-35, design
//! note D-S1.1–D-S1.8): a lower-privileged frame anywhere on the stack
//! denies, root/master paths are allowed without asking the master,
//! `seteuid` is monotone within a frame, `unguarded` is /secure-only, and
//! decisions are cached per policy epoch.

mod common;

use common::{FakeHost, scratch};
use loom_vm::{Value, World};

/// Table-driven test policy: `arch` (think T4) may write anywhere except
/// /secure; everyone else only in its own `/builders/<uid>/` workroom.
/// `appr` (think T1) has only efun classes P0/P1.
const MASTER: &str = r#"
var write_checks: int = 0

fn valid_efun(name: string, class: int, ob: object) -> bool {
    if effective_principal() == "appr" {
        return class <= 1
    }
    return true
}

fn valid_read(path: string, ob: object, op: string) -> bool {
    return true
}

fn valid_write(path: string, ob: object, op: string) -> bool {
    write_checks += 1
    let who = effective_principal()
    let parts = split(path, "/")
    if len(parts) < 3 or parts[1] == "secure" {
        return false
    }
    if who == "arch" {
        return true
    }
    return parts[1] == "builders" and parts[2] == who
}

fn valid_seteuid(ob: object, euid: string) -> bool {
    return effective_principal() == "arch"
}

pub fn root_write(p: string) {
    write_file(p, "root")
}
"#;

const ARCH: &str = r#"
pub fn write_it(p: string) {
    write_file(p, "arch")
}

pub fn via(o: object, p: string) {
    o.write_it(p)
}

pub fn drop_and_write(p: string) {
    seteuid("appr")
    write_file(p, "arch")
}

pub fn ids() -> string {
    return $"{getuid()}/{geteuid()}"
}
"#;

const APPR: &str = r#"
pub fn write_it(p: string) {
    write_file(p, "appr")
}

pub fn ask_arch(p: string) {
    load_object("/builders/arch/daemon").write_it(p)
}

pub fn bounce(p: string) {
    load_object("/builders/arch/daemon").via(load_object("/builders/arch/daemon"), p)
}

pub fn raise() {
    seteuid("arch")
}

pub fn promote(p: string) {
    load_object("/secure/roles").promote(p)
}

pub fn cut(p: string) {
    unguarded("write_it", [p])
}

pub fn read_it(p: string) -> string? {
    return read_file(p)
}
"#;

const ROLES: &str = r#"
pub fn promote(p: string) {
    unguarded("do_write", [p])
}

fn do_write(p: string) {
    write_file(p, "roles")
}
"#;

struct Mud {
    root: std::path::PathBuf,
    world: World,
    host: FakeHost,
}

impl Mud {
    fn new(tag: &str) -> Mud {
        let root = scratch(tag);
        for (path, src) in [
            ("secure/master.wf", MASTER),
            ("secure/roles.wf", ROLES),
            ("builders/arch/daemon.wf", ARCH),
            ("builders/appr/obj.wf", APPR),
        ] {
            let p = root.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, src).unwrap();
        }
        let world = World::boot(&root).expect("boot");
        Mud {
            root,
            world,
            host: FakeHost::default(),
        }
    }

    fn ob(&mut self, path: &str) -> loom_vm::ObjectId {
        self.world.load_object(path, &mut self.host).expect("load")
    }

    fn call(&mut self, path: &str, f: &str, args: &[&str]) -> Result<Value, String> {
        let o = self.ob(path);
        let args = args.iter().map(|a| Value::str(a)).collect();
        self.world.call(o, f, args, &mut self.host)
    }

    fn exists(&self, p: &str) -> bool {
        self.root.join(p.trim_start_matches('/')).exists()
    }

    fn write_checks(&self) -> i64 {
        let m = self.world.find_object("/secure/master").unwrap();
        match self.world.var(m, "write_checks") {
            Some(Value::Int(n)) => n,
            v => panic!("write_checks = {v:?}"),
        }
    }
}

const ARCH_OB: &str = "/builders/arch/daemon";
const APPR_OB: &str = "/builders/appr/obj";

#[test]
fn objects_get_uid_from_their_path_and_euid_starts_equal() {
    let mut m = Mud::new("sec-ids");
    let v = m.call(ARCH_OB, "ids", &[]).unwrap();
    assert_eq!(v.as_str(), Some("arch/arch"));
}

#[test]
fn a_frame_may_do_what_its_own_euid_allows() {
    let mut m = Mud::new("sec-own");
    m.call(ARCH_OB, "write_it", &["/builders/appr/by-arch.txt"])
        .unwrap();
    assert!(m.exists("/builders/appr/by-arch.txt"));
    m.call(APPR_OB, "write_it", &["/builders/appr/own.txt"])
        .unwrap();
    assert!(m.exists("/builders/appr/own.txt"));
}

#[test]
fn a_lower_privileged_caller_denies_a_higher_privileged_callee() {
    let mut m = Mud::new("sec-deputy");
    // appr → arch daemon → write_file: appr is on the stack, so arch's
    // right to write outside appr's workroom does not apply.
    let e = m
        .call(APPR_OB, "ask_arch", &["/builders/arch/stolen.txt"])
        .unwrap_err();
    assert!(e.contains("permission denied"), "{e}");
    assert!(e.contains("`appr`"), "{e}");
    assert!(!m.exists("/builders/arch/stolen.txt"));
    let last = m.world.audit_log().last().unwrap().clone();
    assert!(!last.allowed);
    assert_eq!(last.apply, "valid_write");
    assert_eq!(
        last.denied_by.map(|s| m.world.principal_name(s)),
        Some("appr")
    );
    let guard: Vec<&str> = last
        .guard
        .euids()
        .map(|s| m.world.principal_name(s))
        .collect();
    assert_eq!(guard, vec!["appr", "arch"]);
}

#[test]
fn a_lower_privileged_frame_in_the_middle_of_the_stack_still_denies() {
    let mut m = Mud::new("sec-middle");
    // appr → arch.via → arch.write_it: appr is at the bottom, arch twice
    // above it.
    let e = m
        .call(APPR_OB, "bounce", &["/builders/arch/deep.txt"])
        .unwrap_err();
    assert!(e.contains("permission denied"), "{e}");
    assert!(!m.exists("/builders/arch/deep.txt"));
}

#[test]
fn master_and_root_paths_are_allowed_without_calling_an_apply() {
    let mut m = Mud::new("sec-root");
    let before = m.write_checks();
    // The master's own code writes even to /secure (which its own policy
    // would refuse to anyone): an all-root stack has an empty guard set.
    let master = m.world.find_object("/secure/master").unwrap();
    m.world
        .call(
            master,
            "root_write",
            vec![Value::str("/secure/by-root.txt")],
            &mut m.host,
        )
        .unwrap();
    assert!(m.exists("/secure/by-root.txt"));
    assert_eq!(m.write_checks(), before, "no valid_write call for root");
    let last = m.world.audit_log().last().unwrap();
    assert!(last.allowed && last.guard.is_empty());
}

#[test]
fn decisions_are_cached_and_a_master_recompile_invalidates_them() {
    let mut m = Mud::new("sec-cache");
    m.call(APPR_OB, "write_it", &["/builders/appr/a.txt"])
        .unwrap();
    let after_first = m.write_checks();
    m.call(APPR_OB, "write_it", &["/builders/appr/a.txt"])
        .unwrap();
    assert_eq!(m.write_checks(), after_first, "second check is a cache hit");
    assert!(m.world.security().hits > 0);

    let epoch = m.world.security().epoch();
    assert_eq!(
        m.world.compile_object("/secure/master", &mut m.host),
        Ok(vec![])
    );
    assert!(m.world.security().epoch() > epoch);
    m.call(APPR_OB, "write_it", &["/builders/appr/a.txt"])
        .unwrap();
    assert_eq!(
        m.write_checks(),
        after_first + 1,
        "re-asked after the flush"
    );
}

#[test]
fn seteuid_lowering_takes_effect_in_the_same_frame_and_persists() {
    let mut m = Mud::new("sec-seteuid");
    let e = m
        .call(
            ARCH_OB,
            "drop_and_write",
            &["/builders/arch/after-drop.txt"],
        )
        .unwrap_err();
    assert!(e.contains("permission denied"), "{e}");
    assert!(!m.exists("/builders/arch/after-drop.txt"));
    // A later frame runs with the new euid; the uid never changes.
    assert_eq!(
        m.call(ARCH_OB, "ids", &[]).unwrap().as_str(),
        Some("arch/appr")
    );
    assert!(
        m.call(ARCH_OB, "write_it", &["/builders/arch/later.txt"])
            .is_err()
    );
}

#[test]
fn seteuid_cannot_raise_privilege_without_the_master() {
    let mut m = Mud::new("sec-raise");
    let e = m.call(APPR_OB, "raise", &[]).unwrap_err();
    assert!(e.contains("permission denied"), "{e}");
}

#[test]
fn unguarded_cuts_the_stack_only_for_secure_code() {
    let mut m = Mud::new("sec-unguarded");
    // /secure/roles acts for the apprentice as root (the promotion case).
    m.call(APPR_OB, "promote", &["/builders/arch/promoted.txt"])
        .unwrap();
    assert!(m.exists("/builders/arch/promoted.txt"));
    // Anyone else calling unguarded is refused by the driver.
    let e = m
        .call(APPR_OB, "cut", &["/builders/arch/cut.txt"])
        .unwrap_err();
    assert!(e.contains("only code under /secure"), "{e}");
    assert!(!m.exists("/builders/arch/cut.txt"));
}

#[test]
fn file_paths_cannot_escape_the_mudlib() {
    let mut m = Mud::new("sec-escape");
    let e = m.call(APPR_OB, "read_it", &["/../etc/passwd"]).unwrap_err();
    assert!(e.contains("invalid file path"), "{e}");
    let v = m
        .call(APPR_OB, "read_it", &["/builders/appr/missing.txt"])
        .unwrap();
    assert!(matches!(v, Value::Null));
}
