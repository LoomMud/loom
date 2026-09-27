// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Function values on the S1 guard model (OBI-35 D-S1.6/D-S1.7, OBI-87):
//! the creator frame, and the `call_out` scheduler carrying a captured
//! guard/quota_uid. Mirrors `tests/security.rs`'s table-driven
//! `valid_write` keyed on `effective_principal()`.

mod common;

use common::{FakeHost, scratch};
use loom_vm::{Value, World};

/// Same shape as `tests/security.rs`'s policy, plus:
/// - a `vault` subfolder of `appr`'s own workroom that `arch`'s broad grant
///   does *not* reach (AC 4's differentiator: a captured multi-principal
///   guard must still deny there even though `arch` alone could write
///   almost anywhere non-secure);
/// - `valid_seteuid` also lets `esc` promote itself to `arch` once (AC 5's
///   escalation), without loosening the existing arch-only rule.
const MASTER: &str = r#"
fn valid_efun(name: string, class: int, ob: object) -> bool {
    return true
}

fn valid_read(path: string, ob: object, op: string) -> bool {
    return true
}

fn valid_write(path: string, ob: object, op: string) -> bool {
    let who = effective_principal()
    let parts = split(path, "/")
    if len(parts) < 3 or parts[1] == "secure" {
        return false
    }
    if parts[1] == "builders" and parts[2] == "appr" and len(parts) >= 4 and parts[3] == "vault" {
        return who == "appr"
    }
    if who == "arch" {
        return true
    }
    return parts[1] == "builders" and parts[2] == who
}

fn valid_seteuid(ob: object, euid: string) -> bool {
    let who = effective_principal()
    return who == "arch" or (who == "esc" and euid == "arch")
}
"#;

/// A T4-tier daemon: broad write rights everywhere non-secure.
const ARCH: &str = r#"
var stored: any = null

fn create() {
    set_heartbeat(true)
}

pub fn make_writer(p: string) -> fn() -> int {
    return fn() -> int {
        write_file(p, "arch-closure")
        return 0
    }
}

pub fn invoke(g: fn() -> int) -> int {
    return g()
}

pub fn store(f: fn() -> int) {
    stored = f
}

// Invokes whatever closure another object handed it via `store()`, then
// clears the slot (spec r5 AC 2: an apprentice's closure invoked from a
// T4 daemon's heartbeat runs with apprentice rights).
pub fn heartbeat() {
    if stored != null {
        let f = stored
        stored = null
        f()
    }
}
"#;

/// A tier-1 apprentice: may only write inside its own workroom.
const APPR: &str = r#"
var target_path: string = ""

pub fn make_writer(p: string) -> fn() -> int {
    return fn() -> int {
        write_file(p, "appr-closure")
        return 0
    }
}

pub fn invoke(g: fn() -> int) -> int {
    return g()
}

// A closure whose body schedules a `call_out` when invoked: capturing the
// guard *at invocation time*, not at `make_deferred_writer()`'s own call
// (spec r5 AC 4's stand-in for `db_query`).
pub fn make_deferred_writer() -> fn() -> int {
    return fn() -> int {
        call_out("finish_deferred", 1)
        return 0
    }
}

pub fn set_target(p: string) {
    target_path = p
}

fn finish_deferred() {
    write_file(target_path, "deferred")
}

pub fn schedule_own_write(p: string) {
    target_path = p
    call_out("finish_own", 1)
}

fn finish_own() {
    write_file(target_path, "own-call-out")
}
"#;

/// A one-off identity used only for AC 5 (created-before-`seteuid`): starts
/// as its own restricted tier, then escalates to `arch`.
const ESC: &str = r#"
pub fn make_writer(p: string) -> fn() -> int {
    return fn() -> int {
        write_file(p, "esc-closure")
        return 0
    }
}

pub fn escalate() {
    seteuid("arch")
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
            ("builders/arch/daemon.wf", ARCH),
            ("builders/appr/obj.wf", APPR),
            ("builders/esc/obj.wf", ESC),
        ] {
            let p = root.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, src).unwrap();
        }
        let world = World::boot_with_limits(
            &root,
            loom_vm::Limits {
                // Pin the pre-OBI-82 one-tick-is-one-heartbeat cadence:
                // these tests assert a heartbeat runs on the very next
                // `World::tick()` call.
                heartbeat_interval_ticks: 1,
                ..loom_vm::Limits::default()
            },
        )
        .expect("boot");
        std::fs::create_dir_all(root.join("builders/appr/vault")).unwrap();
        Mud {
            root,
            world,
            host: FakeHost::default(),
        }
    }

    fn ob(&mut self, path: &str) -> loom_vm::ObjectId {
        self.world.load_object(path, &mut self.host).expect("load")
    }

    /// Call with string args (convenience for the common case).
    fn call(&mut self, path: &str, f: &str, args: &[&str]) -> Result<Value, String> {
        let o = self.ob(path);
        let args = args.iter().map(|a| Value::str(a)).collect();
        self.world.call(o, f, args, &mut self.host)
    }

    /// Call with raw `Value` args (needed to pass a function value around).
    fn call_v(&mut self, path: &str, f: &str, args: Vec<Value>) -> Result<Value, String> {
        let o = self.ob(path);
        self.world.call(o, f, args, &mut self.host)
    }

    fn exists(&self, p: &str) -> bool {
        self.root.join(p.trim_start_matches('/')).exists()
    }

    fn tick(&mut self) {
        self.world.tick(&mut self.host);
    }
}

const ARCH_OB: &str = "/builders/arch/daemon";
const APPR_OB: &str = "/builders/appr/obj";
const ESC_OB: &str = "/builders/esc/obj";

/// **AC 1:** a T4 daemon's closure that calls `write_file`, handed to an
/// apprentice's object and invoked there, is denied.
#[test]
fn ac1_a_t4_closure_invoked_by_an_apprentice_is_denied() {
    let mut m = Mud::new("fnval-ac1");
    let target = "/builders/arch/from-appr.txt";
    let f = m.call(ARCH_OB, "make_writer", &[target]).unwrap();

    // Control: arch invoking its own closure directly (guard = {arch}
    // alone) succeeds.
    m.call_v(ARCH_OB, "invoke", vec![f.clone()]).unwrap();
    assert!(m.exists(target));
    std::fs::remove_file(m.root.join(target.trim_start_matches('/'))).unwrap();

    // The AC: appr invokes the *same* closure. The creator frame unions in
    // arch's captured guard, but appr's own frame still contributes its
    // euid, so the guard set is {appr, arch} and `valid_write` denies for
    // `appr`.
    let e = m.call_v(APPR_OB, "invoke", vec![f]).unwrap_err();
    assert!(e.contains("permission denied"), "{e}");
    assert!(!m.exists(target));
}

/// **AC 2:** an apprentice's closure invoked from a T4 daemon's heartbeat
/// runs with apprentice rights (denied where the apprentice is denied,
/// allowed where the apprentice's own workroom allows).
#[test]
fn ac2_an_apprentice_closure_run_from_a_t4_heartbeat_gets_apprentice_rights() {
    let mut m = Mud::new("fnval-ac2");

    // Denied: a path only arch could write to.
    let denied_target = "/builders/arch/from-heartbeat.txt";
    let f = m.call(APPR_OB, "make_writer", &[denied_target]).unwrap();
    m.call_v(ARCH_OB, "store", vec![f]).unwrap();
    m.tick();
    assert!(
        !m.exists(denied_target),
        "apprentice rights must still deny a path outside its workroom, \
         even when the closure runs from arch's heartbeat"
    );

    // Allowed: a path inside the apprentice's own workroom -- arch's
    // heartbeat running the closure does not add arch's broader rights,
    // but it does not take away the apprentice's own either.
    let allowed_target = "/builders/appr/from-heartbeat.txt";
    let f2 = m.call(APPR_OB, "make_writer", &[allowed_target]).unwrap();
    m.call_v(ARCH_OB, "store", vec![f2]).unwrap();
    m.tick();
    assert!(m.exists(allowed_target));
}

/// **AC 3:** an apprentice's `call_out` runs with apprentice rights, and
/// its execution reports quota uid = the apprentice's.
#[test]
fn ac3_an_apprentice_call_out_runs_with_apprentice_rights_and_quota() {
    let mut m = Mud::new("fnval-ac3");
    let ok_target = "/builders/appr/own-cout.txt";
    m.call(APPR_OB, "schedule_own_write", &[ok_target]).unwrap();
    m.tick();
    assert!(m.exists(ok_target));
    assert_eq!(m.world.last_call_out_quota_uid(), Some("appr"));

    let denied_target = "/builders/arch/denied-cout.txt";
    m.call(APPR_OB, "schedule_own_write", &[denied_target])
        .unwrap();
    m.tick();
    assert!(!m.exists(denied_target));
    assert_eq!(m.world.last_call_out_quota_uid(), Some("appr"));
}

/// **AC 4 (stand-in for `db_query`, per the OBI-35 work split):** a
/// scheduled function value runs with exactly its captured guard, not a
/// guard re-derived from whichever object happens to own the call_out.
/// `appr`'s closure is invoked from `arch` (so its body runs with the
/// widened guard `{arch, appr}`) and, *while still inside that widened
/// guard*, schedules a `call_out`; the guard captured for that call_out is
/// therefore `{arch, appr}`, not just `[appr.euid]` (contrast
/// `ac3`, a plain `call_out` from `appr` alone, whose guard is exactly
/// `{appr}`) -- so a write to `appr`'s own `vault/` (which excludes
/// `arch`) is still denied here, even though the same path succeeds when
/// `appr` schedules it directly.
#[test]
fn ac4_a_scheduled_function_value_runs_with_exactly_its_captured_guard() {
    let mut m = Mud::new("fnval-ac4");
    let vault_target = "/builders/appr/vault/deferred.txt";

    // Control: appr alone schedules a write to its own vault -- guard is
    // exactly {appr}, which the vault rule allows.
    m.call(APPR_OB, "schedule_own_write", &[vault_target])
        .unwrap();
    m.tick();
    assert!(
        m.exists(vault_target),
        "appr alone must be able to write its own vault"
    );
    std::fs::remove_file(m.root.join(vault_target.trim_start_matches('/'))).unwrap();

    // The AC: appr's closure is invoked from arch, and *while running*
    // (guard {arch, appr}) it schedules the deferred vault write. The
    // vault rule denies for euid "arch", so the captured guard must still
    // deny this, even though `ob` for the call_out is `appr`.
    m.call(APPR_OB, "set_target", &[vault_target]).unwrap();
    let f = m.call(APPR_OB, "make_deferred_writer", &[]).unwrap();
    m.call_v(ARCH_OB, "invoke", vec![f]).unwrap();
    m.tick();
    assert!(
        !m.exists(vault_target),
        "the call_out's captured guard must still include arch, denying \
         the vault write even though the call_out's own object is appr"
    );
}

/// **AC 5:** a closure created before its creator's `seteuid` does not
/// gain the new rights.
#[test]
fn ac5_a_closure_created_before_its_creators_seteuid_does_not_gain_the_new_rights() {
    let mut m = Mud::new("fnval-ac5");
    let target = "/builders/arch/after-escalation.txt";

    // Captured while esc's own euid is still "esc".
    let f = m.call(ESC_OB, "make_writer", &[target]).unwrap();
    // esc escalates its own euid to "arch" (the master's one-off grant).
    m.call(ESC_OB, "escalate", &[]).unwrap();

    // Invoking the *already-captured* closure must still carry esc's old
    // "esc" identity in its guard (not "arch", the object's new euid):
    // the guard set ends up {arch (the invoker, arch.invoke's own frame),
    // esc (the closure's captured guard)} -- distinct euids -- and
    // `valid_write` denies for "esc" on this arch-only path, so the write
    // must fail even though esc's live euid is now "arch".
    let e = m.call_v(ARCH_OB, "invoke", vec![f]).unwrap_err();
    assert!(e.contains("permission denied"), "{e}");
    assert!(!m.exists(target));
}
