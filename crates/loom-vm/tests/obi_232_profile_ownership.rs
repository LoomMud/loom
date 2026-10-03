// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `profile_start`/`profile_stop` window ownership + auto-expiry (OBI-232,
//! CTO review follow-up from PR #67/OBI-170's should-fix items 4 and 5):
//!
//! 4. One P1 caller must not be able to silently discard another's
//!    in-progress `profile` window: `profile_start` fails if a window is
//!    already open under a *different* principal, and `profile_stop`
//!    refuses to close a window it doesn't own unless the caller passes
//!    `force: true` *and* holds P3 (the master's `valid_efun` grants it).
//! 5. Auto-expiry: a forgotten window stops recording once it hits a cap
//!    (`loom_vm::profiler`'s `MAX_WINDOW`/`MAX_CALLS`), and says so in the
//!    rendered report header. Exercised directly against `Profiler` in
//!    `loom_vm::profiler`'s own unit tests (the caps are minutes/a
//!    million calls -- too large to hit from an integration test in any
//!    reasonable time); this file only covers ownership end to end
//!    through the real efun/master-apply path.

mod common;

use common::{FakeHost, scratch};
use loom_vm::World;

/// `arch` holds P3 (can force-close anyone's window); `appr` only has
/// P1/P2, same shape as `tests/security.rs`'s table-driven policy.
const MASTER: &str = r#"
fn valid_efun(name: string, class: int, ob: object) -> bool {
    if class >= 3 {
        return effective_principal() == "arch"
    }
    return true
}

fn valid_read(path: string, ob: object, op: string) -> bool {
    return true
}

fn valid_write(path: string, ob: object, op: string) -> bool {
    return true
}
"#;

const ARCH: &str = r#"
pub fn open(p: string) {
    profile_start(p)
}

pub fn close() -> string {
    return profile_stop()
}

pub fn close_force() -> string {
    return profile_stop(true)
}
"#;

const APPR: &str = r#"
pub fn open(p: string) {
    profile_start(p)
}

pub fn close() -> string {
    return profile_stop()
}

pub fn close_force() -> string {
    return profile_stop(true)
}
"#;

struct Mud {
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
        ] {
            let p = root.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, src).unwrap();
        }
        let world = World::boot(&root).expect("boot");
        Mud {
            world,
            host: FakeHost::default(),
        }
    }

    fn ob(&mut self, path: &str) -> loom_vm::ObjectId {
        self.world.load_object(path, &mut self.host).expect("load")
    }

    fn call(
        &mut self,
        path: &str,
        f: &str,
        args: &[loom_vm::Value],
    ) -> Result<loom_vm::Value, String> {
        let o = self.ob(path);
        self.world.call(o, f, args.to_vec(), &mut self.host)
    }
}

const ARCH_OB: &str = "/builders/arch/daemon";
const APPR_OB: &str = "/builders/appr/obj";

#[test]
fn profile_start_replaces_its_own_window_but_not_anothers() {
    let mut m = Mud::new("profown-replace");
    m.call(APPR_OB, "open", &[loom_vm::Value::str(ARCH_OB)])
        .unwrap();
    // appr re-targeting is fine: same owner.
    m.call(APPR_OB, "open", &[loom_vm::Value::str(APPR_OB)])
        .unwrap();
    // arch trying to open while appr's window is still open is not: it
    // is a *different* principal, so `profile_start` must not silently
    // discard appr's in-progress window (should-fix 4).
    let e = m
        .call(ARCH_OB, "open", &[loom_vm::Value::str(ARCH_OB)])
        .unwrap_err();
    assert!(e.contains("already open"), "{e}");
    assert!(e.contains("appr"), "{e}");
}

#[test]
fn profile_stop_refuses_to_close_someone_elses_window() {
    let mut m = Mud::new("profown-stop-denied");
    m.call(APPR_OB, "open", &[loom_vm::Value::str(APPR_OB)])
        .unwrap();
    let e = m.call(ARCH_OB, "close", &[]).unwrap_err();
    assert!(e.contains("owned by"), "{e}");
    assert!(e.contains("appr"), "{e}");
    // The window is still open: appr can still close its own.
    let text = m.call(APPR_OB, "close", &[]).unwrap();
    assert!(text.as_str().unwrap().starts_with("profile "));
}

#[test]
fn a_p3_caller_can_force_close_someone_elses_window() {
    let mut m = Mud::new("profown-force-ok");
    m.call(APPR_OB, "open", &[loom_vm::Value::str(APPR_OB)])
        .unwrap();
    // arch holds P3 (master's valid_efun grants class >= 3 only to
    // "arch"), so force-closing appr's window is allowed.
    let text = m.call(ARCH_OB, "close_force", &[]).unwrap();
    let text = text.as_str().unwrap();
    assert!(text.starts_with("profile "));
    assert!(text.contains("opened by appr"));
    // The window is gone: a second close (even forced) reports nothing
    // open rather than erroring on a missing owner.
    let text2 = m.call(ARCH_OB, "close_force", &[]).unwrap();
    assert!(
        text2
            .as_str()
            .unwrap()
            .contains("no sampling window is open")
    );
}

#[test]
fn force_without_p3_is_still_denied() {
    let mut m = Mud::new("profown-force-denied");
    m.call(ARCH_OB, "open", &[loom_vm::Value::str(ARCH_OB)])
        .unwrap();
    // appr has no P3, so `force: true` does not help it close arch's
    // window -- the master's `valid_efun` denies the P3 check before
    // ownership is even reconsidered.
    let e = m.call(APPR_OB, "close_force", &[]).unwrap_err();
    assert!(e.contains("permission denied"), "{e}");
}
