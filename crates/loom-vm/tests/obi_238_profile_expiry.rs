// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Follow-up to PR #67/OBI-232's should-fix 5 (OBI-238, CTO re-review):
//!
//! 1. An expired window must stop costing every call: `Profiler::wants`
//!    answers `false` once a cap is hit, not just `record` dropping the
//!    sample. Covered directly as a unit test in `loom_vm::profiler`
//!    (`expired_window_wants_returns_false`/
//!    `expired_time_window_wants_returns_false_and_caches`) -- this file
//!    only adds the end-to-end angle: a `profile <program>` window still
//!    open on an expired program does not keep paying per-call overhead
//!    from the efun/`World` side either (it simply no longer needs
//!    `profile_stop`/ownership to go away functionally, see test 2).
//! 2. An expired window must not keep its owner lock: `profile_start`
//!    from a *different* principal must succeed once the open window has
//!    expired, with no P3 and no `force`.

mod common;

use common::{FakeHost, scratch};
use loom_vm::World;

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
"#;

const APPR: &str = r#"
pub fn open(p: string) {
    profile_start(p)
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

/// Should-fix 5 follow-up, part 2 (OBI-238): principal B's
/// `profile_start` succeeds once principal A's window has expired, with
/// no P3 and no `force` -- unlike the still-open case
/// (`obi_232_profile_ownership.rs`'s
/// `profile_start_replaces_its_own_window_but_not_anothers`), which still
/// refuses a different owner.
#[test]
fn profile_start_replaces_an_expired_window_from_another_principal() {
    let mut m = Mud::new("profexpiry-replace");
    // arch opens a window.
    m.call(ARCH_OB, "open", &[loom_vm::Value::str(ARCH_OB)])
        .unwrap();
    assert_eq!(m.world.profiling_program(), Some(ARCH_OB));

    // Force that window to its auto-expiry cap (stands in for
    // MAX_WINDOW/MAX_CALLS -- see `force_expire_profiler_for_test`'s
    // doc).
    m.world.force_expire_profiler_for_test();

    // appr (no P3, not the owner) can now open its own window without
    // `force` and without hitting the "already open, owned by arch"
    // refusal.
    m.call(APPR_OB, "open", &[loom_vm::Value::str(APPR_OB)])
        .unwrap();
    assert_eq!(m.world.profiling_program(), Some(APPR_OB));
}

/// Sanity check for the same path through `World::profile_start`
/// directly (the host-side entry point, not just the efun), same
/// behaviour.
#[test]
fn world_profile_start_replaces_an_expired_window_from_another_principal() {
    let mut m = Mud::new("profexpiry-replace-world");
    m.world.profile_start(ARCH_OB, "arch").unwrap();
    m.world.force_expire_profiler_for_test();
    // A different owner, no force -- must succeed because the window is
    // expired.
    m.world.profile_start(APPR_OB, "appr").unwrap();
    assert_eq!(m.world.profiling_program(), Some(APPR_OB));
}
