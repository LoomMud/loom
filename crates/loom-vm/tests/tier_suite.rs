// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! **E1.3 tier suite** (OBI-37; spec r5 §5.11.4, OBI-36 design note).
//!
//! An apprentice (T1) cannot write outside its workroom, cannot exceed any
//! of its tier's quotas, and cannot borrow a higher tier's rights through
//! call_other chains, closures, call_outs, heartbeats, inheritance or
//! shadowing. Every denial has a positive control next to it: the same
//! action by a principal that is allowed to do it, or the apprentice doing
//! the allowed version, succeeds.
//!
//! The Weft half lives in `tests/fixtures/tier_suite`. Its
//! `/secure/master.wf` is Warp's shipped §5.11 policy (warp a50a002), not a
//! test-only allow-list, so this is the policy and the driver tested
//! together. The two-root rule is enforced in SQL; its tests are in
//! `crates/loom-persist/tests/roles_s2_integration.rs` (see
//! `docs/security.md`, "E1.3 tier suite"). Runs in CI's required `rust`
//! job (`cargo test --workspace`).

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::{FakeHost, fixture};
use loom_vm::{Limits, ObjectId, RolesSnapshot, Value, World};

const APPR: &str = "/builders/appr/workroom";
const BUILDER: &str = "/builders/builder/workroom";
const ARCH: &str = "/builders/arch/workroom";
const ARCH_TOOL: &str = "/builders/arch/tool";

/// Tiers: appr T1, builder T2 (member of `forest`), lead T3 (leads
/// `forest`), arch T4, roota/rootb T5. Only T1 has a quota row, so T2 is
/// every quota's positive control.
const SEED: &str = r#"{
  "staff": {"appr": 1, "builder": 2, "lead": 3, "arch": 4, "roota": 5, "rootb": 5},
  "domain_members": {"forest": {"builder": "member", "lead": "lead"}},
  "tier_policy": {"1": {
    "max_objects": 4,
    "max_heartbeats": 1,
    "max_callouts_obj": 2,
    "max_callouts_uid": 3,
    "max_ticks_exec": 20000,
    "max_mem_exec_mb": 1,
    "disk_quota_mb": 1
  }}
}"#;

struct Mud {
    root: PathBuf,
    world: World,
    host: FakeHost,
}

impl Mud {
    fn new() -> Mud {
        Mud::with_seed(SEED)
    }

    fn with_seed(seed: &str) -> Mud {
        let root = fixture("tier_suite");
        let mut world = World::boot_with_limits(
            &root,
            Limits {
                // One world tick is one heartbeat, so a test can tick once.
                heartbeat_interval_ticks: 1,
                ..Limits::default()
            },
        )
        .expect("boot");
        world.set_roles_snapshot(Arc::new(
            RolesSnapshot::from_seed_json(seed).expect("seed parses"),
        ));
        Mud {
            root,
            world,
            host: FakeHost::default(),
        }
    }

    fn ob(&mut self, path: &str) -> ObjectId {
        self.world.load_object(path, &mut self.host).expect("load")
    }

    fn call(&mut self, path: &str, f: &str, args: Vec<Value>) -> Result<Value, String> {
        let o = self.ob(path);
        self.world.call(o, f, args, &mut self.host)
    }

    fn call_s(&mut self, path: &str, f: &str, args: &[&str]) -> Result<Value, String> {
        self.call(path, f, args.iter().map(|a| Value::str(a)).collect())
    }

    /// `write`-style call: `Ok(true)` written, `Ok(false)` refused without
    /// raising, `Err` denied.
    fn write(&mut self, who: &str, p: &str) -> Result<bool, String> {
        match self.call_s(who, "write", &[p])? {
            Value::Bool(b) => Ok(b),
            v => panic!("write returned {v:?}"),
        }
    }

    fn exists(&self, p: &str) -> bool {
        self.root.join(p.trim_start_matches('/')).exists()
    }

    fn tick(&mut self) {
        self.world.tick(&mut self.host);
    }

    fn int_var(&self, path: &str, var: &str) -> i64 {
        let o = self.world.find_object(path).expect("object loaded");
        match self.world.var(o, var) {
            Some(Value::Int(n)) => n,
            v => panic!("{path}.{var} = {v:?}"),
        }
    }
}

fn boolv(v: Value) -> bool {
    match v {
        Value::Bool(b) => b,
        v => panic!("expected a bool, got {v:?}"),
    }
}

fn intv(v: Value) -> i64 {
    match v {
        Value::Int(n) => n,
        v => panic!("expected an int, got {v:?}"),
    }
}

fn strv(v: Value) -> String {
    v.as_str()
        .unwrap_or_else(|| panic!("expected a string, got {v:?}"))
        .to_string()
}

/// The apprentice loads one of its own programs (`load_object` from its
/// workroom), then recompiles it with `compile_object` -- both under its
/// own rights. Loading first used to work around `compile_object` of a
/// never-loaded program dropping its parent link. OBI-156 fixed that (see
/// `obi_156_compile_never_loaded_parent.rs`), so the load is no longer
/// required. It stays as an extra check that `load` works under the
/// apprentice's rights.
fn load_first(m: &mut Mud, path: &str) -> ObjectId {
    let Value::Object(ob) = m.call_s(APPR, "load", &[path]).expect("load") else {
        panic!("load_object must return an object")
    };
    assert!(matches!(
        m.call_s(APPR, "compile", &[path]),
        Ok(Value::Null)
    ));
    ob
}

fn denied(r: Result<impl std::fmt::Debug, String>) -> String {
    match r {
        Err(e) => e,
        Ok(v) => panic!("expected a denial, got Ok({v:?})"),
    }
}

fn assert_permission_denied(r: Result<impl std::fmt::Debug, String>) {
    let e = denied(r);
    assert!(e.contains("permission denied"), "{e}");
}

// ===========================================================================
// 1. Files: an apprentice writes only inside its own workroom
// ===========================================================================

#[test]
fn apprentice_writes_inside_its_own_workroom() {
    let mut m = Mud::new();
    for p in [
        "/builders/appr/notes.txt",
        "/builders/appr/area/deep/room.wf",
    ] {
        std::fs::create_dir_all(m.root.join(p.trim_start_matches('/')).parent().unwrap()).unwrap();
        assert_eq!(m.write(APPR, p), Ok(true), "{p}");
        assert!(m.exists(p), "{p}");
    }
}

#[test]
fn apprentice_cannot_write_anywhere_outside_its_workroom() {
    let mut m = Mud::new();
    for p in [
        "/builders/builder/pwned.txt",
        "/builders/arch/pwned.txt",
        "/builders/appr2/pwned.txt",
        "/std/thing.wf",
        "/std/pwned.wf",
        "/secure/master.wf",
        "/secure/pwned.wf",
        "/domains/forest/room.wf",
        "/domains/forest/wip/room.wf",
        "/doc/README.txt",
        "/data/state.txt",
        "/pwned.txt",
    ] {
        let before = std::fs::read(m.root.join(p.trim_start_matches('/'))).ok();
        assert_permission_denied(m.write(APPR, p));
        let after = std::fs::read(m.root.join(p.trim_start_matches('/'))).ok();
        assert_eq!(before, after, "{p} must be untouched");
    }
    // `..` never reaches the policy: the driver rejects the path itself.
    let e = denied(m.write(APPR, "/builders/appr/../builder/pwned.txt"));
    assert!(e.contains("invalid file path"), "{e}");
}

#[test]
fn higher_tiers_write_where_the_apprentice_cannot() {
    let mut m = Mud::new();
    // T2 member: its domain's wip, not its live area.
    assert_eq!(m.write(BUILDER, "/domains/forest/wip/new.wf"), Ok(true));
    assert_permission_denied(m.write(BUILDER, "/domains/forest/new.wf"));
    // T4: live domain content and /doc, still never /std or /secure live.
    assert_eq!(m.write(ARCH, "/domains/forest/new.wf"), Ok(true));
    assert_eq!(m.write(ARCH, "/doc/arch.txt"), Ok(true));
    assert_permission_denied(m.write(ARCH, "/std/pwned.wf"));
    assert_permission_denied(m.write(ARCH, "/secure/pwned.wf"));
}

#[test]
fn apprentice_reads_code_and_docs_but_not_secure_data_or_other_workrooms() {
    let mut m = Mud::new();
    for p in ["/std/thing.wf", "/doc/README.txt", "/builders/appr/room.wf"] {
        assert!(
            m.call_s(APPR, "read", &[p])
                .is_ok_and(|v| v.as_str().is_some()),
            "{p}"
        );
    }
    for p in [
        "/secure/master.wf",
        "/data/state.txt",
        "/builders/builder/workroom.wf",
        "/domains/forest/room.wf",
    ] {
        assert_permission_denied(m.call_s(APPR, "read", &[p]));
    }
    // Positive control: the domain member reads its domain.
    assert!(
        m.call_s(BUILDER, "read", &["/domains/forest/room.wf"])
            .is_ok_and(|v| v.as_str().is_some())
    );
}

#[test]
fn apprentice_compiles_and_upgrades_only_its_own_workroom() {
    let mut m = Mud::new();
    assert!(matches!(
        m.call_s(APPR, "compile", &["/builders/appr/gadget"]),
        Ok(Value::Null)
    ));
    assert!(matches!(
        m.call_s(APPR, "upgrade", &["/builders/appr/gadget"]),
        Ok(Value::Int(_))
    ));
    for p in [
        "/std/thing",
        "/secure/roles",
        "/builders/builder/workroom",
        "/domains/forest/room",
    ] {
        assert_permission_denied(m.call_s(APPR, "compile", &[p]));
        assert_permission_denied(m.call_s(APPR, "upgrade", &[p]));
    }
    // Positive control: an arch compiles protected code.
    assert!(matches!(
        m.call_s(ARCH, "compile", &["/std/thing"]),
        Ok(Value::Null)
    ));
}

// ===========================================================================
// 2. Identity and privileged efuns
// ===========================================================================

#[test]
fn apprentice_cannot_seteuid_but_login_hands_a_body_its_account() {
    let mut m = Mud::new();
    for e in ["arch", "rootb", "builder", "mudlib", "root"] {
        assert!(m.call_s(APPR, "raise", &[e]).is_err(), "seteuid({e})");
        assert_eq!(
            strv(m.call_s(APPR, "ids", &[]).unwrap()),
            "appr/appr",
            "{e}"
        );
    }
    // Positive control: the mudlib login path moves a body's euid onto an
    // account (master.connect -> /std/player.assume_account_euid).
    let master = m.world.find_object("/secure/master").unwrap();
    m.world
        .call(
            master,
            "set_next_account",
            vec![Value::str("appr")],
            &mut m.host,
        )
        .unwrap();
    m.world.connect(1, &mut m.host);
    assert_eq!(m.host.take(1), "hello appr\n");
    let body = m.world.connection_object(1).unwrap();
    assert_eq!(m.world.euid_name(body), Some("appr"));
    // ...and that body is then held to the apprentice's rights.
    m.world.input(1, "write /std/pwned.wf", &mut m.host);
    assert!(m.host.take(1).starts_with("denied:"));
    m.world
        .input(1, "write /builders/appr/from-body.txt", &mut m.host);
    assert_eq!(m.host.take(1), "true\n");
}

#[test]
fn apprentice_cannot_destruct_other_objects_but_can_destruct_itself() {
    let mut m = Mud::new();
    m.ob("/std/relay");
    assert_permission_denied(m.call_s(APPR, "kill", &["/std/relay"]));
    assert!(m.world.find_object("/std/relay").is_some());
    // Positive controls: T3+ holds P2; any object may destruct itself.
    m.ob("/builders/arch/workroom");
    m.call_s(ARCH, "kill", &["/std/relay"]).unwrap();
    assert!(m.world.find_object("/std/relay").is_none());
    m.call_s(APPR, "kill_self", &[]).unwrap();
    assert!(m.world.find_object(APPR).is_none());
}

#[test]
fn apprentice_cannot_use_driver_only_secure_powers_but_their_facade_answers() {
    let mut m = Mud::new();
    for (f, args) in [
        ("roles_direct", vec![Value::str("appr")]),
        ("propose_direct", vec![Value::str("appr")]),
        ("cut", vec![Value::str("/std/pwned.wf")]),
    ] {
        let e = denied(m.call(APPR, f, args));
        assert!(e.contains("only code under /secure"), "{f}: {e}");
    }
    assert!(!m.exists("/std/pwned.wf"));
    // Positive controls: /secure/roles answers anyone; /secure code cuts.
    assert_eq!(intv(m.call_s(APPR, "roles_facade", &["arch"]).unwrap()), 4);
    assert!(boolv(
        m.call_s("/secure/cutter", "cut_write", &["/std/cut.wf"])
            .unwrap()
    ));
    assert!(m.exists("/std/cut.wf"));
}

// ===========================================================================
// 3. No escalation through a higher-tier object
// ===========================================================================

const LIVE: &str = "/domains/forest/esc.wf";
const OWN: &str = "/builders/appr/esc.txt";

#[test]
fn call_other_into_an_arch_daemon_does_not_lend_its_rights() {
    let mut m = Mud::new();
    assert_permission_denied(m.call_s(APPR, "ask_arch_write", &[LIVE]));
    assert!(!m.exists(LIVE));
    // Positive control: the arch asking its own daemon.
    assert!(boolv(m.call_s(ARCH, "ask_arch_write", &[LIVE]).unwrap()));
    assert!(m.exists(LIVE));
}

#[test]
fn a_call_other_chain_is_denied_by_any_lower_tier_frame_in_it() {
    let mut m = Mud::new();
    // appr -> /std/relay (mudlib) -> arch daemon.
    assert_permission_denied(m.call_s(APPR, "relay_to_arch", &[LIVE]));
    // mudlib -> appr workroom: appr in the middle, arch nowhere.
    let appr = Value::Object(m.ob(APPR));
    assert_permission_denied(m.call("/std/relay", "relay_write", vec![appr, Value::str(LIVE)]));
    assert!(!m.exists(LIVE));
    // Positive controls: the same chains with no apprentice in them.
    assert!(boolv(m.call_s(ARCH, "relay_to_arch", &[LIVE]).unwrap()));
    let arch = Value::Object(m.ob(ARCH));
    assert!(boolv(
        m.call("/std/relay", "relay_write", vec![arch, Value::str(LIVE)])
            .unwrap()
    ));
}

/// Regression (found by this suite): a closure made by *inherited* code
/// (here /std/workbench's `make_writer`, run as the workroom) used to be
/// pinned to the object's own program, so calling it indexed the wrong
/// function table and panicked the world thread.
#[test]
fn a_closure_made_by_inherited_code_runs_its_own_body() {
    let mut m = Mud::new();
    let f = m.call_s(APPR, "make_writer", &[OWN]).unwrap();
    assert!(boolv(m.call(APPR, "invoke", vec![f.clone()]).unwrap()));
    assert!(m.exists(OWN));
    // Invoked by the arch daemon: runs, and is denied for `arch`.
    assert_permission_denied(m.call(ARCH_TOOL, "invoke", vec![f]));
}

#[test]
fn an_arch_closure_invoked_by_the_apprentice_is_denied() {
    let mut m = Mud::new();
    let f = m.call_s(ARCH_TOOL, "make_writer", &[LIVE]).unwrap();
    assert_permission_denied(m.call(APPR, "invoke", vec![f.clone()]));
    assert!(!m.exists(LIVE));
    // Positive control: the arch invoking its own closure.
    assert!(boolv(m.call(ARCH_TOOL, "invoke", vec![f]).unwrap()));
    assert!(m.exists(LIVE));
}

#[test]
fn an_apprentice_closure_run_by_an_arch_heartbeat_keeps_apprentice_rights() {
    let mut m = Mud::new();
    m.call_s(APPR, "give_arch_closure", &[LIVE]).unwrap();
    m.tick();
    assert!(
        !m.exists(LIVE),
        "the arch heartbeat must not lend its rights"
    );
    // Not vacuous: the heartbeat ran the closure and caught the denial.
    let tool = m.world.find_object(ARCH_TOOL).unwrap();
    let err = m
        .world
        .var(tool, "last_error")
        .map(strv)
        .unwrap_or_default();
    assert!(err.contains("permission denied"), "{err:?}");
    // Positive control: the same heartbeat runs the arch's own closure.
    let f = m.call_s(ARCH_TOOL, "make_writer", &[LIVE]).unwrap();
    m.call(ARCH_TOOL, "store", vec![f]).unwrap();
    m.tick();
    assert!(m.exists(LIVE));
}

#[test]
fn a_call_out_keeps_the_guard_it_was_scheduled_under() {
    let mut m = Mud::new();
    // appr has the arch daemon schedule the write: captured {appr, arch}.
    m.call_s(APPR, "ask_arch_schedule", &[LIVE]).unwrap();
    // appr's own call_out: captured {appr}.
    m.call_s(APPR, "schedule_write", &[LIVE]).unwrap();
    m.tick();
    m.tick();
    assert!(!m.exists(LIVE));
    // Positive controls: the arch scheduling for itself, and the
    // apprentice scheduling a write into its own workroom.
    m.call_s(ARCH_TOOL, "schedule_write", &[LIVE]).unwrap();
    m.call_s(APPR, "schedule_write", &[OWN]).unwrap();
    m.tick();
    m.tick();
    assert!(m.exists(LIVE));
    assert!(m.exists(OWN));
}

#[test]
fn inheriting_an_arch_daemon_gives_its_code_not_its_rights() {
    let mut m = Mud::new();
    // The apprentice loads its own program (see `load_first`).
    let sneak = load_first(&mut m, "/builders/appr/sneak_arch");
    assert_eq!(m.world.owner_uid(sneak), Some("appr"));
    assert_permission_denied(m.call_s("/builders/appr/sneak_arch", "write_for", &[LIVE]));
    assert!(!m.exists(LIVE));
    // Positive control: the inherited code works within appr's rights.
    assert!(boolv(
        m.call_s("/builders/appr/sneak_arch", "write_for", &[OWN])
            .unwrap()
    ));
}

#[test]
fn inheriting_secure_code_does_not_unlock_unguarded_or_the_roles_efuns() {
    let mut m = Mud::new();
    // Whether or not the inherit compiles, it must never yield a /secure
    // power: the driver checks the object's own program path.
    let loaded = m.call_s(APPR, "load", &["/builders/appr/sneak_secure"]);
    if loaded.is_ok() {
        let e = denied(m.call_s(
            "/builders/appr/sneak_secure",
            "cut_write",
            &["/std/pwned.wf"],
        ));
        assert!(e.contains("only code under /secure"), "{e}");
        let e = denied(m.call_s("/builders/appr/sneak_secure", "read_tier", &["arch"]));
        assert!(e.contains("only code under /secure"), "{e}");
    }
    assert!(!m.exists("/std/pwned.wf"));
    // Positive control: the /secure program itself has both powers.
    assert_eq!(
        intv(m.call_s("/secure/cutter", "read_tier", &["arch"]).unwrap()),
        4
    );
}

#[test]
fn overriding_a_hook_in_inherited_mudlib_code_runs_it_as_the_apprentice() {
    let mut m = Mud::new();
    let sneak = "/builders/appr/sneak_installer";
    load_first(&mut m, sneak);
    m.call_s(sneak, "aim_at", &["/doc/pwned.txt"]).unwrap();
    assert_permission_denied(m.call_s(sneak, "install", &[]));
    assert!(!m.exists("/doc/pwned.txt"));
    // Positive controls: aimed inside appr's workroom it installs; the
    // mudlib's own copy may write /doc.
    m.call_s(sneak, "aim_at", &[OWN]).unwrap();
    assert!(boolv(m.call_s(sneak, "install", &[]).unwrap()));
    assert!(m.exists(OWN));
    assert!(boolv(m.call_s("/std/installer", "install", &[]).unwrap()));
    assert!(m.exists("/doc/installed.txt"));
}

#[test]
fn shadowing_efun_and_apply_names_changes_nothing_the_driver_checks() {
    let mut m = Mud::new();
    let sh = "/builders/appr/shadow_names";
    load_first(&mut m, sh);
    // The local geteuid() shadows the efun for this program's own calls...
    assert_eq!(strv(m.call_s(sh, "who", &[]).unwrap()), "root");
    // ...but the driver still sees appr, and the local valid_write is not
    // the master's.
    assert_permission_denied(m.call_s(sh, "try_write", &[LIVE]));
    assert!(!m.exists(LIVE));
    assert!(boolv(m.call_s(sh, "try_write", &[OWN]).unwrap()));
}

#[test]
fn lpc_style_shadow_does_not_exist() {
    let mut m = Mud::new();
    let r = m.call_s(APPR, "compile", &["/builders/appr/shadow_efun"]);
    let msg = match r {
        Ok(v) if v.as_str().is_some() => strv(v),
        Err(e) => e,
        other => panic!("shadow() must not compile, got {other:?}"),
    };
    assert!(msg.contains("shadow"), "{msg}");
    assert!(
        m.world
            .load_object("/builders/appr/shadow_efun", &mut m.host)
            .is_err()
    );
}

#[test]
fn a_secure_path_inside_a_workroom_is_just_apprentice_code() {
    let mut m = Mud::new();
    let fake = "/builders/appr/secure/master";
    load_first(&mut m, fake);
    assert_eq!(strv(m.call_s(fake, "ids", &[]).unwrap()), "appr/appr");
    let e = denied(m.call_s(fake, "cut_write", &["/std/pwned.wf"]));
    assert!(e.contains("only code under /secure"), "{e}");
    let e = denied(m.call_s(fake, "read_tier", &["arch"]));
    assert!(e.contains("only code under /secure"), "{e}");
    assert!(!m.exists("/std/pwned.wf"));
}

/// Reserved principal names (D-S3.1). `root`, `mudlib` and `domain:*` are
/// the driver's own principals. No account or workroom may take them: a
/// player who registered `root` would otherwise pass the master's
/// "account name" check and `seteuid` into the driver's root.
#[test]
fn a_body_cannot_take_a_reserved_principal_as_its_account() {
    let mut m = Mud::new();
    let master = m.world.find_object("/secure/master").unwrap();
    for (conn, name) in [(1, "root"), (2, "mudlib")] {
        m.world
            .call(
                master,
                "set_next_account",
                vec![Value::str(name)],
                &mut m.host,
            )
            .unwrap();
        m.world.connect(conn, &mut m.host);
        m.host.take(conn);
        if let Some(body) = m.world.connection_object(conn) {
            assert_ne!(m.world.euid_name(body), Some(name), "{name}");
            m.world.input(conn, "write /secure/pwned.wf", &mut m.host);
            m.host.take(conn);
        }
    }
    assert!(!m.exists("/secure/pwned.wf"));
    // Positive control: an ordinary account name.
    m.world
        .call(
            master,
            "set_next_account",
            vec![Value::str("appr")],
            &mut m.host,
        )
        .unwrap();
    m.world.connect(3, &mut m.host);
    assert_eq!(m.host.take(3), "hello appr\n");
}

#[test]
fn a_workroom_named_after_a_reserved_principal_is_not_that_principal() {
    let mut m = Mud::new();
    for name in ["root", "mudlib"] {
        let dir = m.root.join("builders").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("evil.wf"),
            "pub fn go(p: string) -> bool {\n    return write_file(p, \"evil\")\n}\n",
        )
        .unwrap();
        let path = format!("/builders/{name}/evil");
        let ob = m.ob(&path);
        assert_ne!(m.world.owner_uid(ob), Some(name), "{path}");
        assert!(m.call_s(&path, "go", &["/secure/pwned.wf"]).is_err());
    }
    assert!(!m.exists("/secure/pwned.wf"));
}

// ===========================================================================
// 4. Quotas: every T1 row holds; T2 (no row) is the positive control
// ===========================================================================

#[test]
fn max_objects_holds_even_when_the_clone_is_made_by_an_arch_daemon() {
    let mut m = Mud::new();
    m.ob(APPR); // 1 of 4
    m.call_s(APPR, "spawn", &[]).unwrap();
    m.call_s(APPR, "spawn", &[]).unwrap();
    let via = m.call_s(APPR, "spawn_via_arch", &[]).unwrap(); // 4 of 4
    let Value::Object(via) = via else {
        panic!("{via:?}")
    };
    assert_eq!(m.world.owner_uid(via), Some("appr"), "billed to appr");
    for f in ["spawn", "spawn_via_arch"] {
        let e = denied(m.call_s(APPR, f, &[]));
        assert!(e.contains("object quota exceeded"), "{f}: {e}");
    }
    assert_eq!(m.world.object_count_for_uid("appr"), 4);
    // Positive control.
    for _ in 0..10 {
        m.call_s(BUILDER, "spawn", &[]).unwrap();
    }
}

#[test]
fn max_heartbeats_holds() {
    let mut m = Mud::new();
    m.call_s(APPR, "ticker", &[]).unwrap();
    let e = denied(m.call_s(APPR, "ticker", &[]));
    assert!(e.contains("max_heartbeats"), "{e}");
    m.call_s(BUILDER, "ticker", &[]).unwrap();
    m.call_s(BUILDER, "ticker", &[]).unwrap();
}

#[test]
fn max_callouts_obj_holds() {
    let mut m = Mud::new();
    m.call_s(APPR, "sched", &[]).unwrap();
    m.call_s(APPR, "sched", &[]).unwrap();
    let e = denied(m.call_s(APPR, "sched", &[]));
    assert!(e.contains("max_callouts_obj"), "{e}");
    for _ in 0..5 {
        m.call_s(BUILDER, "sched", &[]).unwrap();
    }
}

#[test]
fn max_callouts_uid_holds_even_through_an_arch_daemon() {
    let mut m = Mud::new();
    m.call_s(APPR, "sched", &[]).unwrap();
    m.call_s(APPR, "sched", &[]).unwrap();
    // The arch daemon's own object has no limit, but the execution is
    // still appr's: 3 of 3.
    m.call_s(APPR, "sched_via_arch", &[]).unwrap();
    let e = denied(m.call_s(APPR, "sched_via_arch", &[]));
    assert!(e.contains("max_callouts_uid"), "{e}");
    for _ in 0..5 {
        m.call_s(BUILDER, "sched_via_arch", &[]).unwrap();
    }
}

#[test]
fn max_ticks_exec_holds() {
    let mut m = Mud::new();
    // Within 20,000 ticks: finishes.
    m.call(APPR, "sched_spin", vec![Value::Int(100)]).unwrap();
    m.tick();
    m.tick();
    assert_eq!(m.int_var(APPR, "spun"), 100);
    // Far beyond it: tick-exhausted, never finishes.
    m.call(APPR, "sched_spin", vec![Value::Int(200_000)])
        .unwrap();
    m.tick();
    m.tick();
    assert_eq!(m.int_var(APPR, "spun"), -200_000);
    // Positive control: T2 gets the world default.
    m.call(BUILDER, "sched_spin", vec![Value::Int(200_000)])
        .unwrap();
    m.tick();
    m.tick();
    assert_eq!(m.int_var(BUILDER, "spun"), 200_000);
}

#[test]
fn max_mem_exec_mb_holds() {
    let mut m = Mud::new();
    m.call(APPR, "grow", vec![Value::Int(1_000)]).unwrap();
    let e = denied(m.call(APPR, "grow", vec![Value::Int(200_000)]));
    assert!(e.contains("memory quota exceeded"), "{e}");
    m.call(BUILDER, "grow", vec![Value::Int(200_000)]).unwrap();
}

#[test]
fn disk_quota_mb_holds() {
    let mut m = Mud::new();
    // 512 KiB: fits under the 1 MB T1 quota once, not twice.
    let big = m.call(APPR, "bytes", vec![Value::Int(500_000)]).unwrap();
    let mut put = |who: &str, p: &str, v: Value| -> bool {
        boolv(m.call(who, "write_text", vec![Value::str(p), v]).unwrap())
    };
    assert!(put(APPR, "/builders/appr/big1.txt", big.clone()));
    assert!(!put(APPR, "/builders/appr/big2.txt", big.clone()));
    // Positive control: T2 has no disk row.
    assert!(put(BUILDER, "/builders/builder/big1.txt", big.clone()));
    assert!(put(BUILDER, "/builders/builder/big2.txt", big));
    assert!(!m.exists("/builders/appr/big2.txt"));
}

#[test]
fn tick_share_per_min_holds() {
    let mut m = Mud::with_seed(
        r#"{"staff": {"appr": 1, "builder": 2, "arch": 4},
            "tier_policy": {"1": {"tick_share_per_min": 1}}}"#,
    );
    for who in [APPR, BUILDER] {
        m.call(who, "sched_spin", vec![Value::Int(10)]).unwrap();
        m.tick(); // runs, and breaches appr's 1-tick share
    }
    for who in [APPR, BUILDER] {
        m.call(who, "sched_spin", vec![Value::Int(20)]).unwrap();
    }
    m.tick();
    assert_eq!(m.int_var(APPR, "spun"), -20, "appr's call_out is deferred");
    assert_eq!(m.int_var(BUILDER, "spun"), 20, "builder's is not");
    assert_eq!(m.world.pending_call_outs(), 1, "deferred, not dropped");
}

// ===========================================================================
// 5. Confinement: workroom objects stay out of the live game
// ===========================================================================

#[test]
fn a_workroom_item_cannot_enter_live_domain_content() {
    let mut m = Mud::new();
    let gadget = Value::Object(m.ob("/builders/appr/gadget"));
    let live = Value::Object(m.ob("/domains/forest/room"));
    let own = Value::Object(m.ob("/builders/appr/room"));
    let e = denied(m.call(APPR, "move_into", vec![gadget.clone(), live]));
    assert!(e.contains("confine") || e.contains("live"), "{e}");
    m.call(APPR, "move_into", vec![gadget, own]).unwrap();
}
