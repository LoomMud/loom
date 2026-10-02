// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The efun registry (spec §5.5, OBI-33 / V6): the single **authoritative**
//! source of privilege class and tick cost for every efun, plus arity
//! (name, min args, max args). This is the table the VM gate
//! (`bcvm::registry::RegistryHost::driver_efun`) looks efuns up in by
//! identity (§5.4's HIR doc, invariant C2): `loom_compiler::efuns` keeps
//! its own (types + an *advisory* copy of privilege, for the checker's
//! diagnostics) and `loom-compiler`'s `efun_table_matches_vm` test asserts
//! the two agree on name/arity/privilege, since a mismatch there would be
//! a compiler diagnostic lying about what the VM actually enforces.
//!
//! The actual implementations are split between `bcvm::vm::Interpreter`'s
//! inline table (`len`/`split`/`join`/`keys`/`trim`, all [`Privilege::P0`])
//! and `bcvm::registry::RegistryHost::driver_efun` (everything else, which
//! needs the object/program registry, the scheduler and/or the network
//! host).
//!
//! `docs/efuns.md` is generated from this table by [`render_markdown`]; the
//! `efuns_reference_doc_is_up_to_date` test in this module keeps the
//! checked-in copy honest.

/// Privilege class (§5.5): how sensitive an efun's effect is. `P0` is safe
/// for any object to call unconditionally (pure queries, and the small set
/// of side effects Phase 0-2 treat as always-available). `P1`+ efuns go
/// through the stack-based check (`crate::security`, OBI-35) before they
/// run: the master's `valid_efun` must allow the class for every euid on
/// the stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Privilege {
    P0,
    P1,
    P2,
    P3,
    P4,
}

impl Privilege {
    /// `true` if this class must pass the enforcement hook before the
    /// efun runs (every class above `P0`).
    pub fn gated(self) -> bool {
        self > Privilege::P0
    }
}

/// `(name, min args, max args, privilege, tick cost)` for every efun.
/// Tick cost is charged against the calling frame's tick budget (§5.8) the
/// same way a bytecode instruction is; it is deliberately coarse (a flat
/// per-call number, not per-byte-copied or similar) until a benchmark asks
/// for more precision.
const EFUNS: &[(&str, usize, usize, Privilege, u32)] = &[
    ("self", 0, 0, Privilege::P0, 1),
    ("this_player", 0, 0, Privilege::P0, 1),
    ("load_object", 1, 1, Privilege::P0, 50),
    ("clone_object", 1, 1, Privilege::P0, 50),
    ("find_object", 1, 1, Privilege::P0, 5),
    ("object_name", 1, 1, Privilege::P0, 1),
    ("environment", 0, 1, Privilege::P0, 1),
    ("inventory", 1, 1, Privilege::P0, 2),
    ("move_to", 1, 1, Privilege::P0, 2),
    ("send", 2, 2, Privilege::P0, 2),
    // Spec r5 §5.5: "destruct on objects the caller doesn't own is P2";
    // disconnect(ob) acts on another user's connection by the same
    // analogy, so it is P2, not P0 (reclassified in CTO review of
    // OBI-33). S1 may relax this to P0 when `ob` is the caller's own
    // connection.
    ("disconnect", 1, 1, Privilege::P2, 2),
    // Spec §9, OBI-176: turns local client echo on/off around a no-echo
    // prompt (telnet `IAC WILL/WONT ECHO`, WS equivalent). Cosmetic on the
    // wire, not an action on another user's connection the way
    // `disconnect`/`bind_connection` are, so it stays `P0` like `send`.
    ("set_echo", 2, 2, Privilege::P0, 2),
    ("bind_connection", 1, 1, Privilege::P3, 2),
    ("compile_object", 1, 1, Privilege::P1, 500),
    // Spec §7.2/§7.3, OBI-89 (eager mode): migrates every live instance of
    // a program still on a stale version, spread across ticks rather than
    // done synchronously. At least as sensitive as `compile_object` (a
    // mass upgrade, not a single recompile), so P1 pending the CTO's
    // sign-off on efun privilege/tier (flagged, not decided here).
    ("upgrade_all", 1, 1, Privilege::P1, 50),
    ("len", 1, 1, Privilege::P0, 1),
    ("split", 2, 2, Privilege::P0, 5),
    ("join", 2, 2, Privilege::P0, 5),
    ("keys", 1, 1, Privilege::P0, 2),
    ("trim", 1, 1, Privilege::P0, 1),
    // OBI-33 / CTO review: call_out / remove_call_out / set_heartbeat
    // are §5.5's "Timing" row, which is **P0**: every mudlib object
    // needs to be able to schedule itself, so gating this at P1 would
    // leave any tier without P1 unable to schedule anything at all.
    // Abuse is bounded by per-tier *quotas* (§5.11.2: pending call_outs
    // per object/uid, heartbeat objects, sustained tick share), tracked
    // as OBI-36 (S2), not by the privilege class here.
    ("call_out", 2, 2, Privilege::P0, 5),
    ("remove_call_out", 1, 1, Privilege::P0, 2),
    ("set_heartbeat", 1, 1, Privilege::P0, 2),
    // OBI-85 (Warp alpha S4): P0 utility efuns the mudlib needs and had
    // no driver support for yet.
    ("random", 1, 1, Privilege::P0, 1),
    ("time", 0, 0, Privilege::P0, 1),
    ("users", 0, 0, Privilege::P0, 2),
    ("lower", 1, 1, Privilege::P0, 1),
    ("to_int", 1, 1, Privilege::P0, 1),
    // OBI-85 CTO review: destructed-reference safety Warp needs --
    // `destructed(ob)` is P0 (a pure liveness check, same class as
    // `find_object`).
    ("destructed", 1, 1, Privilege::P0, 1),
    // OBI-85: `destruct` on an object the caller doesn't own is P2, same
    // rationale as `disconnect` above (spec r5 §5.5).
    ("destruct", 1, 1, Privilege::P2, 5),
    // OBI-85: async R2-account logins (spec's `account_result` apply).
    // Master-only: P3, so the S1 stack check routes it through
    // `valid_efun`.
    ("account_create", 2, 2, Privilege::P3, 50),
    ("account_login", 2, 2, Privilege::P3, 50),
    // OBI-35 (S1): identity and file efuns. `read_file` is P0 but its
    // path is always checked with `valid_read`; `write_file` is P1 plus
    // `valid_write`. Both then go through OBI-85's mudlib-confined
    // `crate::fileio` (symlink-escape check, 1 MiB cap, `.wf`/`.txt`
    // write allow-list). `seteuid` is P3 plus `valid_seteuid`.
    // `unguarded` is P4-sensitive but gated by a driver rule (the
    // caller's program is under /secure), not by `valid_efun` (design
    // note D-S1.5).
    ("getuid", 0, 0, Privilege::P0, 1),
    ("geteuid", 0, 0, Privilege::P0, 1),
    ("effective_principal", 0, 0, Privilege::P0, 1),
    ("seteuid", 1, 1, Privilege::P3, 10),
    ("read_file", 1, 1, Privilege::P0, 20),
    ("write_file", 2, 2, Privilege::P1, 50),
    ("unguarded", 1, 2, Privilege::P4, 10),
    // OBI-36 (S2b), design note D-S2.2: the roles snapshot's read efuns.
    // Secure-only (a driver rule, exactly like `unguarded`'s D-S1.5, not
    // master policy): P0, no `valid_efun`/stack check, cheap (1-5 ticks).
    ("roles_tier", 1, 1, Privilege::P0, 2),
    ("roles_is_member", 2, 2, Privilege::P0, 2),
    ("roles_is_lead", 2, 2, Privilege::P0, 2),
    ("roles_has_grant", 3, 3, Privilege::P0, 3),
    ("roles_policy", 1, 1, Privilege::P0, 3),
    ("roles_domains", 1, 1, Privilege::P0, 3),
    // D-S2.2: async mutation efuns, like `account_create`/`account_login`
    // (OBI-85) -- return a correlation id, deliver the result later
    // through `roles_result(id, ok, detail)`. Class P3, but *exempt* from
    // `valid_efun` (gated instead by the secure-only rule, the actor rule
    // and the SQL re-check; see `RegistryHost::roles_mutation_gate`),
    // again like `unguarded`.
    ("roles_set_tier", 3, 3, Privilege::P3, 50),
    ("roles_set_member", 4, 4, Privilege::P3, 50),
    ("roles_grant", 5, 5, Privilege::P3, 50),
    ("roles_revoke_grant", 4, 4, Privilege::P3, 50),
    ("roles_propose_tier", 3, 3, Privilege::P3, 50),
    ("roles_approve", 1, 1, Privilege::P3, 50),
    // OBI-169: `errors(program_prefix)`, the grouped runtime-error inbox
    // (filtered by the caller's own `valid_read` permission per distinct
    // program, inside `RegistryHost::driver_efun`'s `"errors"` arm --
    // same pattern as `read_file`'s VFS gate, just applied once per
    // program instead of once per call).
    ("errors", 0, 1, Privilege::P1, 20),
];

/// `(min args, max args)` of efun `name`, if it exists.
pub fn arity(name: &str) -> Option<(usize, usize)> {
    EFUNS
        .iter()
        .find(|(n, ..)| *n == name)
        .map(|(_, a, b, ..)| (*a, *b))
}

/// The registry's `'static` copy of efun `name` (so audit entries and
/// policy-cache keys never allocate), if it exists.
pub fn static_name(name: &str) -> Option<&'static str> {
    EFUNS.iter().find(|(n, ..)| *n == name).map(|(n, ..)| *n)
}

/// The privilege class of efun `name`, if it exists.
pub fn privilege(name: &str) -> Option<Privilege> {
    EFUNS
        .iter()
        .find(|(n, ..)| *n == name)
        .map(|(_, _, _, p, _)| *p)
}

/// The tick cost of one call to efun `name`, if it exists.
pub fn tick_cost(name: &str) -> Option<u32> {
    EFUNS.iter().find(|(n, ..)| *n == name).map(|(.., c)| *c)
}

/// Names of all efuns (for docs and tooling), in table order.
pub fn names() -> impl Iterator<Item = &'static str> {
    EFUNS.iter().map(|(n, ..)| *n)
}

/// Render the efun reference table as Markdown (`docs/efuns.md`), pulling
/// types from `loom_compiler::efuns` (the checker's table, kept in sync
/// with this one by `loom-compiler`'s `efun_table_matches_vm` test) since
/// this registry only tracks arity/privilege/tick cost.
pub fn render_markdown() -> String {
    let mut out = String::new();
    out.push_str("# Efun reference\n\n");
    out.push_str(
        "Generated from `loom_vm::efuns` (privilege class, tick cost, arity) and \
         `loom_compiler::efuns` (parameter/return types) by \
         `cargo test -p loom-vm efuns_reference_doc_is_up_to_date -- --ignored` \
         (regenerate with `UPDATE_EFUNS_DOC=1`). Do not hand-edit.\n\n",
    );
    out.push_str("| Efun | Signature | Privilege | Tick cost |\n");
    out.push_str("|---|---|---|---|\n");
    for name in names() {
        let (min, max) = arity(name).expect(name);
        let priv_ = privilege(name).expect(name);
        let cost = tick_cost(name).expect(name);
        let sig = loom_compiler::efuns::lookup(name)
            .map(|s| render_sig(name, &s, min, max))
            .unwrap_or_else(|| format!("`{name}(...)`"));
        out.push_str(&format!("| `{name}` | {sig} | {priv_:?} | {cost} |\n"));
    }
    out
}

fn render_sig(name: &str, sig: &loom_compiler::efuns::EfunSig, min: usize, max: usize) -> String {
    use loom_compiler::efuns::{Param, Ret};
    let params: Vec<String> = sig
        .params
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let ty = match p {
                Param::Ty(t) => format!("{t:?}"),
                Param::Sized => "string \\| [T] \\| {K: V}".to_string(),
                Param::AnyMap => "{K: V}".to_string(),
            };
            if i >= min { format!("{ty}?") } else { ty }
        })
        .collect();
    debug_assert_eq!((min, max), (sig.min_args, sig.params.len()), "{name}");
    let ret = match &sig.ret {
        Ret::Ty(t) => format!("{t:?}"),
        Ret::KeysOf => "[K]".to_string(),
    };
    format!("`{name}({}) -> {ret}`", params.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_name_has_metadata() {
        for n in names() {
            assert!(arity(n).is_some(), "{n}");
            assert!(privilege(n).is_some(), "{n}");
            assert!(tick_cost(n).is_some(), "{n}");
        }
        assert!(arity("nope").is_none());
    }

    #[test]
    fn only_p0_is_ungated() {
        assert!(!Privilege::P0.gated());
        for p in [Privilege::P1, Privilege::P2, Privilege::P3, Privilege::P4] {
            assert!(p.gated());
        }
    }

    /// Keeps `docs/efuns.md` honest: run with `UPDATE_EFUNS_DOC=1` after
    /// changing the registry to regenerate it.
    #[test]
    fn efuns_reference_doc_is_up_to_date() {
        let generated = render_markdown();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/efuns.md");
        if std::env::var("UPDATE_EFUNS_DOC").is_ok() {
            std::fs::write(path, &generated).unwrap();
            return;
        }
        let on_disk = std::fs::read_to_string(path).unwrap_or_default();
        assert_eq!(
            on_disk, generated,
            "docs/efuns.md is stale; regenerate with UPDATE_EFUNS_DOC=1 cargo test -p loom-vm efuns_reference_doc_is_up_to_date"
        );
    }
}
