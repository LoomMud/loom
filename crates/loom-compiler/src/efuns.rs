// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Efun type signatures for the checker (spec §5.5).
//!
//! This is the compile-time half of the efun registry: parameter and return
//! types plus an *advisory* copy of the privilege class, for the checker's
//! diagnostics only. `loom_vm::efuns` is the runtime half and the
//! **authoritative** one (spec's HIR doc, invariant C2: "the VM gate looks
//! the class up in its own efun registry ... the verifier" — here, a
//! cross-crate test, `efun_table_matches_vm` — "checks the two agree").
//! OBI-33 (V6) built that authoritative registry (name/arity/privilege/tick
//! cost) in `loom-vm`; this table must keep listing exactly the same
//! efuns with the same arity and privilege, which `efun_table_matches_vm`
//! enforces.

use crate::ty::Ty;

/// Privilege class (§5.5). Enforcement is the VM's job (V6); the checker
/// only records it in the HIR so codegen can emit the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Privilege {
    P0,
    P1,
    P2,
    P3,
    P4,
}

/// One parameter of an efun.
#[derive(Clone, Debug)]
pub enum Param {
    Ty(Ty),
    /// `string`, `[T]` or `{K: V}` (for `len`).
    Sized,
    /// Any map `{K: V}` (for `keys`).
    AnyMap,
}

#[derive(Clone, Debug)]
pub enum Ret {
    Ty(Ty),
    /// `[K]` for a `{K: V}` first argument.
    KeysOf,
}

#[derive(Clone, Debug)]
pub struct EfunSig {
    pub name: &'static str,
    pub params: Vec<Param>,
    /// Arguments after `min_args` are optional.
    pub min_args: usize,
    pub ret: Ret,
    pub privilege: Privilege,
}

const NAMES: &[&str] = &[
    "self",
    "this_player",
    "load_object",
    "clone_object",
    "find_object",
    "object_name",
    "environment",
    "inventory",
    "move_to",
    "send",
    "disconnect",
    "bind_connection",
    "compile_object",
    "upgrade_all",
    "len",
    "split",
    "join",
    "keys",
    "trim",
    "call_out",
    "remove_call_out",
    "set_heartbeat",
    "random",
    "time",
    "users",
    "lower",
    "to_int",
    "destructed",
    "destruct",
    "account_create",
    "account_login",
    "getuid",
    "geteuid",
    "effective_principal",
    "seteuid",
    "read_file",
    "write_file",
    "unguarded",
];

/// All efun names known to the checker.
pub fn names() -> impl Iterator<Item = &'static str> {
    NAMES.iter().copied()
}

/// The signature of efun `name`, if it exists.
pub fn lookup(name: &str) -> Option<EfunSig> {
    use Param::Ty as P;
    use Privilege::*;
    let obj = Ty::Object;
    let oobj = Ty::optional(Ty::Object);
    let s = Ty::String;
    let (name, params, min_args, ret, privilege) = match name {
        "self" => ("self", vec![], 0, Ret::Ty(obj), P0),
        "this_player" => ("this_player", vec![], 0, Ret::Ty(oobj), P0),
        "load_object" => ("load_object", vec![P(s)], 1, Ret::Ty(obj), P0),
        "clone_object" => ("clone_object", vec![P(s)], 1, Ret::Ty(obj), P0),
        "find_object" => ("find_object", vec![P(s)], 1, Ret::Ty(oobj), P0),
        "object_name" => ("object_name", vec![P(obj)], 1, Ret::Ty(s), P0),
        "environment" => ("environment", vec![P(oobj.clone())], 0, Ret::Ty(oobj), P0),
        "inventory" => (
            "inventory",
            vec![P(obj)],
            1,
            Ret::Ty(Ty::array(Ty::Object)),
            P0,
        ),
        "move_to" => ("move_to", vec![P(obj)], 1, Ret::Ty(Ty::Void), P0),
        "send" => ("send", vec![P(oobj), P(s)], 2, Ret::Ty(Ty::Void), P0),
        // Reclassified P2 (CTO review of OBI-33, spec r5 §5.5 "destruct
        // on objects the caller doesn't own is P2"): disconnect(ob) acts
        // on another user's connection.
        "disconnect" => ("disconnect", vec![P(oobj)], 1, Ret::Ty(Ty::Void), P2),
        "bind_connection" => ("bind_connection", vec![P(obj)], 1, Ret::Ty(Ty::Void), P3),
        "compile_object" => (
            "compile_object",
            vec![P(s)],
            1,
            Ret::Ty(Ty::optional(Ty::String)),
            P1,
        ),
        // Spec §7.2/§7.3, OBI-89 (eager mode); see `loom_vm::efuns` for the
        // authoritative arity/privilege/tick cost and rationale. Returns
        // the number of instances queued for a future tick's batch.
        "upgrade_all" => ("upgrade_all", vec![P(s.clone())], 1, Ret::Ty(Ty::Int), P1),
        "len" => ("len", vec![Param::Sized], 1, Ret::Ty(Ty::Int), P0),
        "split" => (
            "split",
            vec![P(s.clone()), P(s)],
            2,
            Ret::Ty(Ty::array(Ty::String)),
            P0,
        ),
        "join" => (
            "join",
            vec![P(Ty::array(Ty::String)), P(s)],
            2,
            Ret::Ty(Ty::String),
            P0,
        ),
        "keys" => ("keys", vec![Param::AnyMap], 1, Ret::KeysOf, P0),
        "trim" => ("trim", vec![P(s.clone())], 1, Ret::Ty(s), P0),
        // OBI-33 / CTO review: call_out / remove_call_out / set_heartbeat
        // are §5.5's Timing row, P0 (see `loom_vm::efuns` for the
        // authoritative arity/privilege/tick cost and the rationale).
        "call_out" => ("call_out", vec![P(s), P(Ty::Int)], 2, Ret::Ty(Ty::Int), P0),
        "remove_call_out" => (
            "remove_call_out",
            vec![P(Ty::Int)],
            1,
            Ret::Ty(Ty::Bool),
            P0,
        ),
        "set_heartbeat" => ("set_heartbeat", vec![P(Ty::Bool)], 1, Ret::Ty(Ty::Void), P0),
        // OBI-85 (Warp alpha S4 driver support): see `loom_vm::efuns` for
        // the authoritative arity/privilege (kept in sync by
        // `efun_table_matches_vm`).
        "random" => ("random", vec![P(Ty::Int)], 1, Ret::Ty(Ty::Int), P0),
        "time" => ("time", vec![], 0, Ret::Ty(Ty::Int), P0),
        "users" => ("users", vec![], 0, Ret::Ty(Ty::array(Ty::Object)), P0),
        "lower" => ("lower", vec![P(s.clone())], 1, Ret::Ty(s.clone()), P0),
        "to_int" => (
            "to_int",
            vec![P(s.clone())],
            1,
            Ret::Ty(Ty::optional(Ty::Int)),
            P0,
        ),
        "destructed" => (
            "destructed",
            vec![P(oobj.clone())],
            1,
            Ret::Ty(Ty::Bool),
            P0,
        ),
        "destruct" => ("destruct", vec![P(obj)], 1, Ret::Ty(Ty::Void), P2),
        "account_create" => (
            "account_create",
            vec![P(s.clone()), P(s.clone())],
            2,
            Ret::Ty(Ty::Int),
            P3,
        ),
        "account_login" => (
            "account_login",
            vec![P(s.clone()), P(s.clone())],
            2,
            Ret::Ty(Ty::Int),
            P3,
        ),
        // OBI-35 (S1): see `loom_vm::efuns` for the gating rationale.
        "getuid" => ("getuid", vec![], 0, Ret::Ty(s.clone()), P0),
        "geteuid" => ("geteuid", vec![], 0, Ret::Ty(s.clone()), P0),
        "effective_principal" => ("effective_principal", vec![], 0, Ret::Ty(s.clone()), P0),
        "seteuid" => ("seteuid", vec![P(s.clone())], 1, Ret::Ty(Ty::Void), P3),
        "read_file" => (
            "read_file",
            vec![P(s.clone())],
            1,
            Ret::Ty(Ty::optional(Ty::String)),
            P0,
        ),
        "write_file" => (
            "write_file",
            vec![P(s.clone()), P(s.clone())],
            2,
            Ret::Ty(Ty::Bool),
            P1,
        ),
        "unguarded" => (
            "unguarded",
            vec![P(s), P(Ty::array(Ty::Any))],
            1,
            Ret::Ty(Ty::Any),
            P4,
        ),
        _ => return None,
    };
    Some(EfunSig {
        name,
        params,
        min_args,
        ret,
        privilege,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_name_has_a_signature() {
        for n in names() {
            let sig = lookup(n).unwrap_or_else(|| panic!("no signature for {n}"));
            assert_eq!(sig.name, n);
            assert!(sig.min_args <= sig.params.len());
        }
        assert!(lookup("nope").is_none());
    }
}
