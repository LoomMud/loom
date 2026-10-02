// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `textDocument/completion`: efuns, driver applies, and the member API a
//! program inherits (the "`/std` API" scope item -- in practice any
//! inherited program's public interface, `/std` being the common case).

use std::rc::Rc;

use loom_compiler::interface::ProgramInfo;
use loom_compiler::{efuns, ty::Ty};
use lsp_types::{CompletionItem, CompletionItemKind};

/// Driver applies (spec \u00a77.2/\u00a77.5/\u00a7security.md): functions the
/// *driver* calls on an object, not ones a Weft program calls itself.
/// Curated from every `call_apply`/master-apply call site in `loom-vm`
/// (grep audit, OBI-168); kept here rather than generated because the VM
/// side names these as plain string literals at call sites, not a single
/// registry table the way efuns are (`efuns::names`, \u00a75.5).
const APPLIES: &[(&str, &str)] = &[
    ("create", "runs once after load/clone (spec `/std/object` convention); never re-run on update"),
    ("heartbeat", "called once per heartbeat tick while `set_heartbeat(true)`"),
    ("connect", "called on the master when a new connection arrives"),
    ("logon", "called on a player object right after login"),
    ("process_input", "called with one line of raw player input"),
    ("net_dead", "called when a player's connection drops unexpectedly"),
    ("account_result", "async result of `account_create`/`account_login`, by correlation id"),
    ("roles_result", "async result of a `roles_*` efun, by correlation id"),
    ("valid_read", "master apply: may `euid` read `path`?"),
    ("valid_write", "master apply: may `euid` write `path`?"),
    ("valid_efun", "master apply: may `euid` call this P1+ efun?"),
    ("valid_compile", "master apply: may `euid` compile/update `path`?"),
    ("valid_upgrade", "master apply: may `euid` `upgrade_all(path)`?"),
    ("valid_seteuid", "master apply: may the caller `seteuid` to this principal?"),
    ("valid_bind", "master apply: may the caller `bind_connection` this object? (never cached)"),
    ("program_flags", "master apply: `CONFINED`/`LIVE` bitset for `path` (movement/confinement rules)"),
];

fn efun_item(name: &str) -> CompletionItem {
    let detail = efuns::lookup(name).map(|sig| {
        let params = sig
            .params
            .iter()
            .map(|p| match p {
                efuns::Param::Ty(t) => t.to_string(),
                efuns::Param::Sized => "string|[T]|{K: V}".to_string(),
                efuns::Param::AnyMap => "{K: V}".to_string(),
            })
            .collect::<Vec<_>>()
            .join(", ");
        let ret = match &sig.ret {
            efuns::Ret::Ty(t) => t.to_string(),
            efuns::Ret::KeysOf => "[K]".to_string(),
        };
        format!("efun {name}({params}) -> {ret}")
    });
    CompletionItem {
        label: name.to_string(),
        kind: Some(CompletionItemKind::FUNCTION),
        detail,
        ..Default::default()
    }
}

fn apply_item(name: &str, doc: &str) -> CompletionItem {
    CompletionItem {
        label: name.to_string(),
        kind: Some(CompletionItemKind::EVENT),
        detail: Some("apply".to_string()),
        documentation: Some(lsp_types::Documentation::String(doc.to_string())),
        ..Default::default()
    }
}

fn member_item(name: &str, owner: &str, ty: &Ty, kind: CompletionItemKind) -> CompletionItem {
    CompletionItem {
        label: name.to_string(),
        kind: Some(kind),
        detail: Some(format!("{ty} (from {owner})")),
        ..Default::default()
    }
}

/// Every efun (spec \u00a75.5).
pub fn efun_items() -> Vec<CompletionItem> {
    efuns::names().map(efun_item).collect()
}

/// Every known driver apply.
pub fn apply_items() -> Vec<CompletionItem> {
    APPLIES.iter().map(|(n, d)| apply_item(n, d)).collect()
}

/// Members visible on `self` in a program with interface `info`: its own
/// and every inherited (non-private) function/variable/const -- the
/// `/std` API completion item, generalised to whatever is actually
/// inherited (spec \u00a75.4's virtual inheritance already resolved all of
/// this into one flat, dominance-picked view, which is exactly the
/// completion list a builder wants: "what can I call on myself").
pub fn member_items(info: &Rc<ProgramInfo>) -> Vec<CompletionItem> {
    let mut out = Vec::with_capacity(info.fns.len() + info.vars.len() + info.consts.len());
    for f in info.fns.values() {
        let params = f
            .params
            .iter()
            .map(|p| p.ty.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        out.push(CompletionItem {
            label: f.name.to_string(),
            kind: Some(CompletionItemKind::METHOD),
            detail: Some(format!("fn({params}) -> {} (from {})", f.ret, f.owner)),
            ..Default::default()
        });
    }
    for v in info.vars.values() {
        out.push(member_item(&v.name, &v.owner, &v.ty, CompletionItemKind::FIELD));
    }
    for c in info.consts.values() {
        out.push(member_item(&c.name, &c.owner, &c.ty, CompletionItemKind::CONSTANT));
    }
    out
}

/// Everything completion offers at an arbitrary position in the body of a
/// program that currently compiles clean: efuns, applies and inherited
/// members together (the client's own prefix filtering narrows this; we
/// do not attempt context-sensitivity -- e.g. "only after `self.`" -- in
/// this first pass, matching the M-size scope).
pub fn all_items(info: Option<&Rc<ProgramInfo>>) -> Vec<CompletionItem> {
    let mut out = efun_items();
    out.extend(apply_items());
    if let Some(info) = info {
        out.extend(member_items(info));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn efun_items_cover_a_known_efun_with_its_signature() {
        let items = efun_items();
        let send = items.iter().find(|i| i.label == "send").unwrap();
        assert!(send.detail.as_ref().unwrap().contains("send("));
    }

    #[test]
    fn apply_items_cover_create_and_valid_read() {
        let items = apply_items();
        assert!(items.iter().any(|i| i.label == "create"));
        assert!(items.iter().any(|i| i.label == "valid_read"));
    }

    #[test]
    fn member_items_include_inherited_std_functions() {
        let (ast, diags) = loom_syntax::parse("pub fn short() -> string {\n  return \"a thing\"\n}\n");
        assert!(diags.is_empty());
        let parent = loom_compiler::check_program("/std/object", &ast, vec![], vec![]).unwrap();
        let items = member_items(&parent.info);
        assert!(items.iter().any(|i| i.label == "short"));
    }
}
