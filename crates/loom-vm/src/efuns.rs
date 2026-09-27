// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Efun name/arity metadata (spec §5.5), kept in sync with
//! `loom_compiler::efuns` by `loom-compiler`'s `efun_table_matches_vm` test.
//! The actual implementations are split between `bcvm::vm::Interpreter`'s
//! inline table (`len`/`split`/`join`/`keys`/`trim`) and
//! `bcvm::registry::RegistryHost::driver_efun` (everything else, which
//! needs the object/program registry and/or network host).

/// `(name, min args, max args)` for every efun.
const EFUNS: &[(&str, usize, usize)] = &[
    ("self", 0, 0),
    ("this_player", 0, 0),
    ("load_object", 1, 1),
    ("clone_object", 1, 1),
    ("find_object", 1, 1),
    ("object_name", 1, 1),
    ("environment", 0, 1),
    ("inventory", 1, 1),
    ("move_to", 1, 1),
    ("send", 2, 2),
    ("disconnect", 1, 1),
    ("bind_connection", 1, 1),
    ("compile_object", 1, 1),
    ("len", 1, 1),
    ("split", 2, 2),
    ("join", 2, 2),
    ("keys", 1, 1),
    ("trim", 1, 1),
];

/// Arity of efun `name`, if it exists.
pub fn arity(name: &str) -> Option<(usize, usize)> {
    EFUNS
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, a, b)| (*a, *b))
}

/// Names of all efuns (for docs and tooling).
pub fn names() -> impl Iterator<Item = &'static str> {
    EFUNS.iter().map(|(n, _, _)| *n)
}
