// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Weft compiler front half (spec §5.3, §5.4, §5.9): name resolution, the
//! inherit graph, and the strict-by-default gradual type checker, producing
//! the typed HIR that codegen (V2) lowers. Owner: Gimli.
//!
//! Entry points: [`check_program`] for one program against its parents'
//! interfaces, [`Session`] to compile programs in inherit order from a
//! [`SourceLoader`], and [`check_mudlib`] for `loom check`.
//! The HIR contract is documented in [`hir`] and `docs/hir.md`.

pub mod bytecode;
pub mod check;
pub mod codegen;
pub mod disasm;
pub mod dump;
pub mod efuns;
pub mod hir;
pub mod interface;
pub mod ir;
pub mod lint;
pub mod mudlib;
pub mod ty;
pub mod verify;

pub use check::{Checked, check_program};
pub use interface::ProgramInfo;
pub use mudlib::{FsLoader, MudlibReport, Outcome, Session, SourceLoader, check_mudlib};
pub use ty::Ty;
