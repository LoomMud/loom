// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! The bytecode VM core (OBI-31): values, heap, and the register-bytecode
//! interpreter that will replace [`crate::interp`]'s tree-walker behind the
//! same `World` API (spec §5.8/§5.9).
//!
//! **Status:** the interpreter core (this module) is real and tested in
//! isolation — heap-allocated call stack (D-P1.3), 16-byte copy-on-write
//! values (spec r5 §5.2.1), tick metering, depth limits, stack-traced
//! errors — but it is not yet wired to `World`/`Program`/`ObjectTable` as
//! the thing that actually executes a `.wf` file. That needs a `Host` impl
//! backed by `World` plus a codegen path from the Phase 0 subset AST (or
//! the V1 HIR/checker) into `loom_compiler::bytecode::Module`, which is the
//! next slice of OBI-31.

pub mod compile;
pub mod heap;
pub mod vm;

pub use compile::{CompileError, compile_and_verify};
pub use heap::{HeapObj, MapData, Value};
pub use vm::{Host, Interpreter, Limits, RtError};
