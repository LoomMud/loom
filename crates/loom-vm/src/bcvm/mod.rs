// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

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
pub mod compile_worker;
pub mod heap;
pub mod registry;
pub mod schema_convert;
pub mod vm;

pub use compile::{CompileError, compile_and_verify};
pub use heap::{HeapObj, MapData, Value, shallow_bytes};
pub use registry::{
    BcObject, CompiledProgram, Compiler, CowMetrics, Registry, RegistryHost, compile_hir_program,
};
pub use vm::{CallSite, Host, Interpreter, Limits, RtError};
