// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! The bytecode VM core (OBI-31): values, heap, and the register-bytecode
//! interpreter that will replace [`crate::interp`]'s tree-walker behind the
//! same `World` API (spec §5.8/§5.9).
//!
//! **Status:** the interpreter core (this module) is real and tested in
//! isolation — heap-allocated call stack (D-P1.3), 16-byte values, RC +
//! cycle collector, tick metering, depth limits, stack-traced errors — but
//! it is not yet wired to `World`/`Program`/`ObjectTable` as the thing that
//! actually executes a `.wf` file. That needs a `Host` impl backed by
//! `World` plus a codegen path from the Phase 0 subset AST (or the V1
//! HIR/checker) into `loom_compiler::bytecode::Module`, which is the next
//! slice of OBI-31. See the crate's `docs/` note left alongside this
//! module for the concrete next steps.

pub mod heap;
pub mod vm;

pub use heap::{HeapObj, Map, Value, collect_cycles, live_allocations};
pub use vm::{Host, Interpreter, Limits, RtError};
