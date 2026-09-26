// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Bridge from a checked `loom-compiler` program to a `Module` this VM can
//! run: codegen, then the bytecode verifier (the trust boundary that must
//! run before anything executes untrusted bytecode, spec §5.8/§5.9).
//!
//! This is deliberately thin — `loom_compiler::codegen`/`verify` already do
//! the work — but it is the one place `loom-vm` says "these two steps
//! always happen together before a `Module` is allowed to run", which is
//! easy to get wrong by hand (codegen's output must never be executed
//! un-verified, including a `Module` that round-tripped through
//! `encode`/`decode`).

use loom_compiler::bytecode::Module;
use loom_compiler::hir;

#[derive(Debug)]
pub enum CompileError {
    Codegen(loom_compiler::codegen::Unsupported),
    Verify(loom_compiler::verify::VerifyError),
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::Codegen(e) => write!(f, "codegen: {e}"),
            CompileError::Verify(e) => write!(f, "verify: {e}"),
        }
    }
}
impl std::error::Error for CompileError {}

/// Compile checked HIR to a verified `Module`. Never returns a `Module`
/// that hasn't passed [`loom_compiler::verify::verify`].
pub fn compile_and_verify(hir: &hir::Program) -> Result<Module, CompileError> {
    let module = loom_compiler::codegen::compile(hir).map_err(CompileError::Codegen)?;
    loom_compiler::verify::verify(&module).map_err(CompileError::Verify)?;
    Ok(module)
}
