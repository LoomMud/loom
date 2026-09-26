// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Acceptance criterion: every Phase 0 mudlib program compiles to verified
//! bytecode (codegen → assemble → verify, and a decode/encode round trip).

use std::path::Path;

fn compile_and_verify(rel: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel);
    let report = loom_compiler::check_mudlib(&root).expect("scan");
    assert!(
        report.errors.is_empty(),
        "{rel}:\n{}",
        report.errors.join("\n")
    );
    assert!(!report.programs.is_empty(), "{rel}: no programs found");
    for (path, c) in &report.programs {
        let module = loom_compiler::codegen::compile(&c.hir)
            .unwrap_or_else(|e| panic!("{rel}{path}: codegen: {e}"));
        loom_compiler::verify::verify(&module).unwrap_or_else(|e| {
            panic!(
                "{rel}{path}: verify: {e}\n{}",
                loom_compiler::disasm::module(&module)
            )
        });

        // Round trip through the on-the-wire encoding too: decode + verify
        // again, since decode alone does not imply well-typed (see
        // `crate::verify` docs).
        let bytes = loom_compiler::bytecode::encode(&module);
        let back = loom_compiler::bytecode::decode(&bytes)
            .unwrap_or_else(|e| panic!("{rel}{path}: decode roundtrip: {e}"));
        loom_compiler::verify::verify(&back)
            .unwrap_or_else(|e| panic!("{rel}{path}: verify after roundtrip: {e}"));
    }
}

#[test]
fn warp_phase0_compiles_to_verified_bytecode() {
    compile_and_verify("loom-cli/tests/fixtures/warp-phase0");
}

#[test]
fn vm_tworoom_fixture_compiles_to_verified_bytecode() {
    compile_and_verify("loom-vm/tests/fixtures/tworoom");
}
