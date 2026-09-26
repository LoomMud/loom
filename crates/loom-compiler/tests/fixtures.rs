// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The Phase 0 mudlibs in the workspace (Warp Phase 0 and the VM test
//! fixtures) type-check clean under the strict checker, and the checker's
//! efun table matches the efuns the VM implements.

use std::path::Path;

fn assert_clean(rel: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel);
    let report = loom_compiler::check_mudlib(&root).expect("scan");
    assert!(
        report.errors.is_empty(),
        "{rel}:\n{}",
        report.errors.join("\n")
    );
    assert!(!report.programs.is_empty(), "{rel}: no programs found");
}

#[test]
fn warp_phase0_checks_clean() {
    assert_clean("loom-cli/tests/fixtures/warp-phase0");
}

#[test]
fn vm_tworoom_fixture_checks_clean() {
    assert_clean("loom-vm/tests/fixtures/tworoom");
}

#[test]
fn efun_table_matches_vm() {
    let mut ours: Vec<&str> = loom_compiler::efuns::names().collect();
    let mut vm: Vec<&str> = loom_vm::efuns::names().collect();
    ours.sort_unstable();
    vm.sort_unstable();
    assert_eq!(ours, vm);
    for n in vm {
        let sig = loom_compiler::efuns::lookup(n).expect(n);
        let (min, max) = loom_vm::efuns::arity(n).expect(n);
        assert_eq!((sig.min_args, sig.params.len()), (min, max), "{n}");
    }
}
