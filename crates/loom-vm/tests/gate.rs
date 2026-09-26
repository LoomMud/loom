// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! The Phase 0 gate (OBI-23): every v1 construct that `loom-syntax` parses
//! but the Phase 0 evaluator cannot run is a spanned `not yet supported`
//! diagnostic from `loom check`, never a panic or a silent mis-run.
//! Bless with `LOOM_BLESS=1 cargo test -p loom-vm --test gate`.

mod common;

use std::path::Path;

use common::scratch;

/// `check_mudlib` over a one-file mudlib holding `src` at `/secure/master`.
fn check_one(src: &str) -> Vec<String> {
    let root = scratch("gate");
    let p = root.join("secure/master.wf");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, src).unwrap();
    loom_vm::check_mudlib(&root).expect("walk mudlib")
}

#[test]
fn every_v1_construct_is_reported_not_yet_supported() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gate");
    let src = std::fs::read_to_string(dir.join("v1_constructs.wf")).unwrap();
    let (ast, diags) = loom_syntax::parse(&src);
    assert!(diags.is_empty(), "fixture must parse: {diags:?}");
    let gate = loom_vm::subset::phase0_gate(&ast);
    let got: String = gate
        .iter()
        .map(|d| d.render("v1_constructs.wf", &src))
        .collect();
    for d in &gate {
        assert!(d.message.ends_with(loom_vm::subset::NOT_YET), "{d:?}");
        assert!(d.hint.is_some(), "{d:?}");
    }
    let out = dir.join("v1_constructs.out");
    if std::env::var_os("LOOM_BLESS").is_some() {
        std::fs::write(&out, &got).unwrap();
    }
    let want = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(want, got);

    // And `loom check` surfaces them (before linking or loading parents).
    let reports = check_one(&src);
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert!(
        reports[0].contains(loom_vm::subset::NOT_YET),
        "{}",
        reports[0]
    );
}

/// Every success golden of the v1 grammar goes through `loom check` without
/// panicking; files using v1-only constructs are rejected by the gate.
#[test]
fn loom_check_never_panics_on_v1_goldens() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../loom-syntax/tests/golden");
    let mut n = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.ends_with(".wf") || name.ends_with("_err.wf") {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap();
        let (ast, _) = loom_syntax::parse(&src);
        let gated = !loom_vm::subset::phase0_gate(&ast).is_empty();
        let reports = check_one(&src);
        if gated {
            assert!(
                reports.iter().any(|r| r.contains(loom_vm::subset::NOT_YET)),
                "{name}: {reports:?}"
            );
        }
        n += 1;
    }
    assert!(n >= 10, "expected the v1 success goldens, found {n}");
}
