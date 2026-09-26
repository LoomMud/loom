// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Golden tests: every directory under `tests/golden/` is a mini mudlib.
//! It is checked with [`loom_compiler::check_mudlib`] and the rendered
//! diagnostics (or `ok`) are compared with `<case>.out`. For cases named
//! `hir_*` the typed HIR dump of every clean program is appended.
//! Bless changes with `LOOM_BLESS=1 cargo test -p loom-compiler --test golden`.

use std::fs;
use std::path::Path;

fn render(dir: &Path, name: &str) -> String {
    let report = loom_compiler::check_mudlib(dir).expect("scan");
    let mut out = String::new();
    if report.errors.is_empty() {
        out.push_str("ok\n");
    }
    for e in &report.errors {
        out.push_str(e);
        out.push('\n');
    }
    if name.starts_with("hir_") {
        for c in report.programs.values() {
            out.push_str(&loom_compiler::dump::program(&c.hir));
            out.push('\n');
        }
    }
    out
}

#[test]
fn golden() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let bless = std::env::var_os("LOOM_BLESS").is_some();
    let mut cases: Vec<_> = fs::read_dir(&root)
        .expect("golden dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.is_dir())
        .collect();
    cases.sort();
    assert!(!cases.is_empty());
    let mut failures = Vec::new();
    for dir in cases {
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        let got = render(&dir, &name);
        let out = root.join(format!("{name}.out"));
        if bless {
            fs::write(&out, &got).expect("write");
            continue;
        }
        let want = fs::read_to_string(&out).unwrap_or_default();
        if want != got {
            failures.push(format!("--- {name}: expected\n{want}\n--- got\n{got}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
