// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Golden tests: every `tests/golden/*.wf` is parsed and compared with the
//! sibling `.out` file (AST S-expression, or rendered diagnostics). Files
//! named `*_err.wf` must produce diagnostics; all others must parse cleanly.
//! The `.wf` files double as the `cargo fuzz` seed corpus (`fuzz/`).
//! Bless changes with `LOOM_BLESS=1 cargo test -p loom-syntax --test golden`.

use std::fs;
use std::path::Path;

fn render(name: &str, src: &str) -> (String, bool) {
    let (prog, diags) = loom_syntax::parse(src);
    if diags.is_empty() {
        (loom_syntax::pretty::program(&prog), false)
    } else {
        let out = diags
            .iter()
            .map(|d| d.render(name, src))
            .collect::<Vec<_>>()
            .join("");
        (out, true)
    }
}

#[test]
fn golden() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let bless = std::env::var_os("LOOM_BLESS").is_some();
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .expect("golden dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "wf"))
        .collect();
    entries.sort();
    assert!(!entries.is_empty());
    let mut failures = Vec::new();
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let src = fs::read_to_string(&path).expect("read");
        let (got, has_diags) = render(&name, &src);
        let wants_diags = name.ends_with("_err.wf");
        if has_diags != wants_diags {
            failures.push(format!(
                "--- {name}: {}\n{got}",
                if wants_diags {
                    "an `_err` golden must produce diagnostics"
                } else {
                    "a success golden must parse without diagnostics"
                }
            ));
            continue;
        }
        let out = path.with_extension("out");
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
