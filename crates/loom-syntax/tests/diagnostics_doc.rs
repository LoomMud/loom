// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! `docs/reference/weft/diagnostics.md` is generated from
//! [`loom_syntax::codes::REGISTRY`] so the code table can never drift from
//! what the compiler actually emits (OBI-49). Gimli owns the registry and
//! this generator; Bilbo owns the prose around it (the paragraphs above and
//! below the generated block are untouched).
//!
//! Bless with `LOOM_BLESS=1 cargo test -p loom-syntax --test diagnostics_doc`.

use std::fs;
use std::path::Path;

const START: &str = "<!-- BEGIN GENERATED CODE TABLE (OBI-49; do not hand-edit) -->";
const END: &str = "<!-- END GENERATED CODE TABLE -->";

fn range_title(prefix: &str) -> &'static str {
    match prefix {
        "00" => "`00xx` — lexer / parser",
        "01" => "`01xx` — resolver / imports / inherit",
        "02" => "`02xx` — gradual type checker",
        "03" => "`03xx` — link (efun arity, applies, unknown names)",
        "04" => "`04xx` — Phase 0 evaluator gates (\"not yet supported\")",
        "09" => "`09xx` — warnings and lints",
        _ => "other",
    }
}

/// The generated table: one section per `W##xx` range, one row per code.
fn generate_table() -> String {
    let mut by_range: Vec<(&str, Vec<(&str, &str)>)> = Vec::new();
    for (code, desc) in loom_syntax::codes::REGISTRY {
        let prefix = &code[1..3];
        match by_range.iter_mut().find(|(p, _)| *p == prefix) {
            Some((_, v)) => v.push((code, desc)),
            None => by_range.push((prefix, vec![(code, desc)])),
        }
    }
    by_range.sort_by_key(|(p, _)| p.to_string());

    let mut out = String::new();
    out.push_str(START);
    out.push('\n');
    for (prefix, mut codes) in by_range {
        codes.sort_by_key(|(c, _)| c.to_string());
        out.push_str(&format!("\n### {}\n\n", range_title(prefix)));
        out.push_str("| Code | Description |\n");
        out.push_str("| --- | --- |\n");
        for (code, desc) in codes {
            out.push_str(&format!("| `{code}` | {desc} |\n"));
        }
    }
    if !loom_syntax::codes::RETIRED.is_empty() {
        out.push_str("\n### Retired\n\n");
        out.push_str("| Code | Description |\n");
        out.push_str("| --- | --- |\n");
        for (code, desc) in loom_syntax::codes::RETIRED {
            out.push_str(&format!("| `{code}` | {desc} |\n"));
        }
    }
    out.push('\n');
    out.push_str(END);
    out
}

#[test]
fn diagnostics_doc_matches_the_registry() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/reference/weft/diagnostics.md");
    let table = generate_table();

    let existing = fs::read_to_string(&path).unwrap_or_default();
    let (before, after) = match (existing.find(START), existing.find(END)) {
        (Some(s), Some(e)) => (&existing[..s], &existing[e + END.len()..]),
        _ => ("", ""),
    };
    let want = format!("{before}{table}{after}");

    if std::env::var_os("LOOM_BLESS").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &want).unwrap();
        return;
    }
    let got = fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        want, got,
        "docs/reference/weft/diagnostics.md is out of date with the codes \
         registry; bless with `LOOM_BLESS=1 cargo test -p loom-syntax --test diagnostics_doc`"
    );
}
