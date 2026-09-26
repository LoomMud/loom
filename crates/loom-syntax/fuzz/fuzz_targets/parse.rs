// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Fuzz the whole front end: lexer + parser + diagnostic renderer + AST
//! pretty-printer. Properties: no panic, no stack overflow, no hang, and
//! every diagnostic span lies inside the source and renders.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Builder source is UTF-8 on disk; invalid bytes never reach the parser.
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };
    let (prog, diags) = loom_syntax::parse(src);
    for d in &diags {
        assert!(d.span.start <= d.span.end, "{d:?}");
        assert!(d.span.end as usize <= src.len(), "{d:?}");
        let _ = d.render("/fuzz.wf", src);
    }
    if diags.is_empty() {
        let _ = loom_syntax::pretty::program(&prog);
    }
});
