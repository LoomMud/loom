// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzz loom-lsp's request handlers directly against arbitrary source
//! text and cursor offsets (spec `docs/threat-model-phase2.md` M-LSP-4:
//! "add `loom-lsp` request fuzzing to the nightly fuzz job"). Properties:
//! no panic, no hang (libFuzzer's own timeout catches that), and any span
//! a hit returns lies inside the source it came from.
//!
//! Scope note: this fuzzes the pure analysis functions (`hover`,
//! `definition`, `completion`) directly, not the JSON-RPC transport --
//! `serde_json`'s own fuzzing covers malformed wire bytes, and
//! `loom_syntax::parse`'s own fuzz target (`loom-syntax/fuzz`) already
//! covers the parser `hover`/`definition` call into first. What's unique
//! to `loom-lsp` is walking the typed HIR at an arbitrary byte offset,
//! which is what this target actually exercises.

#![no_main]

use libfuzzer_sys::fuzz_target;
use loom_lsp::{completion, definition, hover};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let (offset_bytes, rest) = data.split_at(4);
    let raw_offset = u32::from_le_bytes([offset_bytes[0], offset_bytes[1], offset_bytes[2], offset_bytes[3]]);
    let Ok(src) = std::str::from_utf8(rest) else {
        return;
    };

    let (ast_prog, diags) = loom_syntax::parse(src);
    let offset = raw_offset % (src.len() as u32 + 1);

    let checked = if diags.is_empty() {
        loom_compiler::check_program("/fuzz", &ast_prog, Vec::new(), Vec::new()).ok()
    } else {
        None
    };
    let checked_ref = checked.as_ref().map(|c| (&c.hir, &c.info));

    if let Some(r) = hover::hover(&ast_prog, checked_ref, offset) {
        assert!(r.span.start <= r.span.end, "{:?}", r.span);
        assert!((r.span.end as usize) <= src.len(), "{:?}", r.span);
    }
    if let Some((hir, info)) = checked_ref {
        let _ = definition::definition_for_identifier(hir, info, offset);
    }
    let _ = definition::definition_for_path(&ast_prog, offset);
    let _ = completion::all_items(checked.as_ref().map(|c| &c.info));
});
