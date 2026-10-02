// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Byte-offset ([`loom_syntax::Span`]) <-> LSP [`Position`]/[`Range`]
//! conversion. LSP positions count UTF-16 code units per line (the spec's
//! `PositionEncodingKind`; we only advertise `utf-16`, the universal
//! default every client supports without a capability negotiation), while
//! `loom-syntax` spans are UTF-8 byte offsets, so every conversion has to
//! walk the source text -- there is no constant-time formula once a file
//! has any non-ASCII character.

use loom_syntax::Span;
use lsp_types::{Position, Range};

/// 0-based `(line, UTF-16 character)` for a UTF-8 byte offset, clamped to
/// `src`'s length and snapped to the nearest preceding char boundary (a
/// span that points mid-codepoint should not happen, but a stale buffer
/// racing an edit could hand us one).
pub fn offset_to_position(src: &str, offset: u32) -> Position {
    let mut off = (offset as usize).min(src.len());
    while !src.is_char_boundary(off) {
        off -= 1;
    }
    let before = &src[..off];
    let line = before.matches('\n').count() as u32;
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let character = src[line_start..off].encode_utf16().count() as u32;
    Position { line, character }
}

/// The inverse of [`offset_to_position`]: UTF-8 byte offset of a 0-based
/// `(line, UTF-16 character)`. Clamps a position past end-of-file or
/// end-of-line to the nearest valid offset rather than panicking, since a
/// client's position can race a concurrent edit.
pub fn position_to_offset(src: &str, pos: Position) -> u32 {
    let mut line_start = 0usize;
    for _ in 0..pos.line {
        match src[line_start..].find('\n') {
            Some(i) => line_start += i + 1,
            None => return src.len() as u32, // line past EOF
        }
    }
    let line_end = src[line_start..]
        .find('\n')
        .map_or(src.len(), |i| line_start + i);
    let line = &src[line_start..line_end];
    let mut units = 0u32;
    for (byte_idx, ch) in line.char_indices() {
        if units >= pos.character {
            return (line_start + byte_idx) as u32;
        }
        units += ch.len_utf16() as u32;
    }
    line_end as u32
}

/// [`Span`] -> LSP [`Range`] over `src`.
pub fn span_to_range(src: &str, span: Span) -> Range {
    Range {
        start: offset_to_position(src, span.start),
        end: offset_to_position(src, span.end),
    }
}

/// LSP [`Position`] -> a UTF-8 byte offset into `src`, for hover/definition/
/// completion requests (which give a point, not a span).
pub fn position_to_byte_offset(src: &str, pos: Position) -> usize {
    position_to_offset(src, pos) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_round_trips() {
        let src = "fn a() {\n  let x = 1\n}\n";
        let off = src.find("x").unwrap() as u32;
        let pos = offset_to_position(src, off);
        assert_eq!(
            pos,
            Position {
                line: 1,
                character: 6
            }
        );
        assert_eq!(position_to_offset(src, pos), off);
    }

    #[test]
    fn multibyte_before_offset_shifts_utf16_character_not_byte() {
        // "é" is 2 bytes in UTF-8 but 1 UTF-16 code unit.
        let src = "let é = 1\nlet y = 2\n";
        let y_byte_off = src.find("y").unwrap() as u32;
        let pos = offset_to_position(src, y_byte_off);
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 4); // "let " is 4 UTF-16 units
        assert_eq!(position_to_offset(src, pos), y_byte_off);
    }

    #[test]
    fn astral_plane_char_counts_as_two_utf16_units() {
        // U+1F600 GRINNING FACE: 4 bytes UTF-8, 2 UTF-16 code units (surrogate pair).
        let src = "let s = \"\u{1F600}x\"\n";
        let x_byte_off = src.find('x').unwrap() as u32;
        let pos = offset_to_position(src, x_byte_off);
        assert_eq!(position_to_offset(src, pos), x_byte_off);
    }
}
