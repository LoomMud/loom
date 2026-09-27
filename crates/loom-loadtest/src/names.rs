// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Bot character names, per `warp/loadbot/README.md`: "3-16 letters `a`-`z`
//! (no digits). Suggested: `bot` + base-26 of the index, e.g. `botaaa`,
//! `botaab`, ...".

/// Deterministic name for bot index `i` (0-based): `bot` followed by a
/// 3-letter base-26 counter (`aaa`, `aab`, ..., `zzz`; wraps for i >= 17576,
/// which is far past any run size we drive).
pub fn bot_name(i: usize) -> String {
    let mut n = i % (26 * 26 * 26);
    let c2 = (n % 26) as u8;
    n /= 26;
    let c1 = (n % 26) as u8;
    n /= 26;
    let c0 = (n % 26) as u8;
    format!(
        "bot{}{}{}",
        (b'a' + c0) as char,
        (b'a' + c1) as char,
        (b'a' + c2) as char
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_lowercase_letters_only_and_in_budget() {
        for i in [0, 1, 25, 26, 700, 17575] {
            let name = bot_name(i);
            assert!(name.len() >= 3 && name.len() <= 16, "{name}");
            assert!(name.chars().all(|c| c.is_ascii_lowercase()), "{name}");
        }
    }

    #[test]
    fn sequential_indices_give_distinct_names_within_budget() {
        let names: std::collections::HashSet<String> = (0..2000).map(bot_name).collect();
        assert_eq!(names.len(), 2000);
    }

    #[test]
    fn known_values_match_the_readme_examples() {
        assert_eq!(bot_name(0), "botaaa");
        assert_eq!(bot_name(1), "botaab");
    }
}
