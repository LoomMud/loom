// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Parses the Warp `loadbot/mix.tsv` command-mix contract (R4, OBI-40; see
//! `LoomMud/warp`'s `loadbot/README.md`): `weight<TAB>step[;step...]`,
//! `#`-comments and blank lines ignored. `{peer}` and `{n}` placeholders
//! are substituted per send, not at parse time, so a peer name and a
//! random number differ on every use even within one multi-step entry.

use rand::Rng;
use rand::distributions::{Distribution, WeightedIndex};

#[derive(Debug, Clone)]
pub struct MixEntry {
    pub weight: u32,
    pub steps: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Mix {
    entries: Vec<MixEntry>,
    dist: WeightedIndex<u32>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MixError {
    Empty,
    BadLine(String),
    ZeroWeight,
}

impl std::fmt::Display for MixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MixError::Empty => write!(f, "mix file has no entries"),
            MixError::BadLine(l) => write!(f, "malformed mix line: {l:?}"),
            MixError::ZeroWeight => write!(f, "mix entry has a zero or unparsable weight"),
        }
    }
}

impl std::error::Error for MixError {}

impl Mix {
    pub fn parse(text: &str) -> Result<Self, MixError> {
        let mut entries = Vec::new();
        for raw in text.lines() {
            let line = raw.trim_end();
            if line.is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let (weight_s, steps_s) = line
                .split_once('\t')
                .ok_or_else(|| MixError::BadLine(line.to_string()))?;
            let weight: u32 = weight_s
                .trim()
                .parse()
                .map_err(|_| MixError::BadLine(line.to_string()))?;
            if weight == 0 {
                return Err(MixError::ZeroWeight);
            }
            let steps: Vec<String> = steps_s.split(';').map(|s| s.trim().to_string()).collect();
            if steps.iter().any(|s| s.is_empty()) {
                return Err(MixError::BadLine(line.to_string()));
            }
            entries.push(MixEntry { weight, steps });
        }
        if entries.is_empty() {
            return Err(MixError::Empty);
        }
        let dist = WeightedIndex::new(entries.iter().map(|e| e.weight))
            .map_err(|_| MixError::ZeroWeight)?;
        Ok(Self { entries, dist })
    }

    pub fn pick<R: Rng + ?Sized>(&self, rng: &mut R) -> &MixEntry {
        &self.entries[self.dist.sample(rng)]
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Substitutes `{peer}` (another bot's character name) and `{n}` (a random
/// 1..=999) in one mix step.
pub fn render_step<R: Rng + ?Sized>(step: &str, peer: &str, rng: &mut R) -> String {
    let n = rng.gen_range(1..=999);
    step.replace("{peer}", peer).replace("{n}", &n.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    const SAMPLE: &str = "# comment\n\n25\tlook\n8\tnorth;look;south\n";

    #[test]
    fn parses_weights_and_multi_step_entries() {
        let mix = Mix::parse(SAMPLE).unwrap();
        assert_eq!(mix.len(), 2);
        let picked = mix.pick(&mut StdRng::seed_from_u64(0));
        assert!(picked.steps.len() == 1 || picked.steps.len() == 3);
    }

    #[test]
    fn rejects_line_without_tab() {
        assert_eq!(
            Mix::parse("25 look\n").unwrap_err(),
            MixError::BadLine("25 look".to_string())
        );
    }

    #[test]
    fn rejects_zero_weight() {
        assert_eq!(Mix::parse("0\tlook\n").unwrap_err(), MixError::ZeroWeight);
    }

    #[test]
    fn rejects_empty_mix() {
        assert_eq!(
            Mix::parse("# nothing but comments\n").unwrap_err(),
            MixError::Empty
        );
    }

    #[test]
    fn substitutes_peer_and_n_independently_per_call() {
        let mut rng = StdRng::seed_from_u64(1);
        let a = render_step("tell {peer} ping {n}", "botaab", &mut rng);
        assert!(a.starts_with("tell botaab ping "));
        let n: u32 = a.rsplit(' ').next().unwrap().parse().unwrap();
        assert!((1..=999).contains(&n));
    }

    #[test]
    fn weighted_pick_favors_heavier_entries() {
        let mix = Mix::parse("1\trare\n99\tcommon\n").unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let common_count = (0..1000)
            .filter(|_| mix.pick(&mut rng).steps[0] == "common")
            .count();
        assert!(
            common_count > 900,
            "expected mostly 'common', got {common_count}"
        );
    }

    #[test]
    fn the_mix_file_shipped_by_warp_parses() {
        // A copy of `warp/loadbot/mix.tsv` kept in sync per the contract's
        // "change it here in the same PR" rule; see tests/fixtures/mix.tsv.
        let text = include_str!("../tests/fixtures/mix.tsv");
        let mix = Mix::parse(text).unwrap();
        assert!(mix.len() >= 10);
    }
}
