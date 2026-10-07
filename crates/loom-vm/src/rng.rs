// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `random()` (spec §5.5, OBI-85): a tiny in-tree splitmix64 PRNG, seeded
//! once at boot, so the `random` efun never needs an external `rand`
//! dependency (keeps `cargo deny`'s licence gate trivially clean).
//!
//! `LOOM_RANDOM_SEED` (parsed as `u64`) gives a deterministic seed for
//! tests/load-bot runs; without it, [`Rng::from_env_or_random`] mixes in
//! wall-clock time and `std`'s own randomized `HashMap` seed (no OS RNG
//! crate needed) so ordinary boots are not all seeded identically.

/// A splitmix64 generator (public-domain algorithm; this is a from-scratch
/// implementation, not copied from any existing driver/mudlib).
#[derive(Debug, Clone, Copy)]
pub struct Rng(u64);

impl Rng {
    pub fn seeded(seed: u64) -> Rng {
        Rng(seed)
    }

    /// The raw generator state (OBI-173 binary snapshots): opaque, just
    /// enough to resume an identical sequence via [`Rng::from_state`].
    /// Not `seed` in the `LOOM_RANDOM_SEED` sense -- it is whatever the
    /// counter has advanced to since boot.
    pub fn state(&self) -> u64 {
        self.0
    }

    /// Resume a generator from a state captured by [`Rng::state`].
    pub fn from_state(state: u64) -> Rng {
        Rng(state)
    }

    /// `LOOM_RANDOM_SEED` if set and parses as a `u64`, else a
    /// non-deterministic seed.
    pub fn from_env_or_random() -> Rng {
        let seed = std::env::var("LOOM_RANDOM_SEED")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or_else(random_seed);
        Rng::seeded(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    /// A value in `[0, n)`. Caller must have already checked `n > 0`
    /// (`random()`'s efun wrapper does; a debug assertion catches misuse
    /// from within this crate).
    pub fn gen_range(&mut self, n: i64) -> i64 {
        debug_assert!(n > 0, "gen_range: n must be > 0");
        (self.next_u64() % (n as u64)) as i64
    }
}

impl Default for Rng {
    fn default() -> Rng {
        Rng::from_env_or_random()
    }
}

fn random_seed() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    h.write_u128(nanos);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_generators_are_deterministic() {
        let mut a = Rng::seeded(42);
        let mut b = Rng::seeded(42);
        let seq_a: Vec<i64> = (0..10).map(|_| a.gen_range(1000)).collect();
        let seq_b: Vec<i64> = (0..10).map(|_| b.gen_range(1000)).collect();
        assert_eq!(seq_a, seq_b);
    }

    #[test]
    fn stays_in_range() {
        let mut r = Rng::seeded(7);
        for _ in 0..1000 {
            let v = r.gen_range(37);
            assert!((0..37).contains(&v));
        }
    }

    #[test]
    fn different_seeds_usually_diverge() {
        let mut a = Rng::seeded(1);
        let mut b = Rng::seeded(2);
        let seq_a: Vec<i64> = (0..20).map(|_| a.gen_range(1_000_000)).collect();
        let seq_b: Vec<i64> = (0..20).map(|_| b.gen_range(1_000_000)).collect();
        assert_ne!(seq_a, seq_b);
    }
}
