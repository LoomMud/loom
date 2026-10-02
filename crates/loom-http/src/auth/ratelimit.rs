// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Login rate limiting (OBI-200/OBI-204, design threat model §6.1,
//! M-AUTH-1):
//!
//! - **Per account**: a fixed-window failure counter. 5 failures inside a
//!   15-minute window locks the account for 15 minutes. A locked account
//!   gets exactly the same response as a wrong password -- callers must
//!   never let a caller distinguish "locked" from "wrong password" (that
//!   would itself leak which usernames are real/active). [`Self::check`]
//!   *reserves* a failure slot for the in-flight attempt before any
//!   credential work runs, so N concurrent requests against one account
//!   can't all observe "not locked yet" and slip past the limit as a
//!   group; [`Self::record_success`]/[`Self::release`] give the slot
//!   back.
//! - **Per client IP**: a token bucket, independent of which account(s)
//!   the IP is trying. This is the layer that catches credential
//!   stuffing/spraying across many usernames from one source, which the
//!   per-account counter alone can't see. An IPv6 address is keyed by its
//!   /64 prefix (the smallest block most residential/hosting allocations
//!   hand out), so a scripted attacker rotating addresses within one /64
//!   doesn't get a fresh bucket per address; IPv4 stays keyed per address
//!   (a /64-equivalent aggregation makes no sense for a single IPv4 host,
//!   and NAT already means many distinct users can share one IPv4).
//!
//! TOTP codes share the per-account/per-IP limiter with the password
//! check (a wrong TOTP code is `record_failure` the same as a wrong
//! password); a *missing* code (`TotpRequired`) is not a guess and does
//! not count as a failure.
//!
//! Both maps are bounded (OBI-204): entries that are fully expired (no
//! in-flight reservation, no lockout, no failures inside the window; or,
//! for an IP bucket, fully refilled and idle) are swept opportunistically
//! whenever a map grows past [`MAX_TRACKED_ACCOUNTS`]/
//! [`MAX_TRACKED_IPS`], and if the sweep alone doesn't bring a map back
//! under its cap (an attacker holding that many buckets open
//! concurrently), the oldest-touched entries are evicted outright so an
//! attacker who churns distinct usernames/IPs can't grow either map
//! without bound.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 5 failures / 15 min -> 15 min lockout (M-AUTH-1, exact numbers from the
/// threat model).
pub const ACCOUNT_FAILURE_LIMIT: u32 = 5;
pub const ACCOUNT_FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
pub const ACCOUNT_LOCKOUT_DURATION: Duration = Duration::from_secs(15 * 60);

/// Per-IP token bucket: 20 attempts burst, refilling at 1 token / 3 s
/// (~20/min steady state) -- generous enough for a legitimate user
/// fat-fingering a password a few times, tight enough to blunt scripted
/// spraying across many accounts from one source.
pub const IP_BUCKET_CAPACITY: f64 = 20.0;
pub const IP_BUCKET_REFILL_INTERVAL: Duration = Duration::from_secs(3);

/// Hard cap on distinct tracked accounts/IPs (OBI-204): past this, the
/// oldest-touched entries are evicted to make room rather than letting
/// an attacker who churns distinct keys grow the map without bound.
pub const MAX_TRACKED_ACCOUNTS: usize = 20_000;
pub const MAX_TRACKED_IPS: usize = 20_000;

/// Once a sweep decides eviction is needed, it evicts down to this
/// fraction of the cap rather than exactly to the cap (OBI-204 review
/// fix), so a steady trickle of new distinct keys doesn't force a fresh
/// eviction pass on almost every call once the map is full.
const EVICT_TARGET_FRACTION: f64 = 0.9;

/// The namespace [`crate::auth::uid_rate_key`] uses for a *resolved*
/// staff uid's account bucket. The hard-cap eviction in
/// [`RateLimiter::maybe_sweep_accounts`] must never remove a `uid:`-keyed
/// entry (OBI-204 review fix, must-fix 1): that key space is bounded by
/// the number of staff rows, not attacker-chosen input, so it can never
/// be the thing driving the map over its cap -- but an attacker who
/// fills the map with `user:*` keys (unresolved usernames) must not be
/// able to use the hard cap to evict, and so reset, a real staff
/// member's in-progress lockout.
pub(crate) const UID_KEY_PREFIX: &str = "uid:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed,
    AccountLocked,
    IpThrottled,
}

struct AccountState {
    /// Timestamps of *confirmed* failures still inside the window (oldest
    /// first).
    failures: Vec<Instant>,
    /// In-flight attempts that passed [`RateLimiter::check`] but haven't
    /// yet resolved to a confirmed failure/success -- counted toward the
    /// lockout threshold the same as a confirmed failure, so a burst of
    /// concurrent attempts can't all observe "not locked" before any of
    /// them finishes.
    reserved: u32,
    locked_until: Option<Instant>,
    /// Last time this entry was touched by a check/record call, for the
    /// sweep's "oldest first" eviction order.
    last_touch: Instant,
}

/// An IP bucket key: IPv4 is keyed per address, IPv6 is keyed by its /64
/// prefix (OBI-204).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IpKey {
    V4(Ipv4Addr),
    V6Prefix([u8; 8]),
}

impl IpKey {
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => IpKey::V4(v4),
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&octets[0..8]);
                IpKey::V6Prefix(prefix)
            }
        }
    }
}

struct IpBucketState {
    tokens: f64,
    last_refill: Instant,
}

pub struct RateLimiter {
    accounts: Mutex<HashMap<String, AccountState>>,
    ips: Mutex<HashMap<IpKey, IpBucketState>>,
    account_failure_limit: u32,
    account_failure_window: Duration,
    account_lockout_duration: Duration,
    ip_bucket_capacity: f64,
    ip_bucket_refill_interval: Duration,
    max_tracked_accounts: usize,
    max_tracked_ips: usize,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            accounts: Mutex::new(HashMap::new()),
            ips: Mutex::new(HashMap::new()),
            account_failure_limit: ACCOUNT_FAILURE_LIMIT,
            account_failure_window: ACCOUNT_FAILURE_WINDOW,
            account_lockout_duration: ACCOUNT_LOCKOUT_DURATION,
            ip_bucket_capacity: IP_BUCKET_CAPACITY,
            ip_bucket_refill_interval: IP_BUCKET_REFILL_INTERVAL,
            max_tracked_accounts: MAX_TRACKED_ACCOUNTS,
            max_tracked_ips: MAX_TRACKED_IPS,
        }
    }

    /// Shrink the windows (and, for a map-bound test, the caps) for a
    /// deterministic test.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn with_test_tuning(
        account_failure_limit: u32,
        account_failure_window: Duration,
        account_lockout_duration: Duration,
        ip_bucket_capacity: f64,
        ip_bucket_refill_interval: Duration,
    ) -> Self {
        Self {
            accounts: Mutex::new(HashMap::new()),
            ips: Mutex::new(HashMap::new()),
            account_failure_limit,
            account_failure_window,
            account_lockout_duration,
            ip_bucket_capacity,
            ip_bucket_refill_interval,
            max_tracked_accounts: MAX_TRACKED_ACCOUNTS,
            max_tracked_ips: MAX_TRACKED_IPS,
        }
    }

    /// Like [`Self::with_test_tuning`] but with the map caps shrunk too,
    /// for a deterministic "the maps are bounded" test.
    #[cfg(test)]
    pub fn with_test_caps(mut self, max_tracked_accounts: usize, max_tracked_ips: usize) -> Self {
        self.max_tracked_accounts = max_tracked_accounts;
        self.max_tracked_ips = max_tracked_ips;
        self
    }

    /// Check both limiters *before* doing any password work. The IP
    /// bucket is checked (and a token consumed) unconditionally so a
    /// throttled IP never gets to burn an Argon2 hash, let alone learn
    /// whether an account is locked; the account lockout is checked
    /// second so a client under its IP budget still gets the generic
    /// "invalid credentials" response for a locked account.
    ///
    /// On [`RateLimitDecision::Allowed`], a failure slot for
    /// `account_key` has been reserved (OBI-204): the caller must follow
    /// up with exactly one of [`Self::record_failure`],
    /// [`Self::record_success`], or [`Self::release`] once the attempt
    /// resolves, to give the slot back (a guess that turned out wrong, a
    /// login that succeeded, or neither -- e.g. the directory itself
    /// failed -- respectively).
    pub fn check(&self, account_key: &str, ip: Option<IpAddr>) -> RateLimitDecision {
        if let Some(ip) = ip
            && !self.try_consume_ip(ip)
        {
            return RateLimitDecision::IpThrottled;
        }
        if self.check_and_reserve_account(account_key) {
            return RateLimitDecision::AccountLocked;
        }
        RateLimitDecision::Allowed
    }

    /// Just the IP-bucket half of [`Self::check`] (OBI-204 review fix):
    /// for a caller like `login` that still has to resolve a username to
    /// a uid (a DB round trip) before it knows the account key to
    /// reserve, checking the IP bucket first means a throttled IP is
    /// refused before that lookup ever runs, instead of after.
    pub fn check_ip(&self, ip: IpAddr) -> RateLimitDecision {
        if self.try_consume_ip(ip) {
            RateLimitDecision::Allowed
        } else {
            RateLimitDecision::IpThrottled
        }
    }

    /// Just the account-reservation half of [`Self::check`], for a caller
    /// that already separately checked [`Self::check_ip`]. Same
    /// release/success/failure contract as [`Self::check`].
    pub fn check_account(&self, account_key: &str) -> RateLimitDecision {
        if self.check_and_reserve_account(account_key) {
            RateLimitDecision::AccountLocked
        } else {
            RateLimitDecision::Allowed
        }
    }

    /// Returns `true` if `account_key` is (or just became, via this
    /// reservation) locked. Always creates/touches the map entry --
    /// [`Self::maybe_sweep_accounts`] (run *after* the insert, so an
    /// over-cap map is brought back down the same call that tipped it
    /// over) is what keeps that bounded.
    fn check_and_reserve_account(&self, account_key: &str) -> bool {
        let mut accounts = self.accounts.lock().unwrap();
        let now = Instant::now();
        let locked = {
            let state = accounts
                .entry(account_key.to_string())
                .or_insert_with(|| AccountState {
                    failures: Vec::new(),
                    reserved: 0,
                    locked_until: None,
                    last_touch: now,
                });
            state.last_touch = now;

            state
                .failures
                .retain(|at| now.saturating_duration_since(*at) < self.account_failure_window);

            match state.locked_until {
                Some(until) if until > now => true,
                Some(_) => {
                    // Lockout expired: clear it and the failure history so
                    // the account gets a fresh window, matching "locked for
                    // 15 minutes" rather than "locked forever after 5
                    // failures".
                    state.locked_until = None;
                    state.failures.clear();
                    state.reserved = 0;
                    state.reserved += 1;
                    if (state.failures.len() as u32 + state.reserved) >= self.account_failure_limit
                    {
                        state.locked_until = Some(now + self.account_lockout_duration);
                    }
                    false
                }
                None => {
                    state.reserved += 1;
                    if (state.failures.len() as u32 + state.reserved) >= self.account_failure_limit
                    {
                        state.locked_until = Some(now + self.account_lockout_duration);
                    }
                    false
                }
            }
        };
        Self::maybe_sweep_accounts(
            &mut accounts,
            self.max_tracked_accounts,
            self.account_failure_window,
        );
        locked
    }

    fn try_consume_ip(&self, ip: IpAddr) -> bool {
        let mut ips = self.ips.lock().unwrap();
        let key = IpKey::of(ip);
        let now = Instant::now();
        let allowed = {
            let state = ips.entry(key).or_insert_with(|| IpBucketState {
                tokens: self.ip_bucket_capacity,
                last_refill: now,
            });

            let elapsed = now.saturating_duration_since(state.last_refill);
            let refill_steps = elapsed.as_secs_f64() / self.ip_bucket_refill_interval.as_secs_f64();
            if refill_steps > 0.0 {
                state.tokens = (state.tokens + refill_steps).min(self.ip_bucket_capacity);
                state.last_refill = now;
            }

            if state.tokens >= 1.0 {
                state.tokens -= 1.0;
                true
            } else {
                false
            }
        };
        Self::maybe_sweep_ips(
            &mut ips,
            self.max_tracked_ips,
            self.ip_bucket_capacity,
            self.ip_bucket_refill_interval,
        );
        allowed
    }

    /// Record a failed attempt (wrong password or wrong TOTP code) against
    /// `account_key`, locking it out once [`Self::account_failure_limit`]
    /// failures land inside the window. Converts this attempt's
    /// reservation (if any -- this also works correctly if called without
    /// a prior [`Self::check`], e.g. in a unit test) into a confirmed
    /// failure.
    pub fn record_failure(&self, account_key: &str) {
        let mut accounts = self.accounts.lock().unwrap();
        let now = Instant::now();
        let state = accounts
            .entry(account_key.to_string())
            .or_insert_with(|| AccountState {
                failures: Vec::new(),
                reserved: 0,
                locked_until: None,
                last_touch: now,
            });
        state.last_touch = now;
        state.reserved = state.reserved.saturating_sub(1);

        state
            .failures
            .retain(|at| now.saturating_duration_since(*at) < self.account_failure_window);
        state.failures.push(now);

        if (state.failures.len() as u32 + state.reserved) >= self.account_failure_limit {
            state.locked_until = Some(now + self.account_lockout_duration);
        }
    }

    /// A successful login clears the account's failure history -- it
    /// should not take a 15-minute window of inactivity to forgive a few
    /// mistyped passwords once the right one lands. Also releases this
    /// attempt's reservation (if any).
    pub fn record_success(&self, account_key: &str) {
        if let Some(state) = self.accounts.lock().unwrap().get_mut(account_key) {
            state.reserved = state.reserved.saturating_sub(1);
            state.failures.clear();
            state.locked_until = None;
            state.last_touch = Instant::now();
        }
    }

    /// Give back a reservation from [`Self::check`] without recording a
    /// failure or a success -- for an attempt that resolved to neither
    /// (e.g. the directory itself failed). Not releasing this would leak
    /// a permanently-counted "phantom failure" toward the lockout.
    pub fn release(&self, account_key: &str) {
        if let Some(state) = self.accounts.lock().unwrap().get_mut(account_key) {
            state.reserved = state.reserved.saturating_sub(1);
        }
    }

    /// If `accounts` has grown past `cap`, sweep entries that are fully
    /// idle (no reservation, no lockout, no failures in-window), then --
    /// if that alone wasn't enough -- evict the oldest-touched remaining
    /// *non-`uid:`* entries until back down to ~90% of `cap` (OBI-204,
    /// review fix: evict to a margin below the cap rather than exactly to
    /// it, and review must-fix 1: a `uid:`-keyed entry is a resolved
    /// staff member's bucket, bounded by the number of staff rows -- it
    /// is never what pushes this map over `cap`, and evicting it would
    /// let an attacker who floods the map with `user:*` keys erase a real
    /// account's in-progress lockout). An attacker who can only hold a
    /// bounded number of *concurrently in-flight* reservations open still
    /// can't grow this map without bound by churning distinct usernames.
    fn maybe_sweep_accounts(
        accounts: &mut HashMap<String, AccountState>,
        cap: usize,
        failure_window: Duration,
    ) {
        if accounts.len() <= cap {
            return;
        }
        let now = Instant::now();
        accounts.retain(|key, state| {
            if key.starts_with(UID_KEY_PREFIX) {
                return true;
            }
            state
                .failures
                .retain(|at| now.saturating_duration_since(*at) < failure_window);
            let locked = matches!(state.locked_until, Some(until) if until > now);
            state.reserved > 0 || locked || !state.failures.is_empty()
        });
        if accounts.len() > cap {
            let target = Self::evict_target(cap);
            Self::evict_oldest(
                accounts,
                target,
                |key, _| !key.starts_with(UID_KEY_PREFIX),
                |_, state| state.last_touch,
            );
        }
    }

    /// Same idea as [`Self::maybe_sweep_accounts`] for the IP bucket map:
    /// a bucket that's back at full capacity and hasn't been touched in a
    /// while isn't throttling anything and can be forgotten. IP keys
    /// carry no privileged namespace to protect, so every entry is
    /// eligible for eviction.
    fn maybe_sweep_ips(
        ips: &mut HashMap<IpKey, IpBucketState>,
        cap: usize,
        bucket_capacity: f64,
        refill_interval: Duration,
    ) {
        if ips.len() <= cap {
            return;
        }
        let now = Instant::now();
        ips.retain(|_, state| {
            let elapsed = now.saturating_duration_since(state.last_refill);
            let refill_steps = elapsed.as_secs_f64() / refill_interval.as_secs_f64();
            let projected_tokens = (state.tokens + refill_steps).min(bucket_capacity);
            // Keep only buckets that are still short of full (i.e. an
            // attempt happened recently enough to still matter).
            projected_tokens < bucket_capacity
        });
        if ips.len() > cap {
            let target = Self::evict_target(cap);
            Self::evict_oldest(ips, target, |_, _| true, |_, state| state.last_refill);
        }
    }

    /// ~90% of `cap` (OBI-204 review fix), floored at `cap` itself so a
    /// tiny test cap never computes a target of 0 and evicts everything.
    fn evict_target(cap: usize) -> usize {
        ((cap as f64 * EVICT_TARGET_FRACTION) as usize).min(cap)
    }

    /// Evict the oldest-touched (by `touched_at`) entries matching
    /// `evictable` from `map` until it's down to `target`, breaking a
    /// hard cap when the idle sweep alone didn't bring it under. Entries
    /// for which `evictable` returns `false` (e.g. a protected `uid:` key,
    /// OBI-204 must-fix 1) are never removed, even if that means `map`
    /// stays above `target`.
    fn evict_oldest<K: std::hash::Hash + Eq + Clone, V>(
        map: &mut HashMap<K, V>,
        target: usize,
        evictable: impl Fn(&K, &V) -> bool,
        touched_at: impl Fn(&K, &V) -> Instant,
    ) {
        if map.len() <= target {
            return;
        }
        let overflow = map.len() - target;
        let mut by_age: Vec<(K, Instant)> = map
            .iter()
            .filter(|(k, v)| evictable(k, v))
            .map(|(k, v)| (k.clone(), touched_at(k, v)))
            .collect();
        by_age.sort_by_key(|(_, at)| *at);
        for (key, _) in by_age.into_iter().take(overflow) {
            map.remove(&key);
        }
    }

    /// Force a sweep of both maps regardless of their current size, for
    /// tests (and available for a caller that wants to run one on a
    /// timer rather than only opportunistically on the hot path).
    #[cfg(test)]
    pub fn sweep_for_test(&self) {
        let mut accounts = self.accounts.lock().unwrap();
        Self::maybe_sweep_accounts(&mut accounts, 0, self.account_failure_window);
        let mut ips = self.ips.lock().unwrap();
        Self::maybe_sweep_ips(
            &mut ips,
            0,
            self.ip_bucket_capacity,
            self.ip_bucket_refill_interval,
        );
    }

    #[cfg(test)]
    pub fn tracked_account_count(&self) -> usize {
        self.accounts.lock().unwrap().len()
    }

    #[cfg(test)]
    pub fn tracked_ip_count(&self) -> usize {
        self.ips.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sixth_failure_locks_the_account() {
        let limiter = RateLimiter::new();
        for _ in 0..5 {
            assert_eq!(limiter.check("frodo", None), RateLimitDecision::Allowed);
            limiter.record_failure("frodo");
        }
        // The account is now locked -- the 6th attempt (correct password
        // or not) is refused before any credential check runs.
        assert_eq!(
            limiter.check("frodo", None),
            RateLimitDecision::AccountLocked
        );
    }

    #[test]
    fn a_success_before_the_limit_clears_the_counter() {
        let limiter = RateLimiter::new();
        for _ in 0..4 {
            limiter.record_failure("sam");
        }
        limiter.record_success("sam");
        assert_eq!(limiter.check("sam", None), RateLimitDecision::Allowed);
        limiter.record_success("sam");
        // 4 more failures (not 1) are needed to lock again post-reset.
        for _ in 0..4 {
            limiter.record_failure("sam");
        }
        assert_eq!(limiter.check("sam", None), RateLimitDecision::Allowed);
        limiter.record_failure("sam");
        assert_eq!(limiter.check("sam", None), RateLimitDecision::AccountLocked);
    }

    #[test]
    fn lockout_expires_after_its_duration() {
        let limiter = RateLimiter::with_test_tuning(
            5,
            Duration::from_secs(900),
            Duration::from_millis(20),
            IP_BUCKET_CAPACITY,
            IP_BUCKET_REFILL_INTERVAL,
        );
        for _ in 0..5 {
            limiter.record_failure("pippin");
        }
        assert_eq!(
            limiter.check("pippin", None),
            RateLimitDecision::AccountLocked
        );
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(limiter.check("pippin", None), RateLimitDecision::Allowed);
        limiter.record_success("pippin");
    }

    #[test]
    fn ip_bucket_throttles_independently_of_the_account() {
        let limiter = RateLimiter::with_test_tuning(
            ACCOUNT_FAILURE_LIMIT,
            ACCOUNT_FAILURE_WINDOW,
            ACCOUNT_LOCKOUT_DURATION,
            3.0,
            Duration::from_secs(3600),
        );
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        // Three different (nonexistent) usernames from the same IP: the
        // per-account counter never sees 5 failures for any one of them,
        // but the shared IP bucket should still run dry.
        assert_eq!(limiter.check("a", Some(ip)), RateLimitDecision::Allowed);
        assert_eq!(limiter.check("b", Some(ip)), RateLimitDecision::Allowed);
        assert_eq!(limiter.check("c", Some(ip)), RateLimitDecision::Allowed);
        assert_eq!(limiter.check("d", Some(ip)), RateLimitDecision::IpThrottled);
        // A different IP is unaffected.
        let other: IpAddr = "203.0.113.8".parse().unwrap();
        assert_eq!(limiter.check("a", Some(other)), RateLimitDecision::Allowed);
    }

    #[test]
    fn ip_bucket_refills_over_time() {
        let limiter = RateLimiter::with_test_tuning(
            ACCOUNT_FAILURE_LIMIT,
            ACCOUNT_FAILURE_WINDOW,
            ACCOUNT_LOCKOUT_DURATION,
            1.0,
            Duration::from_millis(20),
        );
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        assert_eq!(limiter.check("a", Some(ip)), RateLimitDecision::Allowed);
        assert_eq!(limiter.check("a", Some(ip)), RateLimitDecision::IpThrottled);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(limiter.check("a", Some(ip)), RateLimitDecision::Allowed);
    }

    /// OBI-204 acceptance: two IPv6 addresses in the same /64 share a
    /// bucket.
    #[test]
    fn ipv6_addresses_in_the_same_slash_64_share_a_bucket() {
        let limiter = RateLimiter::with_test_tuning(
            ACCOUNT_FAILURE_LIMIT,
            ACCOUNT_FAILURE_WINDOW,
            ACCOUNT_LOCKOUT_DURATION,
            2.0,
            Duration::from_secs(3600),
        );
        let first: IpAddr = "2001:db8:dead:beef::1".parse().unwrap();
        let second: IpAddr = "2001:db8:dead:beef:ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(limiter.check("a", Some(first)), RateLimitDecision::Allowed);
        assert_eq!(limiter.check("b", Some(second)), RateLimitDecision::Allowed);
        // Capacity of 2.0 is now spent across the shared /64 bucket.
        assert_eq!(
            limiter.check("c", Some(first)),
            RateLimitDecision::IpThrottled
        );

        // A third address outside that /64 gets its own, fresh bucket.
        let outside: IpAddr = "2001:db8:dead:beee:ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(
            limiter.check("d", Some(outside)),
            RateLimitDecision::Allowed
        );
    }

    /// OBI-204 acceptance: the maps shrink after a sweep.
    #[test]
    fn sweep_shrinks_the_maps() {
        let limiter = RateLimiter::with_test_tuning(
            ACCOUNT_FAILURE_LIMIT,
            Duration::from_millis(10),
            Duration::from_millis(10),
            5.0,
            Duration::from_millis(1),
        );
        for i in 0..50 {
            let ip: IpAddr = format!("203.0.113.{}", i % 255).parse().unwrap();
            let user = format!("attacker{i}");
            limiter.check(&user, Some(ip));
            // Resolve the reservation so the account entry is fully idle
            // once the failure window has elapsed.
            limiter.record_success(&user);
        }
        assert_eq!(limiter.tracked_account_count(), 50);
        assert_eq!(limiter.tracked_ip_count(), 50);

        // Let the failure window (accounts) and the refill interval (ips,
        // 5 tokens * 1ms << this sleep) fully lapse.
        std::thread::sleep(Duration::from_millis(50));
        limiter.sweep_for_test();

        assert_eq!(limiter.tracked_account_count(), 0);
        assert_eq!(limiter.tracked_ip_count(), 0);
    }

    /// OBI-204 review fix: once a hard-cap eviction runs, it evicts down
    /// to ~90% of the cap rather than exactly to it, so a steady trickle
    /// of one-off new keys doesn't force a fresh eviction pass on almost
    /// every subsequent call.
    #[test]
    fn hard_cap_eviction_targets_ninety_percent_of_the_cap() {
        let limiter = RateLimiter::with_test_tuning(
            ACCOUNT_FAILURE_LIMIT,
            ACCOUNT_FAILURE_WINDOW,
            ACCOUNT_LOCKOUT_DURATION,
            IP_BUCKET_CAPACITY,
            IP_BUCKET_REFILL_INTERVAL,
        )
        .with_test_caps(100, 100);

        // Fill the map to exactly the cap, then add one more entry --
        // the single insert that tips it over triggers one eviction pass.
        for i in 0..101 {
            let user = format!("user{i}");
            limiter.check(&user, None);
            // Leave every reservation in place so nothing is idle-swept;
            // only the hard cap can be bringing this back down.
        }
        // That one eviction pass should have brought it down to ~90
        // (`EVICT_TARGET_FRACTION`), not merely back to 100.
        assert!(limiter.tracked_account_count() <= 90);
        assert!(limiter.tracked_account_count() >= 80);
    }

    /// OBI-204 acceptance (hard cap): once the account map is over its
    /// cap, further distinct accounts still get tracked -- the oldest
    /// entries are evicted to make room rather than growing forever.
    #[test]
    fn hard_cap_evicts_the_oldest_accounts_once_full() {
        let limiter = RateLimiter::with_test_tuning(
            ACCOUNT_FAILURE_LIMIT,
            ACCOUNT_FAILURE_WINDOW,
            ACCOUNT_LOCKOUT_DURATION,
            IP_BUCKET_CAPACITY,
            IP_BUCKET_REFILL_INTERVAL,
        )
        .with_test_caps(10, 10);

        for i in 0..25 {
            let user = format!("user{i}");
            limiter.check(&user, None);
            // Leave the reservation in place (don't release it) so the
            // entry can't be swept as idle -- this exercises the hard-cap
            // eviction path, not the idle sweep.
        }
        assert!(limiter.tracked_account_count() <= 10);
    }

    /// OBI-204 review must-fix 1: the hard-cap eviction must never remove
    /// a `uid:`-keyed entry (a resolved staff member's bucket, bounded by
    /// the number of staff rows), even once an attacker floods the map
    /// with enough `user:*` (unresolved-username) keys to blow well past
    /// the cap -- otherwise an attacker could use the hard cap itself to
    /// erase a real staff member's in-progress lockout.
    #[test]
    fn hard_cap_eviction_never_removes_a_uid_keyed_account() {
        let limiter = RateLimiter::with_test_tuning(
            ACCOUNT_FAILURE_LIMIT,
            ACCOUNT_FAILURE_WINDOW,
            ACCOUNT_LOCKOUT_DURATION,
            IP_BUCKET_CAPACITY,
            IP_BUCKET_REFILL_INTERVAL,
        )
        .with_test_caps(10, 10);

        // A real staff member, locked out (5 confirmed failures), well
        // before the attacker shows up.
        let uid_key = format!("{UID_KEY_PREFIX}gandalf");
        for _ in 0..5 {
            limiter.record_failure(&uid_key);
        }
        assert_eq!(
            limiter.check(&uid_key, None),
            RateLimitDecision::AccountLocked
        );

        // An attacker floods the map with far more than the cap's worth
        // of distinct, never-resolved usernames, each left with an
        // in-flight reservation so none of them can be swept as idle --
        // exactly the hard-cap eviction path.
        for i in 0..50 {
            let user = format!("attacker{i}");
            limiter.check(&user, None);
        }

        // The map was forced over its cap, so the hard cap evicted *some*
        // entries -- but the staff member's `uid:`-keyed lockout must
        // still be in force; it was never a candidate for eviction.
        assert_eq!(
            limiter.check(&uid_key, None),
            RateLimitDecision::AccountLocked
        );
    }
}
