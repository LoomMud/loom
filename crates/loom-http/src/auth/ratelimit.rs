// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Login rate limiting (OBI-200, design threat model §6.1, M-AUTH-1):
//!
//! - **Per account**: a fixed-window failure counter. 5 failures inside a
//!   15-minute window locks the account for 15 minutes. A locked account
//!   gets exactly the same response as a wrong password -- callers must
//!   never let a caller distinguish "locked" from "wrong password" (that
//!   would itself leak which usernames are real/active).
//! - **Per client IP**: a token bucket, independent of which account(s)
//!   the IP is trying. This is the layer that catches credential
//!   stuffing/spraying across many usernames from one source, which the
//!   per-account counter alone can't see.
//!
//! TOTP codes share the per-account/per-IP limiter with the password
//! check (a wrong TOTP code is `record_failure` the same as a wrong
//! password); a *missing* code (`TotpRequired`) is not a guess and does
//! not count as a failure.
//!
//! Both maps are bounded only by the number of distinct accounts/IPs
//! that have attempted a login; entries are not evicted here (OBI-200
//! follow-up: an eviction sweep if this ever shows up as a memory
//! concern -- unlikely at staff-auth scale, see the PR description).

use std::collections::HashMap;
use std::net::IpAddr;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed,
    AccountLocked,
    IpThrottled,
}

struct AccountState {
    /// Timestamps of failures still inside the window (oldest first).
    failures: Vec<Instant>,
    locked_until: Option<Instant>,
}

struct IpBucketState {
    tokens: f64,
    last_refill: Instant,
}

pub struct RateLimiter {
    accounts: Mutex<HashMap<String, AccountState>>,
    ips: Mutex<HashMap<IpAddr, IpBucketState>>,
    account_failure_limit: u32,
    account_failure_window: Duration,
    account_lockout_duration: Duration,
    ip_bucket_capacity: f64,
    ip_bucket_refill_interval: Duration,
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
        }
    }

    /// Shrink the windows for a deterministic test.
    #[cfg(test)]
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
        }
    }

    /// Check both limiters *before* doing any password work. The IP
    /// bucket is checked (and a token consumed) unconditionally so a
    /// throttled IP never gets to burn an Argon2 hash, let alone learn
    /// whether an account is locked; the account lockout is checked
    /// second so a client under its IP budget still gets the generic
    /// "invalid credentials" response for a locked account.
    pub fn check(&self, account_key: &str, ip: Option<IpAddr>) -> RateLimitDecision {
        if let Some(ip) = ip
            && !self.try_consume_ip(ip)
        {
            return RateLimitDecision::IpThrottled;
        }
        if self.is_locked(account_key) {
            return RateLimitDecision::AccountLocked;
        }
        RateLimitDecision::Allowed
    }

    fn is_locked(&self, account_key: &str) -> bool {
        let mut accounts = self.accounts.lock().unwrap();
        let Some(state) = accounts.get_mut(account_key) else {
            return false;
        };
        match state.locked_until {
            Some(until) if until > Instant::now() => true,
            Some(_) => {
                // Lockout expired: clear it and the failure history so the
                // account gets a fresh window, matching "locked for 15
                // minutes" rather than "locked forever after 5 failures".
                state.locked_until = None;
                state.failures.clear();
                false
            }
            None => false,
        }
    }

    fn try_consume_ip(&self, ip: IpAddr) -> bool {
        let mut ips = self.ips.lock().unwrap();
        let now = Instant::now();
        let state = ips.entry(ip).or_insert_with(|| IpBucketState {
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
    }

    /// Record a failed attempt (wrong password or wrong TOTP code) against
    /// `account_key`, locking it out once [`Self::account_failure_limit`]
    /// failures land inside the window.
    pub fn record_failure(&self, account_key: &str) {
        let mut accounts = self.accounts.lock().unwrap();
        let now = Instant::now();
        let state = accounts
            .entry(account_key.to_string())
            .or_insert_with(|| AccountState {
                failures: Vec::new(),
                locked_until: None,
            });

        state
            .failures
            .retain(|at| now.saturating_duration_since(*at) < self.account_failure_window);
        state.failures.push(now);

        if state.failures.len() as u32 >= self.account_failure_limit {
            state.locked_until = Some(now + self.account_lockout_duration);
        }
    }

    /// A successful login clears the account's failure history -- it
    /// should not take a 15-minute window of inactivity to forgive a few
    /// mistyped passwords once the right one lands.
    pub fn record_success(&self, account_key: &str) {
        if let Some(state) = self.accounts.lock().unwrap().get_mut(account_key) {
            state.failures.clear();
            state.locked_until = None;
        }
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
}
