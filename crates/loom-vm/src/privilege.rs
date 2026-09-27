// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The P1+ enforcement hook (spec §5.5, OBI-33): every efun call whose
//! `crate::efuns::Privilege` is gated passes through
//! [`PrivilegeCheck::check`] before it runs, with the calling object and
//! the efun identity. This crate only fixes the hook *point*; the actual
//! *policy* (which tier/caller may call which P1+ efun, `/secure`,
//! builder tiers, ...) is S1's and is a CTO-owned security-model decision.
//! Until S1 lands, [`AllowAllAudited`] allows every call and records it,
//! so the call site and the audit-log shape are already exercised and
//! swapping in the real policy later is a one-line change in
//! `crate::world::World::boot*`.

use crate::efuns::Privilege;
use crate::object::ObjectId;
use std::collections::VecDeque;

/// Entries retained by [`AllowAllAudited`]'s ring buffer (spec §5.5's
/// audit trail is for recent-activity inspection, not an unbounded
/// history; `serve` runs for the life of the server, so an
/// ever-growing `Vec` here is a memory leak).
const AUDIT_LOG_CAPACITY: usize = 1024;

/// One P1+ efun call, recorded whether or not it was allowed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    pub caller: ObjectId,
    pub efun: String,
    pub privilege: Privilege,
    pub allowed: bool,
}

/// The enforcement seam. `RegistryHost::driver_efun` calls `check` for
/// every efun with a gated (`P1`+) [`Privilege`] before running it; `Err`
/// aborts the call with the returned message (wrapped in an `RtError` by
/// the caller), `Ok` lets it proceed.
pub trait PrivilegeCheck {
    fn check(&mut self, caller: ObjectId, efun: &str, privilege: Privilege) -> Result<(), String>;

    /// Every call recorded so far (tests, ops tooling). Implementations
    /// that do not keep history may return an empty slice.
    fn log(&self) -> &[AuditEntry] {
        &[]
    }
}

/// Stub policy until S1 lands: allow every call, but append an
/// [`AuditEntry`] for each one so the hook point, the audit-log shape and
/// the tests that exercise them do not have to change again when the real
/// policy replaces this.
///
/// The log is a bounded ring buffer (last [`AUDIT_LOG_CAPACITY`] entries):
/// `serve` runs for the life of the server, so an unbounded `Vec` here
/// would be a slow memory leak. [`AllowAllAudited::total`] is a
/// monotonic count of every call ever recorded (including ones the ring
/// buffer has since evicted), for ops tooling that wants a rate rather
/// than the retained window.
#[derive(Default)]
pub struct AllowAllAudited {
    log: VecDeque<AuditEntry>,
    total: u64,
}

impl AllowAllAudited {
    pub fn new() -> AllowAllAudited {
        AllowAllAudited::default()
    }

    /// Every call ever recorded, including ones the ring buffer has since
    /// evicted (monotonic, never resets).
    pub fn total(&self) -> u64 {
        self.total
    }
}

impl PrivilegeCheck for AllowAllAudited {
    fn check(&mut self, caller: ObjectId, efun: &str, privilege: Privilege) -> Result<(), String> {
        if self.log.len() >= AUDIT_LOG_CAPACITY {
            self.log.pop_front();
        }
        self.log.push_back(AuditEntry {
            caller,
            efun: efun.to_string(),
            privilege,
            allowed: true,
        });
        self.total += 1;
        // `log()` returns `&self`'s single contiguous slice (the trait's
        // shape); keep the ring buffer laid out contiguously so that
        // slice is always the *entire* retained window, not just
        // whichever half `VecDeque` currently starts at.
        self.log.make_contiguous();
        Ok(())
    }

    fn log(&self) -> &[AuditEntry] {
        self.log.as_slices().0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ob(i: u32) -> ObjectId {
        ObjectId {
            index: i,
            generation: 0,
        }
    }

    #[test]
    fn allow_all_audited_allows_and_logs() {
        let mut p = AllowAllAudited::new();
        assert!(p.check(ob(1), "compile_object", Privilege::P1).is_ok());
        assert!(p.check(ob(2), "bind_connection", Privilege::P3).is_ok());
        assert_eq!(
            p.log(),
            vec![
                AuditEntry {
                    caller: ob(1),
                    efun: "compile_object".to_string(),
                    privilege: Privilege::P1,
                    allowed: true,
                },
                AuditEntry {
                    caller: ob(2),
                    efun: "bind_connection".to_string(),
                    privilege: Privilege::P3,
                    allowed: true,
                },
            ]
        );
    }

    #[test]
    fn allow_all_audited_log_is_a_bounded_ring_buffer() {
        let mut p = AllowAllAudited::new();
        // One more than capacity: the oldest entry must be evicted, but
        // `total()` keeps counting every call, including evicted ones.
        for i in 0..(AUDIT_LOG_CAPACITY as u32 + 1) {
            assert!(p.check(ob(i), "compile_object", Privilege::P1).is_ok());
        }
        assert_eq!(p.log().len(), AUDIT_LOG_CAPACITY);
        assert_eq!(p.total(), AUDIT_LOG_CAPACITY as u64 + 1);
        // Entry 0 (the first call) was evicted; the window starts at 1.
        assert_eq!(p.log().first().unwrap().caller, ob(1));
        assert_eq!(
            p.log().last().unwrap().caller,
            ob(AUDIT_LOG_CAPACITY as u32)
        );
    }
}
