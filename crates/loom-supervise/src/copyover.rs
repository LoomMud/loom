// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The two-child copyover state machine (design doc "OBI-184: copyover
//! standby hand-off design", revision 2 -- CTO-approved, incl. binding
//! amendments A1-A6; see the issue's `plan` document).
//!
//! Scope of this module (a vocabulary/skeleton slice, not yet wired into
//! `loom-cli`'s real supervise loop): [`Phase`] is the explicit two-child
//! representation amendment A3 called for ("`active` and `Option<standby>`
//! plus a phase enum with a per-phase deadline"), with its valid
//! transitions encoded in [`Phase::next`] and exercised by this module's
//! own tests. It does not yet hold real `Child`/`UnixStream` handles or
//! drive an actual hand-off -- that is the next slice, built against
//! this module's transition rules so the ordering amendment A1 requires
//! (standby does no socket I/O before `Go`; the supervisor SIGKILLs an
//! unready standby *before* telling the old process to re-adopt) is
//! encoded once, here, rather than re-derived ad hoc inside `loom-cli`'s
//! event loop.
//!
//! Terminology follows the design doc: "old"/"active" is the process
//! already serving players when a copyover begins; "standby" is the
//! freshly spawned process being handed off to.

use std::time::Duration;

/// One phase of a single copyover attempt, in the order the CTO-approved
/// design doc's amended Section 2 lays out. Every phase before
/// [`Phase::Committed`] has a deadline (via [`Phase::deadline`]); a
/// timeout in any of them transitions to [`Phase::Aborting`], never a
/// silent hang (design doc, amendment A1's per-phase-timeout rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// No copyover in flight; the active process alone is serving.
    /// `VersionWatcher` detecting a change is the only thing that leaves
    /// this phase (-> [`Phase::Preparing`]).
    Idle,
    /// The standby has been spawned and handed the listener fds (the
    /// already-merged #90 handoff), but has not yet been asked to do
    /// anything copyover-specific.
    Preparing,
    /// The old process has reclaimed its connections, taken a snapshot,
    /// and sent both (plus the conn-id list, per [`crate::control::
    /// ControlMessage::HandoffOffer`]'s old-process -> supervisor ->
    /// standby ordering contract) on to the standby; waiting for the
    /// standby's own `HandoffReady` ack (standby -> supervisor) that it
    /// has loaded the snapshot and registered (not yet polled) every
    /// adopted connection.
    AwaitingStandbyReady,
    /// **The decision point** (design doc, amendment A1): the standby's
    /// `HandoffReady` arrived within the [`Phase::AwaitingStandbyReady`]
    /// deadline. From here the supervisor commits unconditionally -- an
    /// old-process failure after this point is not an abort (see this
    /// phase's own doc on [`Phase::next`]). Per N1 (CTO re-review
    /// OBI-273): [`CopyoverState::advance`] out of this phase happens
    /// *before* [`crate::control::ControlMessage::HandoffGo`] is written
    /// to the standby's socket -- the decision is recorded first, then
    /// acted on, so any failure after that point (including a short or
    /// failed write of `Go` itself) lands in a phase that is no longer
    /// abortable, never in a state where the recorded decision and the
    /// wire are out of step.
    Deciding,
    /// [`crate::control::ControlMessage::HandoffGo`] has been sent to the
    /// standby and the matching [`crate::control::ControlMessage::
    /// HandoffCommit`] to the old process, in that order; waiting for the
    /// standby's `HandoffRunning` ack (bookkeeping only -- the supervisor
    /// already treats the hand-off as committed the instant it entered
    /// this phase, per amendment A1's "ack does not gate anything
    /// further").
    AwaitingStandbyCommitted,
    /// Steady state after a successful hand-off: the former standby is
    /// now the sole active process, and the old process has been sent
    /// [`crate::control::ControlMessage::HandoffCommit`] to drop its
    /// parked connections and exit.
    Committed,
    /// A failure or timeout occurred before [`Phase::Deciding`] was
    /// reached (or occurred inside it, before the commit messages were
    /// sent). Per amendment A1, entering this phase from the supervisor's
    /// side always SIGKILLs and reaps the standby *before* it sends
    /// [`crate::control::ControlMessage::HandoffAbort`] to the old
    /// process -- order matters, and is exercised by this module's own
    /// `abort_after_the_decision_point_panics`-style tests below.
    Aborting,
}

/// Per the design doc's amendment A4, the sum of every phase's deadline
/// (through [`Phase::AwaitingStandbyCommitted`]) must stay well under the
/// acceptance target of a 5s pause, since the pause is measured from
/// stop-accept to `Go`-processed -- i.e. through [`Phase::Deciding`], not
/// all the way to [`Phase::Committed`]. [`Phase::AwaitingStandbyCommitted`]'s
/// deadline does not count against the pause budget (the old process has
/// already stopped serving regardless of how long this phase takes), but
/// is still bounded so a wedged standby doesn't leave the supervisor
/// waiting forever for bookkeeping that will never arrive.
impl Phase {
    /// Returns the maximum time this phase may remain active before the
    /// supervisor must treat it as failed and transition to
    /// [`Phase::Aborting`] (or, for phases at/after the decision point,
    /// where an old-process-side timeout no longer means abort -- see
    /// [`Phase::is_abortable`]).
    #[must_use]
    pub fn deadline(self) -> Option<Duration> {
        match self {
            Phase::Idle | Phase::Committed | Phase::Aborting => None,
            Phase::Preparing => Some(Duration::from_secs(2)),
            Phase::AwaitingStandbyReady => Some(Duration::from_secs(2)),
            Phase::Deciding => Some(Duration::from_millis(200)),
            Phase::AwaitingStandbyCommitted => Some(Duration::from_secs(5)),
        }
    }

    /// Whether a timeout in this phase means "abort the copyover and
    /// resume the old process" (true) rather than "the standby is
    /// already authoritative, let the old process go" (false). This is
    /// exactly amendment A1's "after the decision point, an old-process
    /// failure is not an abort" rule, expressed as a per-phase fact
    /// instead of being re-derived at each call site.
    #[must_use]
    pub fn is_abortable(self) -> bool {
        matches!(
            self,
            Phase::Preparing | Phase::AwaitingStandbyReady | Phase::Deciding
        )
    }

    /// The phase reached when a timeout or failure occurs in `self`.
    /// Only meaningful when [`Phase::is_abortable`] is true for `self`;
    /// per amendment A1, a failure in a non-abortable phase does not
    /// produce an `Aborting` transition at all (the standby is already
    /// committed) -- callers must check `is_abortable` first, and this
    /// function documents that by being named for the abort case only.
    #[must_use]
    pub fn on_timeout(self) -> Phase {
        debug_assert!(
            self.is_abortable(),
            "on_timeout called on a non-abortable phase ({self:?}); a timeout here is not an \
             abort per amendment A1 -- check is_abortable() first"
        );
        Phase::Aborting
    }

    /// The phase following a successful completion of `self`'s own step
    /// (e.g. the standby's `HandoffReady` arriving, or the supervisor
    /// finishing sending `HandoffGo`+commit). Returns `None` for the two
    /// terminal phases, which only ever leave via a fresh copyover
    /// attempt starting over at [`Phase::Idle`] (not a `next()` call).
    #[must_use]
    pub fn next(self) -> Option<Phase> {
        match self {
            Phase::Idle => Some(Phase::Preparing),
            Phase::Preparing => Some(Phase::AwaitingStandbyReady),
            Phase::AwaitingStandbyReady => Some(Phase::Deciding),
            Phase::Deciding => Some(Phase::AwaitingStandbyCommitted),
            Phase::AwaitingStandbyCommitted => Some(Phase::Committed),
            Phase::Committed | Phase::Aborting => None,
        }
    }
}

/// The two-child supervisor state (amendment A3): at most one standby
/// alongside the single active process, and at most one copyover attempt
/// in flight at a time -- a new version-change detection while
/// `phase != Phase::Idle` must be refused/ignored, not queued or
/// interleaved with the one already running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyoverState {
    phase: Phase,
}

impl Default for CopyoverState {
    fn default() -> Self {
        Self { phase: Phase::Idle }
    }
}

impl CopyoverState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Whether a new copyover attempt may begin -- false while one is
    /// already in flight (amendment A3's "refuse a new version-change
    /// trigger while a hand-off is already in flight").
    #[must_use]
    pub fn can_start(&self) -> bool {
        self.phase == Phase::Idle
    }

    /// Advance to the next phase per [`Phase::next`]. Panics if called
    /// from a terminal phase ([`Phase::Committed`]/[`Phase::Aborting`])
    /// -- callers must call [`Self::finish`] to return to
    /// [`Phase::Idle`] instead of advancing further.
    pub fn advance(&mut self) {
        self.phase = self
            .phase
            .next()
            .expect("advance() called from a terminal phase; call finish() instead");
    }

    /// Transition directly to [`Phase::Aborting`]. Only valid when the
    /// current phase [`Phase::is_abortable`].
    ///
    /// # Panics
    /// If the current phase is not abortable (amendment A1: a failure
    /// after the decision point is not an abort).
    pub fn abort(&mut self) {
        assert!(
            self.phase.is_abortable(),
            "abort() called from a non-abortable phase ({:?}); a failure here does not abort \
             per amendment A1",
            self.phase
        );
        self.phase = self.phase.on_timeout();
    }

    /// Return to [`Phase::Idle`] from either terminal phase, ready for
    /// the next copyover attempt. Panics if called from a non-terminal
    /// phase (a caller bug: finishing a copyover that never reached a
    /// terminal phase would silently discard an in-flight attempt).
    pub fn finish(&mut self) {
        assert!(
            matches!(self.phase, Phase::Committed | Phase::Aborting),
            "finish() called from a non-terminal phase ({:?})",
            self.phase
        );
        self.phase = Phase::Idle;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_idle_and_can_start() {
        let state = CopyoverState::new();
        assert_eq!(state.phase(), Phase::Idle);
        assert!(state.can_start());
    }

    #[test]
    fn happy_path_advances_through_every_phase_to_committed() {
        let mut state = CopyoverState::new();
        assert!(state.can_start(), "Idle must allow a copyover to start");
        let expected = [
            Phase::Preparing,
            Phase::AwaitingStandbyReady,
            Phase::Deciding,
            Phase::AwaitingStandbyCommitted,
            Phase::Committed,
        ];
        for phase in expected {
            state.advance();
            assert_eq!(state.phase(), phase);
            assert!(
                !state.can_start(),
                "must not allow a second copyover mid-flight (phase {phase:?})"
            );
        }
        state.finish();
        assert_eq!(state.phase(), Phase::Idle);
        assert!(state.can_start());
    }

    #[test]
    fn abort_from_preparing_reaches_aborting_then_idle() {
        let mut state = CopyoverState::new();
        state.advance(); // Preparing
        assert!(state.phase().is_abortable());
        state.abort();
        assert_eq!(state.phase(), Phase::Aborting);
        state.finish();
        assert_eq!(state.phase(), Phase::Idle);
    }

    #[test]
    fn abort_from_awaiting_standby_ready_reaches_aborting() {
        let mut state = CopyoverState::new();
        state.advance(); // Preparing
        state.advance(); // AwaitingStandbyReady
        assert!(state.phase().is_abortable());
        state.abort();
        assert_eq!(state.phase(), Phase::Aborting);
    }

    #[test]
    fn abort_from_deciding_reaches_aborting() {
        // The deadline for Deciding is intentionally very short (200ms)
        // but it is still, in principle, abortable per amendment A1 --
        // the decision point is reaching Deciding and sending the
        // messages, not merely entering the phase.
        let mut state = CopyoverState::new();
        state.advance(); // Preparing
        state.advance(); // AwaitingStandbyReady
        state.advance(); // Deciding
        assert!(state.phase().is_abortable());
        state.abort();
        assert_eq!(state.phase(), Phase::Aborting);
    }

    /// Amendment A1's core correctness rule, encoded as a type-level
    /// fact rather than just prose: once the supervisor has sent `Go`
    /// (i.e. advanced past `Deciding` into `AwaitingStandbyCommitted`),
    /// a failure must NOT abort -- the standby is already authoritative
    /// and an abort here would mean the old process re-adopting fds the
    /// standby may already be reading, exactly the split-brain window
    /// the design was amended to close.
    #[test]
    #[should_panic(expected = "non-abortable phase")]
    fn abort_after_the_decision_point_panics() {
        let mut state = CopyoverState::new();
        state.advance(); // Preparing
        state.advance(); // AwaitingStandbyReady
        state.advance(); // Deciding
        state.advance(); // AwaitingStandbyCommitted -- past the decision point
        assert!(!state.phase().is_abortable());
        state.abort();
    }

    #[test]
    #[should_panic(expected = "terminal phase")]
    fn advance_past_committed_panics() {
        let mut state = CopyoverState::new();
        for _ in 0..5 {
            state.advance();
        }
        assert_eq!(state.phase(), Phase::Committed);
        state.advance();
    }

    #[test]
    #[should_panic(expected = "non-terminal phase")]
    fn finish_before_a_terminal_phase_panics() {
        let mut state = CopyoverState::new();
        state.advance(); // Preparing: not terminal
        state.finish();
    }

    #[test]
    fn deadlines_through_the_decision_point_sum_under_the_five_second_pause_budget() {
        // Amendment A4: "per-phase timeouts must sum to under the 5s
        // acceptance pause... measured from stop-accept to
        // Go-processed" -- i.e. through Deciding, not
        // AwaitingStandbyCommitted (that phase's deadline is bounded for
        // a different reason: not leaving the supervisor waiting forever
        // for bookkeeping, not the player-visible pause).
        let pause_budget_phases = [
            Phase::Preparing,
            Phase::AwaitingStandbyReady,
            Phase::Deciding,
        ];
        let total: Duration = pause_budget_phases
            .iter()
            .map(|phase| {
                phase
                    .deadline()
                    .expect("every pre-decision phase has a deadline")
            })
            .sum();
        assert!(
            total < Duration::from_secs(5),
            "pre-decision-point phase deadlines sum to {total:?}, must be under the 5s budget"
        );
    }

    #[test]
    fn terminal_and_idle_phases_have_no_deadline() {
        assert_eq!(Phase::Idle.deadline(), None);
        assert_eq!(Phase::Committed.deadline(), None);
        assert_eq!(Phase::Aborting.deadline(), None);
    }
}
