// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `call_out`/heartbeat scheduler (spec §5.7, OBI-33): pending future
//! calls and heartbeat subscriptions on the world thread. Metering is
//! per-call (each due call gets its own tick budget, exactly like any
//! other driver-started run, via `World::tick`'s use of `RegistryHost`);
//! this module only owns *when* a call becomes due and in what order.
//!
//! Fairness: two `call_out`s due on the same world tick run in the order
//! they were scheduled (`id` ascending), regardless of which object
//! scheduled them, so one object cannot queue itself ahead of another by
//! any means available through the efuns (`call_out` does not take a
//! priority argument).

use crate::bcvm::Value;
use crate::object::ObjectId;

/// One pending `call_out`, not yet due.
#[derive(Clone, Debug)]
pub struct PendingCall {
    pub id: u64,
    pub ob: ObjectId,
    pub due_tick: u64,
    pub func: String,
    pub args: Vec<Value>,
}

/// Pending calls and heartbeat subscriptions. Owned by `World`; advanced
/// once per world tick by `World::tick`.
#[derive(Default)]
pub struct Scheduler {
    tick: u64,
    next_id: u64,
    pending: Vec<PendingCall>,
    /// Objects with `set_heart_beat(true)`, in subscription order (also
    /// the order `World::tick` calls `heart_beat()` in).
    heartbeat: Vec<ObjectId>,
}

impl Scheduler {
    pub fn new() -> Scheduler {
        Scheduler::default()
    }

    /// The current world tick (advanced by [`Scheduler::advance`]).
    pub fn tick(&self) -> u64 {
        self.tick
    }

    /// Schedule `func(args)` on `ob` to run `delay` ticks from now (a
    /// `delay` of 0 still waits for the *next* tick, matching the
    /// traditional `call_out(f, 0)` "as soon as possible, not
    /// reentrantly" idiom). Returns an id `remove_call_out` can cancel.
    pub fn call_out(&mut self, ob: ObjectId, delay: u64, func: String, args: Vec<Value>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let due_tick = self.tick + delay.max(1);
        self.pending.push(PendingCall {
            id,
            ob,
            due_tick,
            func,
            args,
        });
        id
    }

    /// Cancel a pending call by id. `true` if it was still pending.
    pub fn remove_call_out(&mut self, id: u64) -> bool {
        let before = self.pending.len();
        self.pending.retain(|p| p.id != id);
        self.pending.len() != before
    }

    /// Drop every pending call and heartbeat subscription for `ob`
    /// (object destruction: nothing should run against a dead object).
    pub fn remove_for_object(&mut self, ob: ObjectId) {
        self.pending.retain(|p| p.ob != ob);
        self.heartbeat.retain(|o| *o != ob);
    }

    /// `set_heart_beat` efun: subscribe/unsubscribe `ob`. A no-op if
    /// already in the requested state (subscribing twice does not move
    /// `ob` later in the fairness order).
    pub fn set_heart_beat(&mut self, ob: ObjectId, on: bool) {
        if on {
            if !self.heartbeat.contains(&ob) {
                self.heartbeat.push(ob);
            }
        } else {
            self.heartbeat.retain(|o| *o != ob);
        }
    }

    /// Every object currently subscribed to the heartbeat, in
    /// subscription order.
    pub fn heartbeat_targets(&self) -> Vec<ObjectId> {
        self.heartbeat.clone()
    }

    /// Number of pending (not yet due) `call_out`s, for tests/introspection.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Advance one world tick and drain every `call_out` now due, ordered
    /// earliest-`due_tick`-first and FIFO (ascending `id`) among ties.
    pub fn advance(&mut self) -> Vec<PendingCall> {
        self.tick += 1;
        let now = self.tick;
        let (due, keep): (Vec<_>, Vec<_>) = self.pending.drain(..).partition(|p| p.due_tick <= now);
        self.pending = keep;
        let mut due = due;
        due.sort_by(|a, b| a.due_tick.cmp(&b.due_tick).then(a.id.cmp(&b.id)));
        due
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
    fn due_calls_run_in_delay_order() {
        let mut s = Scheduler::new();
        let a = s.call_out(ob(1), 3, "a".into(), vec![]);
        let b = s.call_out(ob(2), 1, "b".into(), vec![]);
        assert_eq!(s.pending_count(), 2);

        let due = s.advance(); // tick 1: only b (due tick 1) is due
        assert_eq!(due.iter().map(|p| p.id).collect::<Vec<_>>(), vec![b]);
        assert!(s.advance().is_empty()); // tick 2: nothing due yet
        let due = s.advance(); // tick 3: a (due tick 3) is due
        assert_eq!(due.iter().map(|p| p.id).collect::<Vec<_>>(), vec![a]);
        assert_eq!(s.pending_count(), 0);
    }

    #[test]
    fn same_tick_ties_break_fifo_by_scheduling_order() {
        let mut s = Scheduler::new();
        let first = s.call_out(ob(9), 1, "first".into(), vec![]);
        let second = s.call_out(ob(1), 1, "second".into(), vec![]);
        let due = s.advance();
        let ids: Vec<u64> = due.iter().map(|p| p.id).collect();
        // ob(9) scheduled first: it runs first even though ob(1)'s id is
        // numerically smaller and both are due on the same tick.
        assert_eq!(ids, vec![first, second]);
    }

    #[test]
    fn remove_call_out_cancels_a_pending_call() {
        let mut s = Scheduler::new();
        let id = s.call_out(ob(1), 3, "f".into(), vec![]);
        assert!(s.remove_call_out(id));
        assert!(!s.remove_call_out(id)); // already gone
        for _ in 0..5 {
            assert!(s.advance().is_empty());
        }
    }

    #[test]
    fn destruction_removes_pending_calls_and_heartbeat() {
        let mut s = Scheduler::new();
        let target = ob(5);
        s.call_out(target, 1, "f".into(), vec![]);
        s.call_out(ob(6), 1, "g".into(), vec![]);
        s.set_heart_beat(target, true);
        assert_eq!(s.heartbeat_targets(), vec![target]);

        s.remove_for_object(target);
        assert_eq!(s.heartbeat_targets(), Vec::<ObjectId>::new());
        let due = s.advance();
        // Only ob(6)'s call_out survives; target's was dropped on
        // destruction even though it was already scheduled.
        assert_eq!(due.iter().map(|p| p.ob).collect::<Vec<_>>(), vec![ob(6)]);
    }

    #[test]
    fn heartbeat_targets_are_stable_and_deduplicated() {
        let mut s = Scheduler::new();
        s.set_heart_beat(ob(1), true);
        s.set_heart_beat(ob(2), true);
        s.set_heart_beat(ob(1), true); // re-subscribing does not reorder
        assert_eq!(s.heartbeat_targets(), vec![ob(1), ob(2)]);
        s.set_heart_beat(ob(1), false);
        assert_eq!(s.heartbeat_targets(), vec![ob(2)]);
    }

    #[test]
    fn call_out_with_zero_delay_waits_for_the_next_tick() {
        let mut s = Scheduler::new();
        s.call_out(ob(1), 0, "f".into(), vec![]);
        assert_eq!(s.advance().len(), 1);
    }
}
