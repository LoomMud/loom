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
//!
//! **OBI-137 S3: counters, not scans.** `pending_count_for_obj`/
//! `pending_count_for_quota_uid` (`max_callouts_obj`/`max_callouts_uid`)
//! and the per-owner heartbeat count `check_heartbeat_quota` needs
//! (`max_heartbeats`) used to be an `O(pending)`/`O(heartbeat)` scan on
//! every `call_out`/`set_heart_beat` call. [`Scheduler`] now keeps a
//! running `HashMap` count for each, maintained on every mutation
//! ([`Scheduler::call_out`], [`Scheduler::remove_call_out`],
//! [`Scheduler::advance`] draining a due call, [`Scheduler::set_heart_beat`]
//! and [`Scheduler::remove_for_object`] on destruct), so every quota check
//! is an `O(1)` `HashMap` lookup instead.

use std::collections::{HashMap, VecDeque};

use crate::bcvm::Value;
use crate::object::ObjectId;
use crate::security::{GuardSet, Sym};

/// One pending `call_out`, not yet due.
#[derive(Clone, Debug)]
pub struct PendingCall {
    pub id: u64,
    pub ob: ObjectId,
    pub due_tick: u64,
    pub func: String,
    pub args: Vec<Value>,
    /// The guard set at the moment `call_out("name", …)` was called
    /// (OBI-35 D-S1.6/D-S1.7): `World::tick` runs this call from a cut
    /// whose guard is exactly this set, not `[ob.euid]` (that is only for
    /// heartbeats, D-S1.2 rule 5) — a call_out is self-scoped (D-S1.4
    /// kind 2), so `ob`'s own euid is already in here from the frame that
    /// called `call_out`.
    pub guard: GuardSet,
    /// The quota root uid this execution charges ticks/memory against
    /// (OBI-35 D-S1.6): the uid of the lowest-tier principal in `guard` at
    /// schedule time (with no roles/tier snapshot yet, S2/OBI-36, the
    /// calling object's own uid).
    pub quota_uid: Sym,
}

/// Bump `map[key]` by one.
fn bump<K: std::hash::Hash + Eq>(map: &mut HashMap<K, u64>, key: K) {
    *map.entry(key).or_insert(0) += 1;
}

/// Drop `map[key]` by one, removing the entry once it hits zero (so an
/// idle uid/object does not leave a permanent zero-valued entry behind —
/// this map is meant to stay bounded by "currently pending", not by
/// "every uid/object ever seen").
fn unbump<K: std::hash::Hash + Eq>(map: &mut HashMap<K, u64>, key: K) {
    if let Some(count) = map.get_mut(&key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            map.remove(&key);
        }
    }
}

/// Pending calls and heartbeat subscriptions. Owned by `World`; advanced
/// once per world tick by `World::tick`.
#[derive(Default)]
pub struct Scheduler {
    tick: u64,
    next_id: u64,
    pending: Vec<PendingCall>,
    /// `pending_count_for_obj` (OBI-137 S3), kept in lockstep with
    /// `pending` by every insertion/removal path (`call_out`,
    /// `remove_call_out`, `advance`'s drain, `defer`'s requeue -- a no-op
    /// there, since the call stays pending -- and `remove_for_object`).
    pending_by_obj: HashMap<ObjectId, u64>,
    /// `pending_count_for_quota_uid` (OBI-137 S3), same discipline as
    /// `pending_by_obj`.
    pending_by_quota_uid: HashMap<Sym, u64>,
    /// Objects with `set_heart_beat(true)`, in subscription order (also
    /// the order `World::tick` calls `heart_beat()` in).
    heartbeat: Vec<ObjectId>,
    /// Each currently-subscribed object's owner uid, as of the moment it
    /// subscribed (OBI-137 S3): what `remove_for_object`/`set_heart_beat`'s
    /// unsubscribe path decrements `heartbeat_by_owner` against, so
    /// unsubscribing/destructing never needs the registry to look the
    /// owner back up (it may already be gone, on destruct).
    heartbeat_owner: HashMap<ObjectId, Sym>,
    /// `check_heartbeat_quota`'s per-owner heartbeat count (OBI-137 S3),
    /// kept in lockstep with `heartbeat`/`heartbeat_owner`.
    heartbeat_by_owner: HashMap<Sym, u64>,
    /// `upgrade_all(path)` efun (OBI-89, eager mode): object ids still on
    /// a stale program for a path, queued by `RegistryHost::driver_efun`
    /// and drained a bounded batch per world tick by `World::tick` —
    /// spread across ticks rather than migrated all at once, so a
    /// builder-triggered mass upgrade cannot block the tick queue (spec
    /// §7.2/§7.3: "upgrade_all spread across ticks, bounded per-tick
    /// budget").
    eager_upgrades: VecDeque<(ObjectId, String)>,
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
    /// reentrantly" idiom). `guard`/`quota_uid` are captured by the caller
    /// at the moment of this call (OBI-35 D-S1.6) via `Host::current_guard`
    /// / `Host::current_uid`. Returns an id `remove_call_out` can cancel.
    #[allow(clippy::too_many_arguments)]
    pub fn call_out(
        &mut self,
        ob: ObjectId,
        delay: u64,
        func: String,
        args: Vec<Value>,
        guard: GuardSet,
        quota_uid: Sym,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let due_tick = self.tick + delay.max(1);
        self.insert_pending(PendingCall {
            id,
            ob,
            due_tick,
            func,
            args,
            guard,
            quota_uid,
        });
        id
    }

    /// Re-queue `call` (still carrying its *original* `id`) one tick out
    /// (OBI-137 S2: `tick_share_per_min` deferral). Unlike scheduling a
    /// brand new `call_out`, this never bumps `next_id`/the counters (the
    /// call was already pending and stays pending), and crucially keeps
    /// its original `id` -- so it keeps its place in `advance`'s
    /// same-tick FIFO tie-break (`id` ascending) relative to any other
    /// call scheduled after it originally, even though it is only being
    /// re-inserted now.
    pub fn defer(&mut self, mut call: PendingCall) {
        call.due_tick = self.tick + 1;
        self.pending.push(call);
        // Note: no `bump()` here -- `advance()` already removed this
        // call's counters when it drained it as due, so pushing it back
        // as still-pending must restore them, not add on top of a stale
        // still-counted entry.
        self.restore_pending_counts_for_last();
    }

    fn restore_pending_counts_for_last(&mut self) {
        let last = self.pending.last().expect("just pushed");
        bump(&mut self.pending_by_obj, last.ob);
        bump(&mut self.pending_by_quota_uid, last.quota_uid);
    }

    fn insert_pending(&mut self, call: PendingCall) {
        bump(&mut self.pending_by_obj, call.ob);
        bump(&mut self.pending_by_quota_uid, call.quota_uid);
        self.pending.push(call);
    }

    /// Cancel a pending call by id, but only if it belongs to `caller`
    /// (spec: an object may only cancel its own `call_out`s; ids are
    /// sequential, so without this check any object could cancel
    /// another's pending calls by guessing a nearby id). Returns `false`
    /// both when the id is unknown and when it belongs to someone else,
    /// so a caller cannot distinguish "not mine" from "already gone" and
    /// cannot use this to probe other objects' ids.
    pub fn remove_call_out(&mut self, caller: ObjectId, id: u64) -> bool {
        let before = self.pending.len();
        let mut removed_quota_uid = None;
        self.pending.retain(|p| {
            let hit = p.id == id && p.ob == caller;
            if hit {
                removed_quota_uid = Some(p.quota_uid);
            }
            !hit
        });
        if let Some(quota_uid) = removed_quota_uid {
            unbump(&mut self.pending_by_obj, caller);
            unbump(&mut self.pending_by_quota_uid, quota_uid);
        }
        self.pending.len() != before
    }

    /// Drop every pending call and heartbeat subscription for `ob`
    /// (object destruction: nothing should run against a dead object).
    pub fn remove_for_object(&mut self, ob: ObjectId) {
        let (removed, kept): (Vec<_>, Vec<_>) = self.pending.drain(..).partition(|p| p.ob == ob);
        self.pending = kept;
        for p in removed {
            unbump(&mut self.pending_by_obj, p.ob);
            unbump(&mut self.pending_by_quota_uid, p.quota_uid);
        }
        self.heartbeat.retain(|o| *o != ob);
        if let Some(owner) = self.heartbeat_owner.remove(&ob) {
            unbump(&mut self.heartbeat_by_owner, owner);
        }
        self.eager_upgrades.retain(|(o, _)| *o != ob);
    }

    /// `set_heart_beat` efun: subscribe/unsubscribe `ob`. A no-op if
    /// already in the requested state (subscribing twice does not move
    /// `ob` later in the fairness order, and does not double-count it).
    /// `owner` (OBI-137 S3) is only consulted on the subscribe path --
    /// unsubscribing decrements against whatever owner was recorded at
    /// subscribe time (`heartbeat_owner`), not whatever is passed here,
    /// so it is correct even if a caller cannot cheaply re-derive `ob`'s
    /// owner on the way out (e.g. after it was already destructed).
    pub fn set_heart_beat(&mut self, ob: ObjectId, owner: Sym, on: bool) {
        if on {
            if !self.heartbeat.contains(&ob) {
                self.heartbeat.push(ob);
                self.heartbeat_owner.insert(ob, owner);
                bump(&mut self.heartbeat_by_owner, owner);
            }
        } else if let Some(owner) = self.heartbeat_owner.remove(&ob) {
            self.heartbeat.retain(|o| *o != ob);
            unbump(&mut self.heartbeat_by_owner, owner);
        }
    }

    /// Every object currently subscribed to the heartbeat, in
    /// subscription order.
    pub fn heartbeat_targets(&self) -> Vec<ObjectId> {
        self.heartbeat.clone()
    }

    /// Is `ob` currently subscribed to the heartbeat? (`set_heart_beat`'s
    /// own "already on" check, and `check_heartbeat_quota`'s "re-
    /// subscribing does not count again" rule.)
    pub fn is_heartbeat_target(&self, ob: ObjectId) -> bool {
        self.heartbeat_owner.contains_key(&ob)
    }

    /// How many objects are currently subscribed to the heartbeat
    /// (OBI-121 S2c `max_heartbeats`, tests/introspection).
    pub fn heartbeat_count(&self) -> usize {
        self.heartbeat.len()
    }

    /// How many currently-subscribed heartbeat objects are owned by
    /// `owner` (OBI-121/OBI-137 `max_heartbeats`): an `O(1)` `HashMap`
    /// lookup, not a scan of every heartbeat target.
    pub fn heartbeat_count_for_owner(&self, owner: Sym) -> u64 {
        self.heartbeat_by_owner.get(&owner).copied().unwrap_or(0)
    }

    /// `upgrade_all(path)` efun (OBI-89): queue `ob` for a batched eager
    /// migration by [`Scheduler::drain_eager_upgrades`].
    pub fn enqueue_eager_upgrade(&mut self, ob: ObjectId, path: String) {
        self.eager_upgrades.push_back((ob, path));
    }

    /// Number of objects still queued for an eager `upgrade_all` migration
    /// (tests/introspection).
    pub fn eager_upgrade_queue_len(&self) -> usize {
        self.eager_upgrades.len()
    }

    /// Pop up to `budget` queued eager upgrades, oldest first — the
    /// per-tick migration slice `World::tick` runs (spec: "bounded
    /// per-tick budget", so one `upgrade_all` of N objects never blocks a
    /// single tick past its budget, and every other object/player's own
    /// call still gets its own tick this same world tick).
    pub fn drain_eager_upgrades(&mut self, budget: usize) -> Vec<(ObjectId, String)> {
        let n = budget.min(self.eager_upgrades.len());
        self.eager_upgrades.drain(..n).collect()
    }

    /// Number of pending (not yet due) `call_out`s, for tests/introspection.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Pending `call_out`s scheduled by `ob` (OBI-121 S2c `max_callouts_obj`),
    /// an `O(1)` `HashMap` lookup (OBI-137 S3).
    pub fn pending_count_for_obj(&self, ob: ObjectId) -> usize {
        self.pending_by_obj.get(&ob).copied().unwrap_or(0) as usize
    }

    /// Pending `call_out`s charged to `quota_uid` (OBI-121 S2c
    /// `max_callouts_uid`), an `O(1)` `HashMap` lookup (OBI-137 S3).
    pub fn pending_count_for_quota_uid(&self, uid: Sym) -> usize {
        self.pending_by_quota_uid.get(&uid).copied().unwrap_or(0) as usize
    }

    /// Advance one world tick and drain every `call_out` now due, ordered
    /// earliest-`due_tick`-first and FIFO (ascending `id`) among ties.
    /// Every drained call's counters are decremented here -- a caller
    /// that decides to defer it (`tick_share_per_min`) re-adds them via
    /// [`Scheduler::defer`].
    pub fn advance(&mut self) -> Vec<PendingCall> {
        self.tick += 1;
        let now = self.tick;
        let (due, keep): (Vec<_>, Vec<_>) = self.pending.drain(..).partition(|p| p.due_tick <= now);
        self.pending = keep;
        for p in &due {
            unbump(&mut self.pending_by_obj, p.ob);
            unbump(&mut self.pending_by_quota_uid, p.quota_uid);
        }
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
        let a = s.call_out(ob(1), 3, "a".into(), vec![], GuardSet::empty(), 0);
        let b = s.call_out(ob(2), 1, "b".into(), vec![], GuardSet::empty(), 0);
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
        let first = s.call_out(ob(9), 1, "first".into(), vec![], GuardSet::empty(), 0);
        let second = s.call_out(ob(1), 1, "second".into(), vec![], GuardSet::empty(), 0);
        let due = s.advance();
        let ids: Vec<u64> = due.iter().map(|p| p.id).collect();
        // ob(9) scheduled first: it runs first even though ob(1)'s id is
        // numerically smaller and both are due on the same tick.
        assert_eq!(ids, vec![first, second]);
    }

    #[test]
    fn remove_call_out_cancels_a_pending_call() {
        let mut s = Scheduler::new();
        let id = s.call_out(ob(1), 3, "f".into(), vec![], GuardSet::empty(), 0);
        assert!(s.remove_call_out(ob(1), id));
        assert!(!s.remove_call_out(ob(1), id)); // already gone
        for _ in 0..5 {
            assert!(s.advance().is_empty());
        }
    }

    #[test]
    fn remove_call_out_cannot_cancel_another_objects_call() {
        let mut s = Scheduler::new();
        let owner = ob(1);
        let attacker = ob(2);
        let id = s.call_out(owner, 3, "f".into(), vec![], GuardSet::empty(), 0);
        // The attacker guesses (or brute-forces) the id but does not own
        // it: the call must survive, and the attempt must not be
        // distinguishable from "unknown id" (both return `false`).
        assert!(!s.remove_call_out(attacker, id));
        assert_eq!(s.pending_count(), 1);
        assert!(s.remove_call_out(owner, id));
        assert_eq!(s.pending_count(), 0);
    }

    #[test]
    fn destruction_removes_pending_calls_and_heartbeat() {
        let mut s = Scheduler::new();
        let target = ob(5);
        s.call_out(target, 1, "f".into(), vec![], GuardSet::empty(), 0);
        s.call_out(ob(6), 1, "g".into(), vec![], GuardSet::empty(), 0);
        s.set_heart_beat(target, 42, true);
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
        s.set_heart_beat(ob(1), 100, true);
        s.set_heart_beat(ob(2), 200, true);
        s.set_heart_beat(ob(1), 100, true); // re-subscribing does not reorder
        assert_eq!(s.heartbeat_targets(), vec![ob(1), ob(2)]);
        s.set_heart_beat(ob(1), 100, false);
        assert_eq!(s.heartbeat_targets(), vec![ob(2)]);
    }

    #[test]
    fn call_out_with_zero_delay_waits_for_the_next_tick() {
        let mut s = Scheduler::new();
        s.call_out(ob(1), 0, "f".into(), vec![], GuardSet::empty(), 0);
        assert_eq!(s.advance().len(), 1);
    }

    // -- OBI-137 S3: counters, not scans -------------------------------

    #[test]
    fn pending_counts_are_o1_and_track_call_out_and_removal() {
        let mut s = Scheduler::new();
        let a = ob(1);
        let b = ob(2);
        let id_a1 = s.call_out(a, 5, "f".into(), vec![], GuardSet::empty(), 10);
        let _id_a2 = s.call_out(a, 5, "f".into(), vec![], GuardSet::empty(), 10);
        let _id_b1 = s.call_out(b, 5, "f".into(), vec![], GuardSet::empty(), 20);
        assert_eq!(s.pending_count_for_obj(a), 2);
        assert_eq!(s.pending_count_for_obj(b), 1);
        assert_eq!(s.pending_count_for_quota_uid(10), 2);
        assert_eq!(s.pending_count_for_quota_uid(20), 1);

        assert!(s.remove_call_out(a, id_a1));
        assert_eq!(s.pending_count_for_obj(a), 1);
        assert_eq!(s.pending_count_for_quota_uid(10), 1);
    }

    #[test]
    fn pending_counts_drop_to_zero_when_a_due_call_fires_and_is_not_deferred() {
        let mut s = Scheduler::new();
        let a = ob(1);
        s.call_out(a, 1, "f".into(), vec![], GuardSet::empty(), 7);
        assert_eq!(s.pending_count_for_obj(a), 1);
        let due = s.advance();
        assert_eq!(due.len(), 1);
        assert_eq!(
            s.pending_count_for_obj(a),
            0,
            "a fired (not deferred) call_out must not still be counted as pending"
        );
        assert_eq!(s.pending_count_for_quota_uid(7), 0);
    }

    #[test]
    fn destruct_drops_pending_counts_and_heartbeat_count_for_the_object() {
        let mut s = Scheduler::new();
        let a = ob(1);
        s.call_out(a, 5, "f".into(), vec![], GuardSet::empty(), 7);
        s.call_out(a, 5, "f".into(), vec![], GuardSet::empty(), 7);
        s.set_heart_beat(a, 99, true);
        assert_eq!(s.pending_count_for_obj(a), 2);
        assert_eq!(s.heartbeat_count_for_owner(99), 1);

        s.remove_for_object(a);
        assert_eq!(s.pending_count_for_obj(a), 0);
        assert_eq!(s.pending_count_for_quota_uid(7), 0);
        assert_eq!(s.heartbeat_count_for_owner(99), 0);
    }

    #[test]
    fn heartbeat_count_for_owner_is_o1_and_tracks_subscribe_unsubscribe() {
        let mut s = Scheduler::new();
        s.set_heart_beat(ob(1), 5, true);
        s.set_heart_beat(ob(2), 5, true);
        s.set_heart_beat(ob(3), 6, true);
        assert_eq!(s.heartbeat_count_for_owner(5), 2);
        assert_eq!(s.heartbeat_count_for_owner(6), 1);

        s.set_heart_beat(ob(1), 5, true); // re-subscribing does not double-count
        assert_eq!(s.heartbeat_count_for_owner(5), 2);

        s.set_heart_beat(ob(1), 5, false);
        assert_eq!(s.heartbeat_count_for_owner(5), 1);
        assert_eq!(s.heartbeat_count_for_owner(6), 1);
    }

    // -- OBI-137 S2: a deferred call_out keeps its id and FIFO position --

    #[test]
    fn a_deferred_call_out_keeps_its_original_id_and_runs_before_a_later_same_tick_call() {
        let mut s = Scheduler::new();
        // `early` is scheduled first (a lower id); `later` is scheduled
        // after it. Both become due on the same tick after `early` is
        // deferred one tick out.
        let early_id = s.call_out(ob(1), 1, "early".into(), vec![], GuardSet::empty(), 0);
        let due = s.advance(); // tick 1: `early` is due
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, early_id);
        let early = due.into_iter().next().unwrap();

        // Defer `early` (as `World::tick` does on a tick_share breach):
        // it keeps its id and becomes due again next tick.
        s.defer(early);
        assert_eq!(s.pending_count_for_obj(ob(1)), 1);

        // `later` is scheduled now (a higher id) but with a 1-tick delay,
        // so it becomes due the same tick `early`'s deferral lands on.
        let later_id = s.call_out(ob(2), 1, "later".into(), vec![], GuardSet::empty(), 0);
        assert!(later_id > early_id);

        let due = s.advance(); // tick 2: both `early` (deferred) and `later` are due
        let ids: Vec<u64> = due.iter().map(|p| p.id).collect();
        assert_eq!(
            ids,
            vec![early_id, later_id],
            "the deferred call keeps its original (lower) id, so it still \
             runs before a call scheduled after it, even though it was \
             re-queued later"
        );
    }
}
