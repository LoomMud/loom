# Copyover state scope (OBI-184, design §7.5/§9.9)

Binary world snapshots (OBI-173, `docs/snapshots.md`) carry the object
graph only. This note records the decisions OBI-184 needed to make about
the state OBI-173 explicitly left out, per Aragorn's OBI-173 follow-up
comment on OBI-184: whether scheduler state (`call_out`s, heartbeat
subscriptions) survives a copyover, and what happens to roles/security
state. Both are settled here, not deferred further, because OBI-221
(the snapshot-load/`reconnect()` side of this work) needs them pinned
down to implement against.

## Roles/security state: not a gap

`RolesSnapshot` is not, and does not need to be, part of the binary
snapshot. It is already loaded from Postgres independently of world boot
(`loom-cli`'s `run_roles_manager`, OBI-36/OBI-123), and that load path
runs unconditionally on **every** process start -- including a standby
process during its pre-takeover boot (§7.5 step 0: "starts it in
*standby*: it runs schema migrations ... and boots the compiler, but
doesn't yet load the world"). A standby that has loaded the world
snapshot but not yet taken over sockets still has a live roles snapshot
by the time it does, from the same boot-time path every other `loom
serve` invocation uses. There is nothing for the binary snapshot to add
here, and nothing for the supervisor to special-case.

## Scheduler state (`call_out`s, heartbeats): re-armed, not preserved

**Decision:** pending `call_out`s and heartbeat subscriptions do **not**
survive a copyover as exact in-flight state. The standby's freshly
loaded `Scheduler` starts empty (no pending calls, no heartbeat
subscribers), and objects that want to keep running on a timer re-arm
themselves through the same `reconnect()` apply §7.5 already specifies
-- generalized to run on **every** loaded object, not only previously
interactive ones.

Why, instead of extending the snapshot format to serialize pending
calls:

- A `PendingCall` closes over a target object/function name and
  arguments, all of which round-trip through the existing snapshot
  machinery fine on their own -- but its *due tick* is meaningless across
  a process restart (world tick count resets to 0 in a freshly booted
  `World`; wall-clock-anchoring it is a separate, bigger scheduler change
  not needed for anything else OBI-184 requires), and whatever call it
  was going to make may no longer be valid once in-flight state (e.g. an
  NPC mid-respawn) also didn't round-trip identically. Re-arming is
  simpler and strictly safer than half-preserving state whose timing
  guarantees we'd otherwise be making up.
- Loom already has an established convention for "this needs
  re-establishing after a restart, by the object's own code, not the
  driver's": the classic LPMud `reset()` apply, called periodically to
  re-populate/respawn. Treating a copyover's scheduler reset the same
  way -- "a kind of reset, mudlib code's job, not state the driver
  promises to carry over" -- is consistent with that, rather than
  inventing a second, driver-magic mechanism that only some objects
  (the ones that happen to have had a pending `call_out`) benefit from.
- It keeps `SnapshotJob`/`decode_snapshot`'s trust boundary small (OBI-173
  deliberately keeps the on-disk format to "the object graph", no
  executable/schedulable state) rather than growing it for a case that a
  one-line `reconnect()` body (`set_heart_beat(this_object(), 1)`, or
  re-issuing the `call_out`s it cares about) already covers.

**What OBI-221 needs to implement**, concretely:
1. `reconnect()` is called once per loaded object after a snapshot load
   (not just on objects that had a live connection at snapshot time).
   Its default (no `reconnect()` defined on the object/its inheritance
   chain) is a no-op -- most objects need nothing.
2. For a previously **interactive** object, the driver also re-binds its
   connection (the socket handed over by the supervisor's `fdpass`,
   §7.5 step 2/3) before calling `reconnect()`, so a `reconnect()` body
   can safely write to `this_player()`'s connection immediately.
3. Nothing in the scheduler itself needs to change -- a fresh `Scheduler`
   from `World::boot`'s normal construction is correct; OBI-221 does not
   need to touch `scheduler.rs`.

Mudlib-side consequence (Warp, flagged for Aragorn/whoever owns Warp's
side of this): any object with a `set_heart_beat`/`call_out` it needs
across process restarts must re-issue it from `reconnect()`. This is the
same shape of work a mudlib already has to do for the "planned reboot"
path in design §9.9's table, so it is not new mudlib-side surface area,
just the same `reconnect()` hook also covering copyover's abbreviated
pause instead of only a full reboot.

## In-flight player output: not carried either (OBI-304)

`loom-net`'s `run_server_full` buffers output the world emitted for a
session across its own reclaim/readopt boundary and replays it, in order,
onto the re-adopted connection (`HandoffOutbox`). That exists so
`loom serve`'s in-process reclaim/readopt rehearsal -- which cannot freeze
the world -- stops silently dropping a player's `logon()` burst.

**Decision:** that buffering is same-process only, and is *not* the
copyover's output story. Parked output is deliberately not serialised into
the handoff manifest: a second source of truth for world output would
compete with the snapshot, and the manifest's trust boundary stays "fds
plus the snapshot pointer" (§7.5 step 2/3). Consequences for the real
hand-off:

1. The driver must stop world output -- `World::tick` *and* input handling
   -- before the **first** reclaim. Anything the world emits after that is
   a driver bug, not state the hand-off owes anyone.
2. Whatever the old process still had parked when it exited is lost with
   it. `run_server_full` makes that loud, not silent: a `warn!` plus
   `loom_net_handoff_outbox_dropped_total` at shutdown, and the same
   counter on the per-session overflow path (`output_queue_depth`).
3. Re-join state the parked queue would otherwise have carried --
   `SetEcho`, `SendGmcp`, `Close` -- is the world's job via `reconnect()`
   (§7.5, OBI-221) and the snapshot, not this queue's. A replayed
   `SendGmcp` in particular usually doesn't reach the player anyway: the
   new connection has not renegotiated GMCP yet.

This is the same reasoning as the scheduler decision above: the snapshot
carries the object graph, `reconnect()` re-establishes everything that has
to be re-established, and the hand-off carries fds -- nothing more.
