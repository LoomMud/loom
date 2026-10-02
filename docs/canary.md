# Canary updates (P2-B7, OBI-182, spec §7.4)

`canary_update(path, pct, window_ticks, max_new_errors)` is the driver half of
`update --canary N%`: it recompiles `path` (exactly like `compile_object`,
install is lazy either way — see `docs/efuns.md`) and then routes only `pct`%
of future accesses to the new version instead of all of them, watching the
P2-B4 error inbox (`loom-vm/src/errors.rs`) to decide whether to promote or
roll back.

## How routing works

- Which `pct`% is decided by `bcvm::registry::canary_cohort`: a deterministic
  hash of the object id, not a coin flip — the same object always lands on the
  same side for the life of one canary, so repeatedly accessing it doesn't
  change its answer.
- `RegistryHost::ensure_current` (the lazy per-instance upgrade check, spec
  §7.2/§7.3, OBI-89) is what actually applies this: while a path has an active
  `CanaryState`, an access routes a cohort member to the candidate and leaves
  everyone else on the pre-canary stable version, instead of unconditionally
  moving everyone to whatever is current.
- A rollback is not a special "downgrade" code path: `RegistryHost::upgrade`
  already works on any target program, not only a "newer" one, so rolling back
  is just re-pointing `programs[path]` at `stable` and letting the normal lazy
  machinery carry already-migrated instances back on their next access.

## Promotion / rollback decision

`World::tick` (`poll_canaries`) runs every tick:

- if the error inbox's count for `path` has grown by more than
  `max_new_errors` since the canary started, it rolls back **immediately**,
  without waiting for the window to elapse;
- otherwise, once `window_ticks` world ticks have passed since it started, it
  promotes.

**Flagged spec deviation:** §7.4 says "watches `runtime_error` rate ... for N
minutes". This implementation measures the window in **world ticks**
(`Scheduler::tick`, advanced once per `World::tick()` call — 100 ms in
production, per `World::tick`'s own doc comment), the same choice
`TickShareWindow` (OBI-121 S2c) already made for its 60-second window, and for
the same reason: it makes the whole thing deterministic from the tick counter
alone, so a test drives a multi-minute window with repeated `World::tick()`
calls instead of a real sleep. A builder-facing `update --canary 5% --minutes
10` command (mudlib, out of scope here) converts minutes to ticks at the call
site.

**Known interaction, not specially handled:** calling `compile_object`/
`upgrade_all` on a path with an active canary is a plain recompile — it cancels
the in-flight canary (`Registry::install` drops the `CanaryState` for any path
in the installed set) rather than being rejected or layered on top of it.

**Out of scope for this slice:** an in-flight canary is not captured by world
snapshots (`loom-vm/src/snapshot.rs`) — a copyover or restore mid-canary loses
the pending decision. Revisit when O1 (copyover) lands if that turns out to
matter in practice (a canary's window is expected to be short relative to a
15-minute snapshot interval).

## Efuns

See `docs/efuns.md` for the authoritative signatures. `canary_update` returns
`null` on success or a diagnostics/error string (mirrors `compile_object`'s
`Optional<String>`); `canary_status` returns `null` if `path` has no canary in
flight, else `{"program", "pct", "ticks_left", "new_errors",
"max_new_errors"}`. Both are gated the same as `upgrade_all`: P1 plus
`valid_upgrade(path, ob)`.
