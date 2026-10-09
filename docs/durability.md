# Durability: how a `save_object` reaches the disk (OBI-348)

Spec references: design v2 §8.1 ("Explicit saves"), §7.3 (versioning
semantics). Implemented in `loom-vm` (`crate::save_queue`,
`crate::bcvm::registry::RegistryHost::save_object`/`restore_object`,
`crate::fileio::write_file_atomic`, `World::tick`).

**Read this before trusting a `save_object` return value.**
[save-objects.md](save-objects.md) documented these two efuns as durable the
moment they returned `true`. Since OBI-348 that is no longer the
default, and the difference is visible to a builder: `save_object` returns
`true` when the driver has *accepted* the save, not when the bytes are on
disk. [save-objects.md](save-objects.md) now defers to this page for the
durability half of the contract.

## What `save_object() == true` means now

Rendering, validation, the confinement check, the `valid_write` callback, and
the `disk_quota_mb` check all still happen **synchronously, on the world
thread, before `true` is returned**. So a rejected save never silently
"misplaced a character": `false` (or an error) is returned on the same call,
and nothing was written. Exactly as before.

What moved off the world thread is the *durability* step -- the write, the
`fsync` of the file, the `rename` over the real name, and the `fsync` of the
directory. `save_object` hands that to one dedicated worker thread and
returns. The reason: `World::disconnect` runs `autosave`, and with a real save
root every logout made the thread that serves every player pay two `fsync`s.
E1.1 CI measured 150 simultaneous logouts as world-loop iterations of 304-562 ms
(OBI-344). The per-logout figure is in
[`crates/loom-vm/benches/BASELINE.md`](../crates/loom-vm/benches/BASELINE.md)
("Deferred save durability").

## The durability points

| Call | After it, every save the world has accepted is on disk |
|---|---|
| `restore_object(path)` | yes, for `path` (read-your-writes, see below) |
| `World::flush_pending_saves()` | yes, for everything queued |
| `World::begin_snapshot()` | yes -- a snapshot must not claim durability it does not have |
| `World::tick()` (the next one) | no: it *reaps* what finished, it does not wait |
| process exit (`SaveQueue::drop`) | yes: `Drop` flushes; a crash or `kill -9` does not |

**The crash window.** Between `save_object` returning `true` and the worker
finishing, a power loss loses that save and nothing else: the old file is
still there, intact, because the write is still `stage_write` + `commit_write`
(rename), one atomic swap per object. So the window is *at most one save per
object*, never a half-written one, and it is the same window a normal
`Extfile`-style mudlib has -- it is now visible to a caller who used to be
told "it is on disk". A driver that wants the old guarantee sets
`World::set_save_durability(SaveDurability::Sync)`: then `save_object` is
literally the pre-OBI-348 code path, durability included, and `true` means
"durable" again. Deferred is the default; `Sync` is the escape hatch for tests
and for anyone who would rather pay the latency.

## Ordering, and one writer

The queue is FIFO and the worker is a **single thread**, so same-path saves
land oldest-first and the newest content wins -- the property the pre-OBI-348
code got from doing everything inline.

While the worker is alive it is the only thread that commits queued saves. A
full queue makes `save_object` **wait for a slot** (counted in
`SaveQueueStats::backpressure_waits`); a flush that runs past
`SaveQueueConfig::flush_deadline` **reports and keeps waiting** (counted in
`flush_deadline_exceeded`, and put in the `errors` inbox as one entry per
event). Neither starts a second writer, and that is deliberate: two writers on
one path is how CI run 37869788819 lost 2 of 20 same-path saves (the pre-OBI-348
`.{leaf}.tmp-{pid}` temp name is per process, so the two collided on
`create_new`/`unlink` and the file ended up *one version stale*). The durable
write now also stages a temp name unique **per write** (`.{leaf}.tmp-{pid}-{seq}`)
as defence in depth, and `save_queue::tests::temp_files_do_not_collide_across_threads`
holds that line.

An inline commit on the world thread still exists, but only where there is
provably nobody else to write: `Sync` mode, a world that never started a
worker, a worker whose exit is *confirmed* (its thread cleared its alive flag
and it was joined), or a save too large for the queue's byte budget -- and in
that last case the queue is empty, so it cannot race anything.

## Read-your-writes

`restore_object(path)` waits for `path` if and only if a save to that exact
path is still in flight (`SaveQueue::has_pending_for_path`). Because the worker
is one FIFO thread, that wait also lands everything queued before it, so the
rule is simple: **a restore never reads a file older than the newest save it
follows.** No wait, and no disk I/O on the world thread, in the common case.

`save_object`'s *own* rejections keep the old synchronous meaning: a bad
argument, an escape from `save_root`, a `valid_write` veto, or a
`disk_quota_mb` breach still returns `false` (or raises) on the call that
asked, because the check runs before anything is queued. What you can no
longer learn from the return value is "the disk said no" -- that arrives as an
`errors` inbox entry (`save_object("/players/bob.o"): No such file or
directory (os error 2)`) and in `save_queue_stats().failed`, and the object's
previous file is untouched (still `stage_write`/`commit_write`, one swap per
object, never a half-written save). See
`save_queue::tests::a_commit_failure_reports_one_save_not_the_batch` and
`loom_vm::tests::save_durability::a_deferred_write_failure_reaches_the_error_inbox`,
which is also the test that proves a failed save leaves the previous file alone.

## Quota accounting

`disk_quota_mb` is charged where the bytes actually are, so a save that is
accepted but not yet durable cannot double-count and cannot escape:

- at `save_object` time, the projection folds in what is already queued (this
  path's queued content replaces the stale file size in the delta; other paths
  queued for the same uid count as if already written).
- the real charge is applied when the outcome is reaped, from the file's size
  *after* the rename -- not from the rendered length.
- an inline commit is charged on the spot, exactly as the pre-OBI-348 code did.
- `write_file`'s check (`file_writes`) folds in queued `save_object` bytes too,
  otherwise accepted-but-unlanded saves would understate a uid's usage.

Failure to *charge* is never a failure to *save*: a save that reached the disk
stays reported `true` and the mismatch goes to the `errors` inbox.

## Where the numbers go

`World::save_queue_stats()` returns `SaveQueueStats { queued, committed,
failed, inline_commits, backpressure_waits, flush_deadline_exceeded, pending,
pending_bytes, peak_pending, panicked }`. Nothing in this crate registers a
`metrics` family -- the names and their scrape wiring belong to `loom-obs` /
`loom-cli serve` (OBI-344's follow-up). The three that matter operationally:

- `inline_commits` -- did the world thread just `fsync`? Should be ~0 while a
  worker is alive.
- `backpressure_waits` + `flush_deadline_exceeded` -- is the disk behind? If
  the second one moves, durability is late and `errors` says so.
- `panicked` -- a bug in the durability path, not a disk error. Non-zero means
  the worker caught a panic; investigate.

## What a builder has to do about this

Nothing, for the normal flow: `save_object` → `true` → the file turns up. What
you must not write is a check of the save directory from script immediately
after saving (`read_file` on the save path, a `file_exists` poll) -- that can
now observe the pre-swap file. If you genuinely need the durability point, ask
the driver (a GM-only efun over `flush_pending_saves` is the obvious shape and
is **not** implemented yet; OBI-348 did not add any new efun).

## Tests that hold this contract

| Test | What it proves |
|---|---|
| `save_queue::tests::a_saturated_queue_on_one_path_still_has_one_writer` | CTO review item: 10 same-path saves on a `max_pending: 2` queue with a 20 ms disk -> newest wins, `committed == 10`, `failed == 0`, `inline_commits == 0` |
| `save_queue::tests::a_saturated_queue_never_loses_a_save` | 200 saves through a 2-slot queue, all of them land |
| `save_queue::tests::a_flush_deadline_does_not_start_a_second_writer` | the same shape with `flush_deadline` shorter than the backlog -- report and keep waiting, never a second writer |
| `save_queue::tests::a_live_worker_without_a_handle_is_still_the_only_writer` | losing the join handle is not losing the thread |
| `save_queue::tests::a_lost_worker_commits_its_backlog_inline` | a *confirmed* exit is the one time inline is legal: nothing is lost, order kept |
| `save_queue::tests::a_commit_failure_reports_one_save_not_the_batch` | disk failures stay per-save; the queue keeps working |
| `save_queue::tests::temp_files_do_not_collide_across_threads` | `fileio`'s per-write temp name (defence in depth) |
| `fileio::tests::two_staged_writes_of_one_path_do_not_share_a_tmp_name` | same, at the fileio layer |
| `save_durability::a_save_returns_before_the_disk_has_finished` | the efun's answer is "accepted", end to end through `World` |
| `save_durability::disconnect_autosaves_without_paying_for_the_disk` | OBI-348's actual goal, asserted on a clock |
| `save_durability::restore_waits_for_its_own_path` | the read-your-writes rule, semantically (the value, not the file) |
| `save_durability::sync_mode_restores_the_pre_348_meaning` | `Sync` mode is bit-for-bit the old behaviour, including a synchronous rejection |
