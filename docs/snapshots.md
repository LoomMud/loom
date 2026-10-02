# Binary world snapshots (OBI-173)

Design spec §8.1 model 2: a versioned binary file that round-trips a
`loom_vm::World`'s object graph. This is the base for copyover (P2-O1):
the standby process loads a snapshot instead of starting from an empty
world.

## What's in a snapshot (and what isn't)

A snapshot carries every live object's **dynamic** state:

- `vars` (by `(declaring program path, name)`, same identity hot reload
  uses), `env`/`inventory` placement, the connection it is bound to (if
  any), and its `uid`/`euid`/`owner`.
- Registry-level bookkeeping needed to keep `ObjectId`s stable across the
  load: the slot table's shape (so index/generation round-trip exactly),
  `names`, `next_clone`, `conns`/`bind_seq`, and the uid/euid interner.

It does **not** carry a program's bytecode. `World::load_snapshot`
compiles (or reuses an already-compiled) program per distinct path on
demand from the loading process's own `mudlib_root`, exactly like
`World::boot` does — a binary snapshot assumes the standby side is
running the same mudlib source, not a frozen copy of the compiled form.

Also out of scope for this slice (flagged, not hidden):

- **Function values.** A closure or named-function-reference stored in a
  var references this process's own `Rc<dyn ProgramCode>`, which has no
  serialized form yet. Encoding one is a clean
  `SnapshotError::UnsupportedValue`, not a panic.
- **Scheduler state** (pending `call_out`s, heartbeat subscriptions) and
  **security/roles state**. The issue's scope is "the full object graph";
  a real copyover (O1) needs to decide separately whether in-flight
  `call_out`s survive a restart or are simply re-armed by each object's
  own `create()`/`reset()` after reload.

## The copy-on-write split

Design spec §8.1 asks for this "incrementally with copy-on-write so the
tick is not paused for the whole write". Two phases:

1. `World::begin_snapshot` calls `Registry::capture`, which clones every
   live object's `Rc`s (vars, inventory, program pointer) — O(object
   count) pointer bumps, not O(bytes). This is the *entire* synchronous
   cost charged to the world thread; its result does not borrow the
   registry, so `World::tick` can run immediately after.
2. The returned `SnapshotJob` encodes that captured graph into bytes via
   repeated `SnapshotJob::encode_step(&mut out, max_slots)` calls, each
   bounded by a caller-supplied slot budget — meant to be driven a little
   at a time between ticks. This is safe to spread across many ticks'
   worth of further live mutation because every `Value` is
   immutable-once-shared (`bcvm::heap`'s module docs): a live write
   anywhere in the registry clones its buffer through `Rc::make_mut`
   rather than mutating through the snapshot's own `Rc`.

`SnapshotJob::encode_all` drives a job to completion in one call, for
tests or a driver that has decided a single pause is acceptable.

## Versioning

Every encode writes `SNAPSHOT_FORMAT_VERSION` (on-disk framing shape) and
`SNAPSHOT_ABI_VERSION` (the VM's value/object representation) into an
8-byte-magic-prefixed header. `decode_snapshot` rejects a bad magic
(`SnapshotError::BadMagic`), a different ABI version
(`SnapshotError::UnsupportedAbi`), or a truncated/corrupt stream
cleanly — never panics; this is a trust boundary (a snapshot file is
attacker-reachable the moment it touches disk or a copyover channel).
There is deliberately no partial forward/backward compatibility in v1:
copyover's two sides are always the same driver build.

## Benchmark (E1.2: 10k live `/std/item` clones)

`crates/loom-vm/tests/binary_snapshot.rs`'s
`ten_thousand_item_clones_snapshot_and_reload_with_identical_state`
(`#[ignore]`d — run with `cargo test -p loom-vm --test binary_snapshot
--release -- --ignored --nocapture`), one measured run:

```
OBI-173 binary snapshot (exit_10k_item, 10002 objects): capture pause =
5.122722ms, tick right after capture = 1.757µs, encode = 3.038736ms,
total = 8.161458ms, 1468120 bytes
```

- **Pause per tick** (the only synchronous cost): ~5.1 ms to capture
  10,002 objects — a `World::tick` immediately after returns in ~2 µs,
  proving the capture itself does not hold up the world thread.
- **Total snapshot time** (capture + full encode): ~8.2 ms for a ~1.4 MB
  file.

These numbers are from a debug-vs-release note: the run above used
`--release`; `cargo test` (debug) is slower but the same test (not
`#[ignore]`d further) is also run against the smaller `tworoom` fixture
on every `cargo test -p loom-vm`.

## Round trip

`binary_snapshot_round_trip_preserves_object_state` (not `#[ignore]`d)
snapshots a small but structurally rich world (a map var, an object var
round-tripped through `env`/`inventory`, a live connection binding),
loads it into a fresh `World` (standing in for "a fresh driver process"),
and checks object count, names, `env`/`inventory`, vars (including the
map), owner/euid, memory accounting, program version, and the connection
binding are all identical to the original.

`bad_magic_and_bad_abi_are_clean_errors_not_panics` covers the "a load
from an incompatible ABI fails cleanly" acceptance criterion directly:
corrupted magic, a mismatched ABI version, and truncated bytes each
produce a typed `SnapshotError`, never a panic.
