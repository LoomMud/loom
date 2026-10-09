# `save_object`/`restore_object`: player and character persistence (OBI-171)

Spec references: design v2 §8.1 ("Explicit saves"), §7.3 (versioning
semantics / by-name migration). Implemented in `loom-vm`
(`crate::bcvm::registry::RegistryHost::save_object`/`restore_object`,
`crate::bcvm::persist`, `crate::bcvm::schema_convert::hydrate`,
`crate::fileio::write_file_atomic`).

## What gets saved

`save_object(path)` serialises every `persistent var` the calling
object's program declares, across its whole inherit chain, keyed by
**(declaring program path, name)** — the same identity hot-reload
migration uses (§7.2/§7.3). A plain `var` (no `persistent` modifier) is
never saved and never touched by `restore_object`, regardless of its
value.

```weft
persistent var hp: int = 100      // saved
var connection_hint: string = ""  // never saved
```

Function-typed persistent variables are already a compile error
(`check.rs` W0294, spec §5.2.2 rule 4: "function values are never
saved"). A persistent `object`-typed variable compiles, but its value
never survives a restart — see "What does not round-trip" below.

## Storage location (deliberately *not* the mudlib VFS)

Save files live under a **separate root** from the mudlib's own
`.wf`/Git-backed tree: `World::save_root()`, default
`<parent of mudlib root>/saves` (`World::boot`'s `default_save_root`),
overridable with `World::set_save_root` (`loom-cli serve`'s `--save-dir
<path>` flag, or the `LOOM_SAVE_DIR` environment variable if no flag is
given).

This is a deliberate split from spec §8.1's literal text, which
describes `save_object`'s target as a Postgres `object_state` table
(the same hybrid model `loom-persist`'s `accounts`/`roles` tables use).
**Flagged spec deviation:** Phase 2 ships `save_object` as confined,
atomic *files* instead, for two reasons:

1. The acceptance criteria this work was scoped against ("writes are
   atomic (write + rename)", "crash during write leaves the old save
   intact") describe exactly the write-temp-then-rename durability
   pattern a filesystem gives you directly and a transactional
   database already gives you for free a different way — i.e. the task
   was written assuming file storage.
2. It keeps `save_object`/`restore_object` synchronous in everything that
   decides the outcome (no async round trip through a DB connection the way
   `account_create`/`db_query` need, and no awaiting in a Weft function),
   which matches classic LPMud driver semantics builders already expect from
   these two efuns. OBI-348 moved only the *durability step* (write/fsync/
   rename/fsync) onto the driver's save worker -- see
   [durability.md](durability.md) for what `true` means now.

Migrating `object_state` to Postgres later (to get point-in-time
recovery, replication, and a single backup story with `accounts`) is a
compatible follow-up: the on-disk JSON format below is exactly the
shape a `jsonb` column would hold, and `hydrate`/`encode_value` don't
care where their bytes came from. Tracked for the CTO's sign-off, not
decided unilaterally here.

Why a *separate* root and not just a `/save/`-prefixed path inside the
existing mudlib VFS root: player save data must never be a candidate
for `git add`, a `revert <file>`, or a recompile sweep (§7.4/§8.5) --
none of which have any business touching it.

## On-disk format

One file per `save_object(path)` call, at `<save-root>/<path>.o`
(`.o` appended if `path` doesn't already end in it — classic LPMud
convention). JSON:

```json
{
  "program": "/std/player",
  "version": 3,
  "schema_hash": 1234567890123456789,
  "vars": {
    "/std/player\u0000hp": 100,
    "/std/player\u0000stats": { "$map": [["str", 10], ["dex", 10]] }
  }
}
```

- `vars` keys are `"<declaring program path>\u0000<var name>"` (NUL
  joiner — program paths are themselves `/`-delimited, so a NUL can't
  collide with one).
- Values are `crate::bcvm::persist::encode_value`'s **portable form**
  (spec §7.3): scalars/arrays encode directly; a map (or a `struct`/
  `enum` value, via `schema_convert::struct_portable`/`enum_portable`)
  encodes as `{"$map": [[k, v], ...]}` — a pair list, not a JSON object,
  because a Weft map key can be `int`/`bool`/`object` as well as
  `string` (only a pair list round-trips a non-string key). A non-finite
  float encodes as `{"$float": "nan" | "inf" | "-inf"}`.
- `program`/`version`/`schema_hash` are recorded but not required to
  match the *current* program on restore — see "Restoring across a
  program upgrade" below. They exist for audit/debugging, and
  `version` is what `restore_object` passes to `upgrade()` as
  `from_version`.

## What does not round-trip

- **Function values**: never saved (already a compile error on a
  `persistent` var).
- **Object references**: a live `ObjectId` from a previous driver run
  cannot mean anything after a restart (no instance with that id exists
  any more), so `Value::Object` always encodes to JSON `null` and
  always decodes back as a type mismatch against an `object`-typed var
  on restore (handed to `upgrade()`'s `old` map like any other
  type-changed value, or silently left at its `create()`-time default if
  no `upgrade()` claims it). This mirrors the function-value rule in
  spirit, just not as its own numbered spec rule yet.

## Restoring across a program upgrade (spec §7.3)

`restore_object(path)` does **not** require the saved `version`/
`schema_hash` to match the object's current program. For every
`persistent` var the *current* program declares:

1. If the save has a value for that `(program, name)` key, decode it to
   a portable `Value` (`persist::decode_value`) and try to make it
   conform to the var's **current** declared type
   (`schema_convert::hydrate`).
2. If that succeeds (the type still matches, or — for a `struct` — the
   old fields still line up by name with defaults filling any new
   ones), the value carries straight over — no `upgrade()` call needed.
3. If it doesn't (the type changed incompatibly), the portable value is
   added to an `old` map keyed by var name and handed to
   `upgrade(from_version, old)` if the program defines it — **the same
   mechanism and the same `old` map shape** `RegistryHost::upgrade`
   (hot reload) uses, per spec: "restoring an old save into a new
   program runs the same migration path — one mechanism for hot reload
   and for database migrations."
4. If the save has nothing for a var, it keeps whatever `create()`
   already put there (its own default) — restoring is *overlaying*
   saved state onto an already-instantiated object, not replacing it
   wholesale.

If `upgrade()` is defined and it raises, every var `restore_object`
touched this call reverts to what it held before the call (all-or-
nothing, mirroring spec §7.2 step 6.4's hot-reload rollback rule) and
the efun returns `false`. There is no `runtime_error` apply wired up yet
to report this to (tracked separately); the detail goes to stderr in
the meantime.

## Authorization: the master's save-path contract (CTO review, PR #75)

`save_object`/`restore_object` go through the ordinary `valid_write`/
`valid_read` applies (P1/P0 respectively), same as `write_file`/
`read_file` — but the path they hand the master is **not** a mudlib VFS
path. It is the save-namespace path (the efun's own `path` argument,
without the trailing `.o`), with `op = "save_object"` / `"restore_object"`
so a master can tell the two efuns apart from `write_file`/`read_file`
in the same apply.

**A master that treats this like an ordinary `valid_write`/`valid_read`
VFS-path check is a privilege-escalation bug, not a hardening gap.**
Concretely:

- If a master grants a builder tier write access to `/players` (or, worse,
  to `/` as a catch-all), that same rule now lets that builder
  `save_object("/players/anyone")` and overwrite **any other player's**
  save — `valid_write`'s path argument looks exactly like a normal VFS
  write target, but the effect is clobbering someone else's persistent
  state, not writing a file under their own tree.
- `restore_object` is **P0** (every object may call it on itself — see
  `RegistryHost::dispatch_efun`'s `Privilege::P0` on the `"restore_object"`
  arm). Any object whose program chain happens to declare the same
  `persistent` vars (by `(declaring program, name)`, not by path) can
  `restore_object` another player's save path into *itself* and read
  that player's persistent state into its own vars — `valid_read`
  returning `true` for a path that merely looks like "this player's own
  file" is not enough; it must check that the path *is* the calling
  object's own save path.

The master **must** confine both efuns' `op == "save_object" ||
op == "restore_object"` cases to the caller's own save path (e.g. derived
from the connected account/player's own identity, never from a
caller-suppliable path alone) — a blanket `/players/**` or `/` write/read
grant that is otherwise fine for `write_file`/`read_file` is **not** fine
here. `loom-vm`'s own fixtures (`tests/fixtures/*/secure/master.wf`) are
intentionally permissive (`valid_write`/`valid_read` always `true`) —
that is a test-only stance for exercising the efuns' own mechanics, not a
model for a real mudlib's master. Warp's own master enforces this
confinement on the live path (OBI-172, warp autosave).

## `disk_quota_mb` (OBI-137 S1, CTO review on PR #75, must-fix 2)

`save_object` is charged against `disk_quota_mb` the same way
`write_file` is, through the same `crate::disk_usage::DiskUsage`
seeded-once/`O(1)`-after counter and the same non-raising-`Ok(false)`-on-
breach shape — but keyed differently, because a save path carries no uid
in its text the way `/builders/<u>/**` does:

- `write_file`'s `check_disk_quota` attributes a write to the `<u>`
  *named in the path* (the directory's owner, not the caller).
- `save_object`'s `check_save_disk_quota` instead attributes the save to
  the **writing object's own uid** (`principal_of(self_object()).uid`) —
  the same uid the authorization contract above is responsible for
  keeping confined to its own save path in the first place.
- The counter is seeded from `World::save_root()`
  (`DiskUsage::seeded_save_total`), a single `metadata()` stat on the
  uid's own save file rather than a directory walk — the authorization
  contract above means there is nothing to recursively walk (one uid,
  one save path), unlike `/builders/<u>/**`'s whole subtree.
- Both pools share one counter per `<u>`: `disk_quota_mb` is one number
  covering everything `<u>` has on disk, builder-authored source and the
  uid's own save file alike.

An over-quota save returns `false` (never raises) and never touches
disk, same as an over-quota `write_file`. Unit/integration-tested at
`crates/loom-vm/tests/quotas.rs`'s
`disk_quota_mb_row_denies_a_save_object_that_would_exceed_the_quota`.

## Return contract: accepted in order, not yet on disk (OBI-348)

`save_object(path)` returning `true` means the driver has **accepted the
content and will write it in order**. Everything that could refuse the save
still runs on the world thread, before the call returns: render, the
confinement check, `valid_write`, and the `disk_quota_mb` check. The disk half
is handed to one dedicated worker thread, because `World::disconnect` runs
`autosave()` and the thread that serves every player must not pay for two
`fsync`s per logout (E1.1 measured 304-562 ms world-loop iterations for 150
simultaneous logouts -- OBI-344).

The **durability points** -- after which every save the world has accepted is
on disk -- are `restore_object` (for the path it reads),
`World::flush_pending_saves()`, `World::begin_snapshot()` (a snapshot must not
claim durability it does not have), and process exit (`SaveQueue::drop`
flushes; a crash or `kill -9` does not). Full contract, the crash window,
ordering, the single-writer rule, quota accounting, and the stats a board
operator should watch are in [durability.md](durability.md).

`World::set_save_durability(SaveDurability::Sync)` puts back the old meaning
exactly: `true` means durable, written on this thread. Deferred is the default;
`Sync` is the escape hatch for tests and for anyone who prefers the latency.

## Atomicity: crash during write leaves the old save intact

`save_object` writes through `crate::fileio::write_file_atomic`:
content is written to a sibling temp file in the same directory,
`fsync`ed, then atomically `rename`d over the target, then the **parent
directory itself is `fsync`ed** (CTO review, PR #75, must-fix 4). A
crash (process kill, power loss, OOM-kill) at any point before the
rename leaves whatever was already saved completely untouched — there
is no window where a reader observes a half-written save. The parent-
directory `fsync` closes a second, subtler window: a `rename()` syscall
returning success only makes the new directory entry *visible*, not
necessarily *durable* — without fsyncing the directory, a power loss
shortly after a successful `rename()` can roll the directory entry back
on the next boot even though `save_object` already returned `true`
(the old save would still be intact, same as the first window, but the
new one the caller was told succeeded could vanish). Unit-tested
directly at
`loom-vm::fileio::tests::crash_before_rename_leaves_the_previous_save_intact`,
which drives the pre-rename window (temp file staged, rename never
called) without needing to actually kill a process mid-write.

The temp file itself is created with `OpenOptions::new().write(true)
.create_new(true)` (O_EXCL), not `File::create` (CTO review, PR #75,
must-fix 3): `File::create` truncates-or-creates and **follows** a
symlink already planted at the tmp-file's exact name, so a symlink
planted there pointing outside `save_root` would have the write go
through it. `create_new` fails outright on anything already at that
path instead of following it. A stale tmp file from an earlier crashed
attempt is cleared with a plain `remove_file` immediately before
`create_new` -- `unlink`/`remove_file` always targets the link/file entry
itself, never what a symlink there points to, so this clears a stale tmp
file without ever writing through a symlink planted in its place.
The name is unique **per write** (`.{leaf}.tmp-{pid}-{seq}`, OBI-348 CTO
review) rather than per process: the durability step now has a thread of
its own, and two writers sharing one temp name could unlink each other's
in-flight file or lose `create_new` to `EEXIST` -- which is how CI run
37869788819 lost 2 of 20 same-path saves. The sweep covers both this
write's own name and the pre-OBI-348 `.{leaf}.tmp-{pid}` shape, so an
older build's half-write is still cleaned up without a directory walk.
Tested at `loom-vm::fileio::tests::
stage_write_clears_a_stale_tmp_file_from_an_earlier_crashed_attempt`,
`::stage_write_does_not_follow_a_symlink_planted_at_the_tmp_name`, and
`::two_staged_writes_of_one_path_do_not_share_a_tmp_name`.

## Driver-side autosave hooks

The driver (not the mudlib) guarantees three triggers call an
`autosave()` apply, if the connected object's program defines one — the
mudlib decides what `autosave()` does (typically `save_object` with its
own path convention), the driver only guarantees *when* it's called:

| Trigger | Where |
|---|---|
| Every `Limits::autosave_interval_ticks` world ticks (default 3,000 ticks = 5 min at the 100 ms tick) | `World::tick`, once per currently-connected object, in connection-bind order |
| Explicit `quit` | The mudlib's `quit` command calls the `disconnect()` efun, which closes the connection; once the transport reports it closed, `World::disconnect` runs |
| Net-dead (an unexpected drop) | Same `World::disconnect` call — the transport reports a closed connection the same way whether the driver asked for the close or the remote end disappeared, so this is **one driver hook covering both triggers**, not two |

`World::disconnect` runs `autosave()` and then `net_dead()` as two
separate executions (each with its own tick budget and error handling),
so an `autosave()` failure can never suppress `net_dead()`. Since OBI-348
the save's *durability* is not part of the disconnect cost at all: the
render/validate/authorise half runs there, and the write lands on the
save worker (see [durability.md](durability.md)) -- which is the whole
point of the change, and why this hook's own queue is drained before a
snapshot or process exit.
