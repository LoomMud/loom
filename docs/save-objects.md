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
2. It keeps `save_object`/`restore_object` fully synchronous and
   World-thread-local (no async round trip through a DB connection the
   way `account_create`/`db_query` need), which matches classic LPMud
   driver semantics builders already expect from these two efuns.

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

## Atomicity: crash during write leaves the old save intact

`save_object` writes through `crate::fileio::write_file_atomic`:
content is written to a sibling temp file in the same directory,
`fsync`ed, then atomically `rename`d over the target. A crash (process
kill, power loss, OOM-kill) at any point before the rename leaves
whatever was already saved completely untouched — there is no window
where a reader observes a half-written save. Unit-tested directly at
`loom-vm::fileio::tests::crash_before_rename_leaves_the_previous_save_intact`,
which drives exactly that window (temp file staged, rename never
called) without needing to actually kill a process mid-write.

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
so an `autosave()` failure can never suppress `net_dead()`.
