# loom-persist notes

## Password hashing

`loom-persist` stores account passwords using Argon2id with:

- memory cost: 19 MiB (`m=19456` KiB)
- iterations: 2 (`t=2`)
- parallelism: 1 (`p=1`)

These are intentionally interactive-login settings for Phase 1 and can be raised
later once production latency/CPU baselines are measured.

## Two logins (D-27.4)

Migrations must not create Postgres logins or contain passwords. There are two
logins, both of which must already exist before `run_migrations` is called:

- **`loom_owner`** owns every table and `security definer` function. Only this
  login runs `run_migrations(LOOM_DB_MIGRATE_URL)`.
- **`loom_app`** is the world-runtime login (`Persist::connect(DATABASE_URL)`).
  It is not an owner, and has no `insert`/`update`/`delete` on the roles
  tables -- only `SELECT`, plus `EXECUTE` on the four `roles_*`
  security-definer functions.

CI creates both logins in a setup step (see `.github/workflows/ci.yml`).
Staging provisions them from `/etc/loom/secrets.env` ([OBI-42](/OBI/issues/OBI-42)).

## Local DB testing (OBI-151)

**Never run a Postgres-backed loom/warp test, or `loom serve`, against the
ambient `DATABASE_URL` in an agent shell.** Agent shells export
`DATABASE_URL` pointing at Paperclip's own control-plane Postgres
([OBI-150](/OBI/issues/OBI-150)) -- a real smoke run once wrote accounts
into it. That variable must never be treated as "the DB to test against";
treat it the same as any other secret you didn't provision yourself.

Rules, enforced both by naming and by a hard runtime check:

- `loom-cli`'s and `loom-persist`'s DB-backed integration tests
  (`roles_demo`, `accounts_demo`, `persist_integration`,
  `roles_s2_integration`) read `LOOM_TEST_DATABASE_URL` and
  `LOOM_TEST_DB_MIGRATE_URL` -- never the ambient `DATABASE_URL`/
  `LOOM_DB_MIGRATE_URL`. They skip (or, with `LOOM_REQUIRE_DB=1`, fail) if
  those aren't set; they never fall back to `DATABASE_URL`.
- A local, interactive smoke run of `loom serve` (not through the real
  staging deployment) should export `LOOM_SMOKE_DATABASE_URL` instead of
  `DATABASE_URL`. `connect_persist()` in `loom-cli` prefers
  `LOOM_SMOKE_DATABASE_URL` and only falls back to `DATABASE_URL` for the
  real production/staging wiring (a container's own env, set once by
  Compose/Flux -- not an ambient shell leak).
- Either way, [`loom_persist::assert_not_control_plane_db`] is called
  inside `Persist::connect`/`run_migrations` and hard-fails (returns
  `Err`, does not silently proceed) if the resolved URL's host is
  `postgres:5432` or its database name is `paperclip` -- the two shapes
  Paperclip's control-plane DSN is known to take. This is defense in
  depth, not the primary guardrail: the primary guardrail is simply never
  reading `DATABASE_URL` from a test/dev entrypoint in the first place.

**Practical rule of thumb: `unset DATABASE_URL` in your shell before doing
any loom/warp DB-backed work, and use the disposable-DB helper below
instead of exporting your own DSN.**

### `scripts/with-disposable-postgres.sh`

Boots a throwaway Postgres instance this run owns -- `initdb`/`pg_ctl` on a
random `127.0.0.1` port, data directory under
`$PAPERCLIP_RUN_SCRATCH_DIR` (or `$TMPDIR`) -- bootstraps the same
`loom_owner`/`loom_app` two-login shape CI's Postgres service creates,
exports `LOOM_TEST_DATABASE_URL`/`LOOM_TEST_DB_MIGRATE_URL`/
`LOOM_SMOKE_DATABASE_URL` for the command it wraps, runs that command, and
always tears the instance down afterwards (success, failure, or signal),
deleting its data directory. It never reads or forwards the ambient
`DATABASE_URL`.

```sh
# DB-backed integration tests
scripts/with-disposable-postgres.sh -- \
  cargo test -p loom-cli --test roles_demo -- --test-threads=1
scripts/with-disposable-postgres.sh -- cargo test -p loom-persist

# an interactive loom serve smoke run
scripts/with-disposable-postgres.sh -- cargo run -p loom-cli -- serve --mudlib mudlib
```

It needs a real Postgres server binary already available -- in order,
it tries `$LOOM_DISPOSABLE_PG_DIR`, `initdb`/`pg_ctl`/`postgres` on `PATH`,
then a vendored `@embedded-postgres/linux-<arch>` npm package already
present under a local pnpm store (no network fetch at run time). If none
of those exist on your machine, it fails with the exact fix needed; see
`scripts/disposable-postgres-lib.sh` for the search order.

## Roles schema (design §5.11.3)

Implements the tier model directly: `staff`, `domains`, `domain_members`,
`tier_policy`, `grants`, `role_changes`. A player is an account with no
`staff` row and has no tier. `staff.account_id` is `UUID` (matching
`accounts.id`), not the `BIGINT` in the design doc's illustrative excerpt.

All writes to these tables go through four `SECURITY DEFINER` functions,
never direct DML from `loom_app`:

- `roles_set_tier(actor, target_uid, new_tier, reason)` -- T3 (domain lead)
  may only promote T1 -> T2 within a domain it leads; T4 (arch) may set any
  tier 1-3 for anyone currently below T4. No self-promotion. **Rejects tiers
  4 and 5 in Phase 1** -- there is no driver-reachable path to arch/root.
- `roles_set_member(actor, domain, target_uid, role, reason)` -- T3 may
  add/remove members in domains it leads; T4+ may also appoint leads.
- `roles_grant(actor, uid, kind, target, expires_at, reason)` /
  `roles_revoke_grant(actor, uid, kind, target, reason)` -- time-boxed,
  per-uid exceptions (efun/db_query/path). Requires actor tier >= 3.
  Read back through the `active_grants` view, which excludes expired rows.

`roles_bootstrap_root(uid, account_id)` sets a T5 (root) tier directly. It is
**owner-only** (not granted to `loom_app`) and is the only way to create a
T4/T5 staff row in Phase 1. The two-root approval flow for further T4/T5
grants is deferred; see "what's next" below.

**Reserved uids** (migration 0006, OBI-276): `roles_set_tier`,
`roles_propose_tier`, `roles_approve_proposal`, and `roles_bootstrap_root`
all refuse a uid `loom_vm::security::is_reserved_principal` names as a
trusted driver principal (`root`, `mudlib`, `domain:<d>`) -- no staff row
may ever carry one, including via owner-only bootstrap.

**Security invariant:** every `actor` argument above must be the driver's
effective principal from the privilege stack (OBI-35), never a string taken
from mudlib/Weft code. The database re-checks promotion rights independently
of the master's `valid_*` applies, but that check is only as trustworthy as
the `actor` the driver passes in. See the doc comment on `Persist` in
`src/lib.rs`.

### What's next

- Domain lifecycle (create/archive) and `staff` row removal (full demotion to
  player) are not yet covered by any `security definer` function.
- `roles_set_member` does not reject changes to membership in an `archived`
  domain; a follow-up should add that check alongside the existing `unknown
  domain` check.
- The two-root proposal flow (below) covers T4/T5 tier changes only.
  Domain-lead appointment/removal at T3/T4 is unchanged from R2.

## Migration 0002: two-root proposals, NOTIFY, audit_log (design OBI-36 §1, §5, §6)

[OBI-119](/OBI/issues/OBI-119) (S2a) adds `crates/loom-persist/migrations/0002_roles_s2.sql`
on top of 0001:

- **Existing-staff account lookup fix (R2 follow-up).** `roles_set_tier` (and
  the new two-root apply path) now resolve an *existing* staff row's account
  through `staff.account_id` first, and only fall back to
  `accounts.username` for a target that has no `staff` row yet. This fixes
  the assumption noted in the original R2 follow-up: a uid no longer has to
  match its account's username once it already has a `staff` row (for
  example a root created by `roles_bootstrap_root` with uid != username).
- **Two-root rule for T4/T5 (§6/D-S2.6).** `roles_set_tier` still rejects
  tiers 4 and 5 outright. Two new `SECURITY DEFINER` functions implement the
  two-root approval flow:
  - `roles_propose_tier(actor, target_uid, new_tier, reason) -> bigint`:
    only a T5 root may call this, only to propose granting T4/T5 or to
    demote an existing T4/T5 account. No self-target. Inserts a row into
    `role_proposals` (default 24 h expiry) and returns its id.
  - `roles_approve_proposal(actor, id)`: only a T5 root, distinct from both
    the proposer and the target, may approve an unexpired, not-yet-applied
    proposal. It applies the tier and writes `role_changes` with a reason
    naming both roots and the proposal id.
  - `role_proposals` is never written directly by `loom_app`, only through
    these two functions.
- **`NOTIFY roles_changed`.** `AFTER INSERT OR UPDATE OR DELETE ... FOR EACH
  STATEMENT` triggers on `staff`, `domains`, `domain_members`, `tier_policy`
  and `grants` call `pg_notify('roles_changed', <table name>)`. This is one
  of three refresh triggers for the driver's roles snapshot (design §1); the
  other two (after any mutation efun, and a timer at the earliest grant
  expiry) are S2b (loom-vm/loom-cli, OBI-120).
- **`audit_log`.** An append-only Postgres sink for the driver's in-memory
  audit ring (design §5). `loom_app` has `INSERT` only -- no `SELECT`,
  `UPDATE` or `DELETE` -- so a compromised world-runtime login can add
  entries but never read back, edit or erase them.

### `Persist` API added in 0002

- `load_roles_snapshot() -> RolesRows`: plain data (no `loom-vm` dependency)
  -- `staff`, `domains`, `domain_members`, `tier_policy`, every currently
  unexpired grant (`active_grants`), and the earliest of those grants'
  `expires_at` (`None` if there are no active grants). `loom-vm` builds its
  own `RolesSnapshot` from these rows (S2b).
- `listen_roles_changed() -> mpsc::Receiver<String>`: `LISTEN roles_changed`
  on a dedicated `PgListener`, forwarding each notification's payload (the
  table name) on the returned channel until it errors or the receiver is
  dropped.
- `roles_propose_tier` / `roles_approve_proposal`: thin wrappers over the
  SQL functions above.
- `insert_audit_batch(&[AuditRow])`: appends a batch of audit rows in one
  round trip (a single multi-row `INSERT`), matching the driver's
  batched-write DB-worker pattern.

## loom-cli wiring (OBI-123)

`crates/loom-cli/src/main.rs` is the only caller of every API above (`loom-persist` itself never touches `loom-vm`):

- **Snapshot loader**: `connect_persist()` connects `Persist` from `LOOM_SMOKE_DATABASE_URL`/`DATABASE_URL` if either is set (see "Local DB testing" above). `run_roles_manager`, a dedicated `tokio::spawn`ed task, owns every refresh trigger design §1 lists (boot, `LISTEN roles_changed`, a pulse after every completed mutation, and a timer at the earliest grant expiry) in one loop, converts `RolesRows` to a `loom_vm::RolesSnapshot` (`build_roles_snapshot`) and publishes it on a `watch` channel. The world thread (which cannot itself be async: `World` is `!Send`) polls that channel once per event and calls `World::set_roles_snapshot`. With neither set, `spawn_world_thread` instead loads `LOOM_ROLES_SEED` synchronously at boot (`loom_vm::roles::load_seed_from_env`); a malformed seed is a boot failure.
- **Mutation dispatch**: `ChannelRolesMutations` (a `loom_vm::RolesMutations` impl) turns each `roles_*` efun call into a `DbRequest::Roles*` sent to the same DB worker (`loom_persist::spawn_db_worker`/`spawn_dev_account_worker`) that already serves `account_create`/`account_login`; `try_send` never blocks the world thread and reports `false` (queue full/closed) exactly like `ChannelAccountAuth`. Answers come back as `DbEvent::RolesResult`, delivered to `World::deliver_roles_result` by the same drain loop that already handles `DbEvent::AccountResult`, which also pulses `run_roles_manager`'s reload channel.
- **`audit_log` sink**: once per world tick, the world thread calls `World::drain_audit_since` and hands the new rows to `run_audit_sink` (another dedicated task), which appends them via `insert_audit_batch`. No `DATABASE_URL` means no sink task at all -- the rows are computed but never sent anywhere.

## SQLx offline metadata

`loom-persist` uses `sqlx::query!` macros and commits the generated metadata
under `.sqlx/` (workspace root).

**An offline build is the workspace default** (OBI-321): `.cargo/config.toml`
sets `[env] SQLX_OFFLINE = { value = "true", force = false }`, so `cargo
build`, `cargo check`, `cargo test` and rust-analyzer compile the macros from
`.sqlx/` and never open a connection. Before that file, a plain `cargo build`
dialled whatever the ambient `DATABASE_URL` pointed at, at compile time, to
`DESCRIBE` the schema -- and on an agent shell that is Paperclip's own
control-plane Postgres ([OBI-150](/OBI/issues/OBI-150), see "Local DB testing"
above). The failure looked like a broken migration
(`column "key" of relation "object_state" does not exist`,
`function roles_set_tier(...) does not exist`) against a live database you do
not own, which is exactly the wrong invitation to "fix the schema". CI
(`SQLX_OFFLINE: "true"` in `.github/workflows/ci.yml`) and the image build
(`ENV SQLX_OFFLINE=true` in the `Dockerfile`) already built offline; this only
makes the same thing true for a bare `cargo` invocation.

Because `force = false`, a value already in the environment wins: a live-DB
build stays available as an explicit opt-in, and `cargo sqlx prepare` (which
sets `SQLX_OFFLINE=false` on the `cargo check` it spawns itself) keeps working.

### Refreshing the cache

After adding or editing a `query!`, the cache is missing an entry and the
offline build says so -- `SQLX_OFFLINE=true but there is no cached data for
this query`. That is the expected failure, and the fix is a refresh, never a
change to some database:

```bash
scripts/sqlx-prepare.sh
```

That script re-execs itself under
[`scripts/with-disposable-postgres.sh`](../scripts/with-disposable-postgres.sh),
applies `loom-persist`'s migrations to that throwaway instance as `loom_owner`,
runs `cargo sqlx prepare` against it, then re-checks the macros offline from the
cache it just wrote -- so a refresh that the default build cannot use fails
there instead of in CI. Commit the resulting `git diff .sqlx` with the query
change. `crates/loom-persist/tests/sqlx_offline_default.rs` guards both the
config entry and the presence of the cache.

The manual form, if you must use it, is the same prepare the script runs --
connected as `loom_owner` (the schema owner: `loom_app` cannot `DESCRIBE` the
`security definer` functions) against a migrated database **you own**:

```bash
SQLX_OFFLINE=false DATABASE_URL=postgres://loom_owner:...@host/db \
    cargo sqlx prepare --workspace -- -p loom-persist --tests
```

Note where `-p` goes: sqlx-cli 0.8's `prepare` has no package flag of its own,
so the package and target filters belong after `--`, where they are handed to
the `cargo check` it runs.
