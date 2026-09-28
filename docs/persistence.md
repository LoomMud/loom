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

- **Snapshot loader**: `connect_persist()` connects `Persist` from `DATABASE_URL` if set. `run_roles_manager`, a dedicated `tokio::spawn`ed task, owns every refresh trigger design §1 lists (boot, `LISTEN roles_changed`, a pulse after every completed mutation, and a timer at the earliest grant expiry) in one loop, converts `RolesRows` to a `loom_vm::RolesSnapshot` (`build_roles_snapshot`) and publishes it on a `watch` channel. The world thread (which cannot itself be async: `World` is `!Send`) polls that channel once per event and calls `World::set_roles_snapshot`. With no `DATABASE_URL`, `spawn_world_thread` instead loads `LOOM_ROLES_SEED` synchronously at boot (`loom_vm::roles::load_seed_from_env`); a malformed seed is a boot failure.
- **Mutation dispatch**: `ChannelRolesMutations` (a `loom_vm::RolesMutations` impl) turns each `roles_*` efun call into a `DbRequest::Roles*` sent to the same DB worker (`loom_persist::spawn_db_worker`/`spawn_dev_account_worker`) that already serves `account_create`/`account_login`; `try_send` never blocks the world thread and reports `false` (queue full/closed) exactly like `ChannelAccountAuth`. Answers come back as `DbEvent::RolesResult`, delivered to `World::deliver_roles_result` by the same drain loop that already handles `DbEvent::AccountResult`, which also pulses `run_roles_manager`'s reload channel.
- **`audit_log` sink**: once per world tick, the world thread calls `World::drain_audit_since` and hands the new rows to `run_audit_sink` (another dedicated task), which appends them via `insert_audit_batch`. No `DATABASE_URL` means no sink task at all -- the rows are computed but never sent anywhere.

## SQLx offline metadata

`loom-persist` uses `sqlx::query!` macros and commits generated metadata under
`.sqlx/` (workspace root) so `cargo check -p loom-persist` can run with
`SQLX_OFFLINE=true` without a database connection.

Refresh metadata after query changes (from the workspace root, connected as
`loom_owner` against a migrated database):

```bash
DATABASE_URL=postgres://loom_owner:...@host/db cargo sqlx prepare --workspace -p loom-persist -- --tests
```
