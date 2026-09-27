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

- **Two-root approval for T4/T5 grants.** Phase 1 has no function that grants
  tier 4 or 5; `roles_bootstrap_root` is an owner-invoked, out-of-band
  bootstrap step. A follow-up will add the two-root approval flow from
  design §5.11.2 ("two-root rule for T4/T5 grants") as a driver-reachable
  path, once OBI-35's effective-principal plumbing lands.
- Domain lifecycle (create/archive) and `staff` row removal (full demotion to
  player) are not yet covered by any `security definer` function.
- **`roles_set_tier` assumes uid == username for new staff.** It binds a new
  `staff` row via `accounts.username = p_target_uid`, so it only works when
  the target's account username matches its intended uid. That assumption
  breaks for a root created by `roles_bootstrap_root` with a uid different
  from its account's username. A follow-up should, for *existing* staff, look
  the account up through `staff.account_id` instead of `accounts.username`;
  for now, new staff must be created with uid == username by convention.
- `roles_set_member` does not reject changes to membership in an `archived`
  domain; a follow-up should add that check alongside the existing `unknown
  domain` check.

## SQLx offline metadata

`loom-persist` uses `sqlx::query!` macros and commits generated metadata under
`.sqlx/` (workspace root) so `cargo check -p loom-persist` can run with
`SQLX_OFFLINE=true` without a database connection.

Refresh metadata after query changes (from the workspace root, connected as
`loom_owner` against a migrated database):

```bash
DATABASE_URL=postgres://loom_owner:...@host/db cargo sqlx prepare --workspace -p loom-persist -- --tests
```
