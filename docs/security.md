# Driver security model (stack-based privilege check)

Normative source: spec r5 §5.7, §5.11.4 and §5.2.2 (D25), and the
[OBI-35 design note](https://paperclip.home.oberfield.net/OBI/issues/OBI-35#document-design)
(D-S1.1 to D-S1.8). This page is the mudlib author's contract.
Implementation: `crates/loom-vm/src/security.rs` and `bcvm::registry::RegistryHost`.

## Principals

- Every object has a **uid**, taken from the master's `creator_file(path)` when it is loaded or cloned. It never changes.
  - `/secure/**` is always `root`.
  - When the master has no `creator_file`, the driver uses this mapping: `/builders/<u>/**` → `<u>`, `/domains/<d>/**` → `domain:<d>`, anything else → `mudlib`.
- Every object also has an **euid**. It starts equal to the uid and changes only through `seteuid(e)`, which is P3 and must pass `valid_seteuid(ob, e)`.
- `getuid()` and `geteuid()` return the calling object's uid and euid.

## The check

The **guard set** is the set of distinct euids on the call stack, down to the nearest cut. `root` never counts. A privileged operation is allowed **iff the master allows it for every euid in the guard set**. If any frame anywhere on the stack is not allowed, the operation is denied. If every frame is root, the guard set is empty and the operation is allowed without asking the master.

Every execution the driver starts is a cut. That covers heartbeats, call_outs, `connect`, player input and `valid_*` applies.

| Efun | Decisions, in order |
|---|---|
| any P1+ efun | `valid_efun(name, class, ob)` |
| `read_file(path)` (P0) | `valid_read(path, ob, "read_file")` |
| `write_file(path, text)` (P1) | `valid_efun`, then `valid_write(path, ob, "write_file")` |
| `compile_object(path)` (P1) | `valid_efun`, then `valid_compile(path, ob)` |
| `upgrade_all(path)` (P1) | `valid_efun`, then `valid_upgrade(path, ob)`, checked after `valid_efun`, mirroring `compile_object` |
| `bind_connection(ob)` (P3) | `valid_efun`, then `valid_bind(caller, ob)` (and the caller must be the master) |
| `seteuid(e)` (P3) | `valid_efun`, then `valid_seteuid(ob, e)` |

- **Inside an apply,** `effective_principal()` returns the euid under evaluation. The driver calls the apply once for each euid in the guard set.
- **Fail closed.** The operation is denied if there is no master, if the master lacks the apply, or if the apply throws, returns a non-bool or runs out of ticks. A master must define at least `valid_efun` before any non-root code can use a P1+ efun.
- **Budget.** An apply runs with its own 50,000-tick budget. The caller is charged 100 ticks per cache miss.
- **`seteuid` is monotone within a frame.** The current frame keeps its old euid in its guard set as well as the new one, so dropping privilege takes effect immediately and raising it only helps frames pushed later.
- **Function values** (landing with OBI-87: closures, named references, call_out targets, `db_query` callbacks) record the guard set at creation. Invoking one runs with `creator ∪ caller`. A scheduled callback runs with exactly its creator's set. There is no delegation mechanism.

## `unguarded(fname, args)`

This efun calls `self.<fname>(args…)` with the guard set restarted at the calling object's own euid, which is root for `/secure` code.

- Only code compiled from `/secure/**` may call it. This is a driver rule, not master policy, and no grant can change it.
- It takes a function **name**, never a function value.
- Every call is audited.
- Use it for the `SECURITY DEFINER` pattern: check the actor's rights yourself, then act as root. An example is `/secure/roles` performing a promotion that the actor's tier allows but the actor's efun classes do not.

## Caching contract

The driver caches decisions per `(apply, euid, argument)`. The argument is the efun name, the path and op, or the euid. It does not cache `valid_bind`.

**A `valid_*` result must depend only on those keys and the roles snapshot.** The `ob` argument is informational, so policy that depends on the object belongs in a non-cached apply.

## The S2 roles snapshot (`loom_vm::roles::RolesSnapshot`)

Normative source: [OBI-36 design note](https://paperclip.home.oberfield.net/OBI/issues/OBI-36#document-design) D-S2.1/D-S2.2. Implementation: `crates/loom-vm/src/roles.rs`, `crates/loom-vm/src/bcvm/registry.rs`'s `roles_*` efun arms.

- The driver holds the tier model (`staff`, `domain_members`, `tier_policy`, `active_grants`) in an immutable `Arc<RolesSnapshot>`, owned by `World`. `World::set_roles_snapshot(snap)` swaps it in **between executions** and calls `flush_security_cache`, so the very next execution both sees the new tier and never serves a `valid_*` decision cached against the old one.
- `/secure/roles.wf` is the snapshot's only mudlib facade. It keeps no Weft-side copy of anything: every question (`tier`, `member`, `lead`, `has_grant`, `policy`, `domains`) is answered by calling a read efun.
- **Dev/CI without Postgres:** set `LOOM_ROLES_SEED` to a JSON file's path and call `loom_vm::roles::load_seed_from_env()` (or build a `RolesSnapshot::from_seed_json` directly) at boot, then `World::set_roles_snapshot`. See `crate::roles` for the seed format. `loom-cli`'s DB-worker loader (OBI-119/S2a) is the Postgres-backed alternative; this crate has no dependency on which one a given boot uses.

### Read efuns: secure-only, not master policy

`roles_tier(uid)`, `roles_is_member(uid, domain)`, `roles_is_lead(uid, domain)`, `roles_has_grant(uid, kind, target)`, `roles_policy(tier)`, `roles_domains(uid)`.

- `Privilege::P0` (no `valid_efun` check, no stack check), but the **immediate calling program** must be compiled from `/secure/**` -- a driver rule, exactly like `unguarded`'s, not master policy. Any other caller gets a runtime error.
- Cheap (1-5 ticks): only `/secure/roles` and the master read policy; nobody else needs to.

### Mutation efuns: async, driver-chosen actor

`roles_set_tier(target, tier, reason)`, `roles_set_member(domain, target, role, reason)`, `roles_grant(target, kind, what, expires_at, reason)`, `roles_revoke_grant(target, kind, what, reason)`, `roles_propose_tier(target, tier, reason)`, `roles_approve(proposal_id)`.

- Async, like `account_create`/`account_login`: each returns a correlation id immediately; the result arrives later through the apply `roles_result(id, ok, detail)` on the calling object (`World::drain_roles_results`, mirroring `drain_account_results`).
- `Privilege::P3`, but **exempt from `valid_efun`** (same reasoning as `unguarded`: a T3 lead's own tier does not include P3, so that check would wrongly deny a legitimate promotion). Gated instead by:
  1. **Secure-only**: the immediate caller must be `/secure/**` (in practice, `/secure/roles`).
  2. **The actor rule**: the actor passed to the backend (and, once S2a lands, to SQL) is **the euid of the interactive whose input started the current execution** -- captured once, at the input cut, by `World::input`, and never re-read. The call is refused if the execution was not started by player input (a call_out, a heartbeat, a `roles_result`/`account_result` drain, `connect`, a driver-started apply/introspection call all have no such actor), and refused if that euid is no longer in the guard set at the point of the call (e.g. a `/secure` cut via `unguarded` restarts the guard at its own root euid, dropping it). **The actor is never a string read from Weft** -- it is resolved purely from the registry's own `BcObject::euid`, never from a function argument.
  3. Every call is audited, allowed or denied.
- The database re-checks rank independently (`docs/persistence.md`); this is the driver's half. `/secure/roles` also checks the actor's rank in Weft before calling, as a fast, friendly refusal.

The cache is dropped whole on any of these events:
- a recompile of anything under `/secure`;
- `World::flush_security_cache` (a roles snapshot swap, or a grant expiry);
- the cache reaching 8,192 entries.

## Per-tier quotas, ownership, and confinement (OBI-121/S2c)

Normative source: [OBI-36 design note](https://paperclip.home.oberfield.net/OBI/issues/OBI-36#document-design) §3, §4, §7. Implementation: `crates/loom-vm/src/quota.rs` (resolution + the `loom_tier_quota_breaches_total{tier,quota}` counter table), `crates/loom-vm/src/bcvm/registry.rs` (every enforcement point).

### `owner`, `uid`, and R1

- `BcObject::uid` is set once, at `load_object`/`clone_object`, from the master's `creator_file(path)`, and **never changes for the rest of the object's life, R1 included** — it stays the single source of truth for "which program declared this".
- `BcObject::owner` is a separate field, also set once at creation. It starts equal to `uid`; **R1** can redirect it (and the object's starting `euid`) to the caller's own quota uid instead. Every owner-keyed quota below (`max_objects`, `max_heartbeats`, `max_callouts_obj`, `max_mem_exec_mb`) is keyed on `owner`, never on `uid`.
- **R1:** a `clone_object` whose current guard set does not already contain `creator_file(path)`'s own euid gets `owner`/starting `euid` set to **the caller's quota uid** instead of `uid` — "the caller's quota uid" is the lowest-tier principal in the current guard set, ties broken by the most recently pushed frame (falls back to the self object's own uid with no roles/tier snapshot, or an empty guard set). Applies to *every* program uid, not only the always-unlimited ones — narrowing it that way is a quota-evasion hole: an apprentice at `max_objects` could otherwise loop `clone_object("/builders/senior/x")` and have every clone billed to `senior` instead.
  - Example (the design note's own "known consequence"): `domain:start` cloning a `domain:forest` NPC gets a clone owned by, and euid, `domain:start` — a domain lead cannot escape their own domain's object-count budget by spawning another domain's NPCs.
  - Example (this task's AC): a T1 workroom object (owner `appr`) calling `clone_object("/daemons/thing")` (declared uid `mudlib`, not in the caller's guard set) gets a clone owned by, and euid, `appr` — and that clone's `max_objects` count is charged to `appr`.
  - **`load_object` does not apply R1** (flagged deviation from a fully literal reading, open for CTO re-review): it returns the same object for a given path to every future caller, so it never multiplies billed objects (not the clone-spam quota evasion R1 targets), and applying R1 there would let whichever caller happens to `load_object` a path first silently steal that path's owner/euid assignment forever — a regression against the pre-existing rule (`security.rs`) that a shared daemon object's own uid/euid do not depend on who first resolved it.

### Quotas

Every quota is resolved from the S2 `RolesSnapshot`'s `tier_policy` row for a uid (`quota::resolve`), keyed on the execution's quota uid (`max_ticks_exec`, `tick_share_per_min`, `max_callouts_uid`) or on an object's `owner` (`max_mem_exec_mb`, `max_objects`, `max_heartbeats`, `max_callouts_obj`). `root`, `mudlib` and every `domain:*` uid (`quota::is_unlimited_uid`) are always unlimited **counts**, but still get the world default for the two per-execution limits every execution/object always has a finite value for (`max_ticks_exec`, `max_mem_exec_mb`) — a mudlib heartbeat with a buggy infinite loop must tick-exhaust at the world default like anything else, not hang the driver. Every other uid gets the same world default for those two, and "no limit" for every count-based quota its tier's policy row does not mention.

| Quota | Keyed on | World default | Enforcement point | On breach |
|---|---|---|---|---|
| `max_ticks_exec` | execution's quota uid | 1,000,000 ticks | `World::exec`'s tick budget | execution errors out (existing tick-exhaustion path); player input still gets the world default even through a T1 object; **also the world default for `root`/`mudlib`/`domain:*`** |
| `max_mem_exec_mb` | object's `owner` | 16 MB | `store_global` (per-object vars, spec r6) | write denied, audited, `loom_tier_quota_breaches_total{quota="max_mem_exec_mb"}` |
| `tick_share_per_min` | execution's quota uid | unlimited | a sliding 60 s window checked before a heartbeat/call_out execution starts | the heartbeat/call_out is deferred to a later tick; player input is never deferred |
| `max_objects` | object's `owner` | unlimited | `RegistryHost::instantiate`, before the new object is inserted | `load_object`/`clone_object` denied (`"object quota exceeded"`), audited |
| `max_heartbeats` | object's `owner` | unlimited | `set_heartbeat(true)` | denied, audited (re-subscribing an already-on object never counts twice) |
| `max_callouts_obj` | calling object's `owner` | unlimited | `call_out`, before scheduling | denied, audited |
| `max_callouts_uid` | execution's quota uid | unlimited | `call_out`, before scheduling (separately from `max_callouts_obj`, since one uid's several objects can collectively exceed it) | denied, audited |
| `disk_quota_mb` | the `<u>` in `/builders/<u>/**` | unlimited | `write_file` into that subtree | denied, audited; scoped to `/builders/**` only, keyed on the directory's owner even for a staff/grant write into someone else's tree |

Every denial (except `max_ticks_exec`'s existing tick-exhaustion error and `tick_share_per_min`'s defer, which are not "violations") bumps `loom_tier_quota_breaches_total{tier,quota}` (`Registry::quota_breaches`/`World::quota_breach_count`) **and** appends an audit entry (`apply: "quota"`, `efun`: the quota's own name), same as every other decision. There is no metrics-export story for `loom-vm` yet (same caveat as `bcvm::registry::CowMetrics`), so the metric is an in-process counter table today, not a Prometheus series.

### `program_flags(path)` and confinement

- `program_flags(path)` is a cached master apply (`RegistryHost::ensure_program_flags`), returning a **bitset**: `CONFINED = 1`, `LIVE = 2`, and `0` (neither) is a real, distinct state — most programs (`/std`, `/secure`, ordinary containers, the void, ...) are neither, and `move_to`'s confinement rules simply stay inactive for them. Absent a master apply (or one that errors), the value is `0`, **not** `LIVE` — this is a data classification, not a privilege decision, so a missing apply must not silently promote every unflagged program to `LIVE`.
- Recomputed **as part of `Registry::install`** (every recompile of the affected paths), not lazily on the next `load_object`/`clone_object` — an already-live clone of a program that just got reflagged `CONFINED` is confined starting with that install, not starting with whenever someone next happens to load/clone that exact path (a confinement bypass window otherwise, since the cache is keyed by path and shared by every existing instance).
- `move_to` enforces three rules against the cached flags, whether the mover/room is **interactive** (`BcObject::conn.is_some()`, i.e. has a connection bound to it *right now*) and the roles snapshot's tier of its **euid** (not its owner/uid — a real mudlib player is a single `mudlib`-owned clone whose euid is `seteuid`'d to the account post-login, so keying on owner/uid would make every player, staff included, read as tier 0):
  1. A `CONFINED` object cannot move into a `LIVE` room.
  2. A `CONFINED` object cannot move into a tier-0 interactive's inventory, but can move into a staff interactive's. This checks `dest`'s **entire environment chain**, not only `dest` itself (folded into `move_to`'s existing O(depth) cycle-check walk, not a second pass) — a confined item cannot be smuggled into a bag that is itself in a tier-0 player's inventory.
  3. A tier-0 interactive cannot enter a `CONFINED` room.
- Every violation returns a runtime error and appends an audit entry (`efun: "move_to"`, `apply: "confinement"`), even though it is a driver rule derived from cached data, not a master `valid_*` decision routed through `authorize`.
- **V7 bench gate:** `check_confinement` is a pure lookup against already-cached data (`program_flags`, `conn`, the roles snapshot's `tier`) — it adds nothing but O(1) map reads to `move_to`'s existing O(depth) cycle-check walk; no master apply runs on this path.

### `valid_upgrade(path)`

A cached master apply, same shape and caching contract as `valid_compile`. `upgrade_all` calls `authorize` with `Operation::Upgrade`, which runs `valid_efun` first (P1) and `valid_upgrade(path, ob)` second — exactly `compile_object`'s order — before doing any of the upgrade's own program-replacement work.

## Audit

Every decision, allowed or denied, is appended to a bounded in-memory ring. Each entry records: caller, efun, class, apply, argument, guard set, verdict, and which euid denied. `World::audit_log()` returns the ring. The Postgres `audit_log` sink is S2 ([OBI-36](https://paperclip.home.oberfield.net/OBI/issues/OBI-36)).
