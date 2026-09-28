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

### `owner` and R1

- `owner` (the `uid` field on `BcObject`) is set once, at `load_object`/`clone_object`, from the master's `creator_file(path)`, and never changes for the rest of the object's life. It is the uid every quota below is keyed on for an object (as opposed to the *execution's* quota uid, OBI-35 D-S1.6, which is what player input, a call_out or a heartbeat is charged under).
- **R1:** a load or clone whose current guard set does not already contain the program's own declared uid gets `owner`/`euid` confined to the caller's own quota uid instead. Scoped to the always-unlimited owner uids (`root`, `mudlib`, `domain:*`) rather than to every uid literally — see the doc comment on `RegistryHost::instantiate` for the reasoning (ownership and privilege are orthogonal in this model; R1 only needs to stop a clone from picking up a never-billed uid it has no rights to). Example: a T1 workroom object (owner `appr`) calling `clone_object("/daemons/thing")` (declared uid `mudlib`, not in the caller's guard set) gets a clone owned by, and euid, `appr` — and that clone's `max_objects` count is charged to `appr`.

### Quotas

Every quota is resolved from the S2 `RolesSnapshot`'s `tier_policy` row for a uid (`quota::resolve`), keyed on the execution's quota uid (`max_ticks_exec`, `tick_share_per_min`, `max_callouts_uid`) or on an object's `owner` (`max_mem_exec_mb`, `max_objects`, `max_heartbeats`, `max_callouts_obj`). `root`, `mudlib` and every `domain:*` uid (`quota::is_unlimited_uid`) are always unlimited and never tracked. Every other uid gets the world default for the two quotas every execution/object always has a finite value for, and "no limit" for every count-based quota its tier's policy row does not mention.

| Quota | Keyed on | World default | Enforcement point | On breach |
|---|---|---|---|---|
| `max_ticks_exec` | execution's quota uid | 1,000,000 ticks | `World::exec`'s tick budget | execution errors out (existing tick-exhaustion path); player input still gets the world default even through a T1 object |
| `max_mem_exec_mb` | object's `owner` | 16 MB | `store_global` (per-object vars, spec r6) | write denied, `loom_tier_quota_breaches_total{quota="max_mem_exec_mb"}` |
| `tick_share_per_min` | execution's quota uid | unlimited | a sliding 60 s window checked before a heartbeat/call_out execution starts | the heartbeat/call_out is deferred to a later tick; player input is never deferred |
| `max_objects` | object's `owner` | unlimited | `RegistryHost::instantiate`, before the new object is inserted | `load_object`/`clone_object` denied |
| `max_heartbeats` | object's `owner` | unlimited | `set_heartbeat(true)` | denied (re-subscribing an already-on object never counts twice) |
| `max_callouts_obj` | calling object's `owner` | unlimited | `call_out`, before scheduling | denied |
| `max_callouts_uid` | execution's quota uid | unlimited | `call_out`, before scheduling (separately from `max_callouts_obj`, since one uid's several objects can collectively exceed it) | denied |
| `disk_quota_mb` | the `<u>` in `/builders/<u>/**` | unlimited | `write_file` into that subtree | denied; scoped to `/builders/**` only, keyed on the directory's owner even for a staff/grant write into someone else's tree |

Every denial (except `max_ticks_exec`'s existing tick-exhaustion error and `tick_share_per_min`'s defer, which are not "violations") bumps `loom_tier_quota_breaches_total{tier,quota}`, read back via `Registry::quota_breaches`/`World::quota_breach_count`. There is no metrics-export story for `loom-vm` yet (same caveat as `bcvm::registry::CowMetrics`), so this is an in-process counter table today, not a Prometheus series.

### `program_flags(path)` and confinement

- `program_flags(path)` is a cached master apply (`RegistryHost::ensure_program_flags`), called at most once per path per compile — invalidated by `Registry::install` on every recompile of that path, exactly like `valid_*` decision caching. It returns `CONFINED` (`1`) or `LIVE` (anything else, including no master apply at all — a deliberate fail-open default: this is a data classification, not a privilege decision, so absent a master apply nothing is granted or denied, only `move_to`'s confinement rules stay inactive).
- `move_to` (and `clone_object`'s destination in the mudlib sense — the driver only gates `move_to` itself, since that is the one primitive every mudlib move path funnels through) enforces three rules against the cached flags, a `BcObject::ever_bound` flag (has this object ever had a connection bound to it — the driver's stand-in for "is a player", since "room" vs "player" is not a separate object kind it models) and the mover's/room's tier:
  1. A `CONFINED` object cannot move into a `LIVE` room.
  2. A `CONFINED` object cannot move into a tier-0 player's inventory, but can move into a staff player's.
  3. A tier-0 player cannot enter a `CONFINED` room.
- Every violation returns a runtime error and appends an audit entry (`efun: "move_to"`, `apply: "confinement"`), even though it is a driver rule derived from cached data, not a master `valid_*` decision routed through `authorize`.
- **V7 bench gate:** `check_confinement` is a pure lookup against already-cached data (`program_flags`, `ever_bound`, the roles snapshot's `tier`) — it adds nothing but O(1) map reads to `move_to`'s existing O(depth) cycle-check walk; no master apply runs on this path.

### `valid_upgrade(path)`

A cached master apply, same shape and caching contract as `valid_compile`. `upgrade_all` calls `authorize` with `Operation::Upgrade`, which runs `valid_efun` first (P1) and `valid_upgrade(path, ob)` second — exactly `compile_object`'s order — before doing any of the upgrade's own program-replacement work.

## Audit

Every decision, allowed or denied, is appended to a bounded in-memory ring. Each entry records: caller, efun, class, apply, argument, guard set, verdict, and which euid denied. `World::audit_log()` returns the ring. The Postgres `audit_log` sink is S2 ([OBI-36](https://paperclip.home.oberfield.net/OBI/issues/OBI-36)).
