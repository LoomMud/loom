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

## Audit

Every decision, allowed or denied, is appended to a bounded in-memory ring. Each entry records: caller, efun, class, apply, argument, guard set, verdict, and which euid denied. `World::audit_log()` returns the ring. The Postgres `audit_log` sink is S2 ([OBI-36](https://paperclip.home.oberfield.net/OBI/issues/OBI-36)).
