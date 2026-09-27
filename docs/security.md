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

The cache is dropped whole on any of these events:
- a recompile of anything under `/secure`;
- `World::flush_security_cache` (a roles snapshot swap, or a grant expiry);
- the cache reaching 8,192 entries.

## Audit

Every decision, allowed or denied, is appended to a bounded in-memory ring. Each entry records: caller, efun, class, apply, argument, guard set, verdict, and which euid denied. `World::audit_log()` returns the ring. The Postgres `audit_log` sink is S2 ([OBI-36](https://paperclip.home.oberfield.net/OBI/issues/OBI-36)).
