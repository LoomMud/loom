# Typed HIR (loom-compiler → V2 codegen) — r3

Status: **agreed** (CTO review on OBI-24, r1 approved 2026-09-26; r2 applies
decision D23 and conditions C1–C4 from that review; r3 updates C1 and C3 for
design spec r5 §5.2.1/§5.2.2, D24/D25, delivered by OBI-53). Source of truth for the Rust types: `crates/loom-compiler/src/hir.rs`.
Run `loom-cli check <mudlib> --dump-hir` to see the HIR of real programs;
`crates/loom-compiler/tests/golden/hir_*.out` are checked-in examples.

## Pipeline position

```
source ─► loom-syntax (AST) ─► loom-compiler: declarations (inherit graph,
          interfaces) ─► bodies (resolve + gradual type check + narrowing)
          ─► typed HIR  ─► V2: IR ─► register bytecode ─► verifier
```

One `hir::Program` per source file. A program is checked against its parents'
**interfaces** (`interface::ProgramInfo`: visible functions and variables with
types and declaring program), never their bodies, so a child only needs a
recompile when a parent's interface changes.

## Data model

| Node | Purpose |
|---|---|
| `Program { path, inherits, linearization, vars, fns }` | `linearization`: every program whose variables an instance holds, root first, each **once** (virtual inheritance; a diamond shares one copy), ending with this program. Instance layout is per linearization entry. |
| `Inherit { label, path, span }` | Direct parents in source order; `label` for `inherit combat = /std/mixins/combat`. |
| `Var { name, ty, vis, persistent, init }` | Variables declared *here*. `init` runs with `self` = the object on creation and when hot reload cannot keep the old value. `None` ⇒ `null` (only allowed for nullable types). |
| `Function { name, vis, is_override, params, ret, locals, body }` | `locals`: parameters first, then every binding in order; ids never reused (the allocator may share registers of disjoint scopes). `ret = Void` for no `-> T`. |
| `Param { local, default }` | Defaults are filled **callee-side** (see below). |
| `Stmt`: `Let`, `Assign{place, op, kind, value}`, `If`, `While`, `For{local, iter, kind}`, `Return`, `Expr` | `else if` is a nested `If`; compound assignment keeps `op` + operand `kind`, place evaluated once. |
| `Place`: `Local`, `Global(GlobalRef)`, `Index{base, index, kind}` | |
| `Expr { kind, ty, span }` | Every expression carries its static type (after flow narrowing). |
| `GlobalRef { owner, name }` | A program variable keyed by **(declaring program, name)** — the §7.3 state-migration key. |
| `Callee::Virtual { name }` | Unqualified call to a non-private function: look up `name` on the running object's *current* program (hot-reload friendly). |
| `Callee::Static { program, name }` | Private functions, `super::f()`, `label::f()`: a fixed program's body. `program` is the *declaring* program (e.g. `super::g()` reaching `/a` through `/b` is `Static{/a, g}`). |
| `CallEfun { name, privilege, args }` | `privilege` is **advisory** (C2): diagnostics and tooling only. The VM gate looks the class up in its own efun registry by efun identity and never reads it from HIR or bytecode; the verifier checks the two agree. |
| `CallOther { recv, name, args, safe }` | `ob.f()` / `ob?.f()`; late-bound by name, result `any`. |
| `CallValue { callee, args }`, `FnRef(Callee)` | Function values (`add_verb("wield", do_wield)`); type `fn(A) -> R`. Semantics in "Function values" below. |
| `Cast(expr)` | Runtime-checked conversion to `Expr::ty`: **the gradual boundary**. |
| `Index { kind: Array \| String \| Map \| MapPresent \| Dyn }` | `Map`: missing key reads `null`, type `V?`. `MapPresent`: key proven by an enclosing `k in m`; type `V`, but codegen must still raise if the key vanished. |
| `Unary/Binary { op, kind: OpKind }` | Operand kind resolved (`Int`, `Float`, `Str`, `Bool`, `Array`, `Map`, `Object`, `Generic`, `Dyn`) so codegen picks typed instructions; only `Dyn` dispatches at runtime. `And`/`Or`/`Coalesce` are separate short-circuit nodes. |

## Invariants V2 may rely on

1. Every name is resolved; no string lookups remain except `Callee::Virtual`
   and `CallOther` (both intentionally late-bound, §5.4).
2. A program with diagnostics produces **no HIR**; `Ty::Error` never appears in
   emitted HIR (property-tested in `tests/props.rs`).
3. **Static types are an optimisation contract, not a memory-safety
   guarantee (C1).** Arrays, maps and structs are **value types with
   copy-on-write storage** (spec r5 §5.2.1, D24): assignment, argument
   passing, `return`, closure capture, storing into a container and storing
   into an object variable each produce a logical copy, so a write through
   one name is never visible through another. This closes the aliasing
   route the earlier (reference-semantics) design relied on for its main
   soundness gap: an `[any]` alias of a `[string]` can no longer write an
   `int` into the typed view, because the write lands in a copy, not the
   original buffer. `copy()` is removed from the efun table (r5.5) — it has
   no meaning once containers are values, and it must not be re-added.
   Codegen's **tag-safe** typed instructions (`AddInt`, `IndexArr`, …) stay
   as defence in depth regardless: `Cast` is shallow (it checks the
   value's kind and nullability only, O(1); element types are not walked),
   so a value nested inside a container can still carry an unexpected tag
   after a cast at a shallow boundary. The fast path assumes the static
   kind, and a value with the wrong tag raises a runtime error — never a
   panic, never undefined behaviour. The *points where a well-typed program
   is expected to need a check* are `Cast`, `IndexKind::MapPresent`,
   `OpKind::Dyn`/`IterKind::Dyn`/`IndexKind::Dyn`, `CallOther` (missing
   function / non-`pub`) and `CallValue` on an `any` callee; everywhere else
   a tag mismatch indicates an `any` alias and is still caught by the
   typed instruction. (Integer overflow, index bounds, destructed objects
   stay runtime errors.)
   **Codegen must not create spurious sharing**: an element write
   (`a[i] = v`, `m[k] op= v`, a nested `a[i][j] = v`) lowers as *take →
   mutate → put back* through every level of the path down to its root
   local or program variable (spec r5 §5.2.1 rule 3, OBI-53); a lowering
   that reads a container into a register and mutates that register
   without writing it back would silently lose the write under value
   semantics (see `FnLower::take_place`/`put_back_place` in `codegen.rs`).
   **`Cast` is shallow**: it checks the value's kind and nullability only
   (`[string]` ⇒ "is an array"), O(1). Element types are not walked; element
   reads are covered by the tag-safe instructions above.
4. Control flow: a non-void function's body never falls off the end (checked),
   so codegen needs no implicit `return null` for typed functions.
5. `LocalId`s are dense per function; `Function::locals[i].ty` is the declared
   type (narrowing never changes a slot's type, only the type of a *use*).

## Function values (C3)

Evaluating `FnRef(callee)` (and, with V0, a closure literal) creates a value
that binds **(creator object, callee)** at creation time. Spec r5 §5.2.2
(D25) supersedes the simpler "creator rights only" rule this section
previously described:

- Invoking a function value pushes a synthetic **creator frame** carrying
  the principal captured at creation time onto the privilege stack, below
  the callee's own frame. The effective principal for the call is
  `min(creator principal, every frame currently on the stack)` — the lower
  of the creator's and the caller's rights, not the creator's alone. A
  closure never lends its creator's rights to a lower-privileged caller
  (closes the callback confused-deputy hole `secure_stack_check` alone
  does not cover). A scheduled call (`call_out`, a `db_query` callback) has
  no other frames, so it runs with exactly the creator principal.
- For `Callee::Virtual` the name is still looked up at call time on the
  creator's *current* program (hot-reload friendly); `Static` still runs
  the fixed body.
- **Version pinning.** An anonymous closure keeps running the code version
  it was created with after its creator's program is upgraded (with a
  warning on first use per site, `loom_stale_closure_calls_total`); the old
  program version is kept alive by a refcount from its closures. A named
  reference re-resolves on the creator's current program, as before.
- If the creator has been destructed, the call raises `object was
  destructed`.
- **Never persisted (r5 rule 4, OBI-53):** the checker rejects a
  `persistent` variable whose type is or contains `fn(...)` — directly, in
  an array/map, or (once structs are checked) in a struct field — with
  `W0294`. A function value pins a code version and a principal that may
  not survive a reboot.

A function value is therefore a capability: its runtime representation and
invocation path (the synthetic creator frame, version pinning) are a V3/VM
security review item.

## Defaults are callee-side

A call passes only the arguments written at the call site. The callee's
prologue evaluates `Param::default` for missing trailing arguments (the
bytecode needs an "arg count" in the frame). Rationale: a hot reload that
changes a default must not require re-linking callers, and virtual dispatch
means the caller cannot know which override's defaults apply.

## Type system as implemented (§5.2)

- Strict by default: annotations required on parameters and on program
  variables without an initialiser; locals are inferred; `null` alone cannot
  seed an inferred type.
- Consistent subtyping: `any` is consistent with everything (both ways, with a
  `Cast` when leaving `any`); `T <: T?`; `null <: T?`; containers invariant up
  to `any` (reference semantics); `fn` types contravariant in parameters.
- Nullability with flow narrowing of **locals and parameters**: `x != null`,
  `x == null` + early return, `and`/`or`/`not`, `while x != null`; assignment
  of a non-null value narrows, any assignment ends a narrowing; loops drop
  narrowings of locals assigned in the body. Program variables are never
  narrowed (a call could change them) — the diagnostic says to copy into a
  local or use `?.`.
- Conditions are `bool` only (or `any`, cast at runtime), with a hint that
  names the explicit comparison for the offending type.
- Overrides: `override` required and checked (Phase 0 rules), plus: same
  parameter types, compatible return type, may not narrow `pub`.
- **Stored object references (D23):** a program variable (later also struct
  fields) whose type would be `object` is an error — it must be `object?`,
  because it outlives the execution and the object may be destructed.
  Locals, parameters, return values and container elements may be `object`.
  VM semantics: a stale handle compares `== null` as true anywhere;
  dereferencing it through an `object`-typed value (CallOther, an efun object
  argument) raises `object was destructed`, never a panic.

## Decisions (CTO review, OBI-24)

1. **D23 stored `object` references** — see the type-system section;
   supersedes the spec §5.2 wording "every stored reference is `object?`"
   (spec text update tracked by the CTO).
2. **`m[k]` is `V?`**, with `IndexKind::MapPresent` after `k in m`.
3. **An override of a `pub` function must be `pub`.**
4. **Efun metadata seam:** `loom-compiler::efuns` owns the compile-time half
   (types, privilege for diagnostics) until V6 (OBI-33) builds the unified
   registry, subject to C2 (the VM registry is authoritative).
5. **C4 (planned for V7 hot reload):** `Program` gains an interface
   fingerprint (hash of the exported `ProgramInfo`: function signatures,
   variable types, linearization) so "a child recompiles only when a parent's
   interface changes" is checkable mechanically. Not implemented in r2.

## Pending the V0 grammar (OBI-23)

The resolver and HIR already model these; they are wired as soon as the
parser produces them:

- `inherit label = /path` and multiple inherits: `ParentInfo.label`,
  dominance-based resolution, ambiguity and label diagnostics, `label::f()`
  → `Callee::Static` (tested in `tests/inherit_graph.rs` by building the
  parent list directly).
- Closures `fn(x) => …` and the `fn(A) -> R` type syntax: `Ty::Fn`,
  `CallValue` exist; closures add `ExprKind::Closure { params, captures,
  body }` (captures by value, listed explicitly for codegen).
- `import` / `const` / `enum` / `struct`: planned as module-level symbols
  in the resolver; `const` folds to literals in HIR, enums add
  `ExprKind::Variant`, `match` adds `StmtKind::Match` with exhaustiveness.
- `protected` / `final` (`FnInfo.is_final` + the "cannot override `final`"
  diagnostic are in place), `atomic` (flag on `Function`), `try/catch/throw`
  (`Ty::Never` for `throw`), named args, `if let`, float literals, slices.

## Known deviations / risks

- `loom check` now uses this checker; `loom serve` still runs the Phase 0
  linker + tree-walker until V2/V3 land. The checker is stricter (so
  `check`-clean code runs), except function values (`FnRef`), which the
  checker accepts and the Phase 0 runtime does not.
- Apply signatures (`process_input(line: string)` etc.) are not checked yet.
