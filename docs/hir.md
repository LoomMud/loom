# Typed HIR (loom-compiler → V2 codegen) — draft r1

Status: **draft for review** (OBI-24 → Aragorn, and the V2 owner before codegen
starts). Source of truth for the Rust types: `crates/loom-compiler/src/hir.rs`.
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
| `CallEfun { name, privilege, args }` | `privilege` is the efun's class (§5.5); the VM gate goes here. |
| `CallOther { recv, name, args, safe }` | `ob.f()` / `ob?.f()`; late-bound by name, result `any`. |
| `CallValue { callee, args }`, `FnRef(Callee)` | Function values (`add_verb("wield", do_wield)`); type `fn(A) -> R`. |
| `Cast(expr)` | Runtime-checked conversion to `Expr::ty`: **the gradual boundary**. |
| `Index { kind: Array \| String \| Map \| MapPresent \| Dyn }` | `Map`: missing key reads `null`, type `V?`. `MapPresent`: key proven by an enclosing `k in m`; type `V`, but codegen must still raise if the key vanished. |
| `Unary/Binary { op, kind: OpKind }` | Operand kind resolved (`Int`, `Float`, `Str`, `Bool`, `Array`, `Map`, `Object`, `Generic`, `Dyn`) so codegen picks typed instructions; only `Dyn` dispatches at runtime. `And`/`Or`/`Coalesce` are separate short-circuit nodes. |

## Invariants V2 may rely on

1. Every name is resolved; no string lookups remain except `Callee::Virtual`
   and `CallOther` (both intentionally late-bound, §5.4).
2. A program with diagnostics produces **no HIR**; `Ty::Error` never appears in
   emitted HIR (property-tested in `tests/props.rs`).
3. Soundness needs runtime checks only at `Cast`, `IndexKind::MapPresent`,
   `OpKind::Dyn`/`IterKind::Dyn`/`IndexKind::Dyn`, `CallOther` (missing
   function / non-`pub`), and `CallValue` on an `any` callee. Everything
   else is statically typed: codegen may emit unchecked typed instructions.
   (Integer overflow, index bounds, destructed objects stay runtime errors.)
4. Control flow: a non-void function's body never falls off the end (checked),
   so codegen needs no implicit `return null` for typed functions.
5. `LocalId`s are dense per function; `Function::locals[i].ty` is the declared
   type (narrowing never changes a slot's type, only the type of a *use*).

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

## Decisions requested (Aragorn)

1. **Stored `object` references.** Spec §5.2 says the static type of any
   stored reference is `object?` because destructed objects read as `null`.
   Implemented instead: a declared `object` stays `object`; destructed
   references are a runtime error at use (call/efun), not a static one.
   Treating every stored reference as `object?` would reject most of Warp
   (`for ob in inventory(env) { ob.visible() }`). Proposal: keep this, and
   make the VM raise "object was destructed" when a destructed ref is read
   from an `object`-typed slot. Needs your call.
2. **`m[k]` is `V?`** (matches runtime: missing key reads `null`), softened
   by `MapPresent` after `k in m`. Alternative: `V` with a runtime error on a
   missing key. I prefer `V?` (strict, honest).
3. **Override visibility**: an override of a `pub` function must be `pub`.
   Needed because `ob.f()` only reaches `pub`; the VM tworoom fixture had
   this bug (`override fn long` in rooms) and was fixed in this change.
4. **Efun signatures** live in `loom-compiler::efuns` until V6 (OBI-33)
   builds the unified registry (types + tick cost + privilege). A test keeps
   names/arity in sync with `loom-vm`. This is the "efun metadata" seam —
   confirming it is OK for V1 to own the compile-time half until V6.

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
