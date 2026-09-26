# Weft — v1 grammar and implementation status

This is the reference for the Weft language as implemented in this repo. It
supersedes `docs/weft-phase0.md` (OBI-23).

- **Part 1** is the full v1 grammar of spec v2 §5.3, which `loom-syntax`
  parses into a spanned AST (`crates/loom-syntax/src/ast.rs`).
- **Part 2** says, for each construct, what is *parsed* vs. what *runs* today.
  The Phase 0 tree-walking evaluator in `loom-vm` only runs a subset. Every
  construct outside it gets a spanned `…: not yet supported by the Phase 0
  evaluator` diagnostic from `loom check` / `compile_object`. It never panics
  and never silently mis-runs (`loom_vm::subset::phase0_gate`).
- **Part 3** is the Phase 0 runtime reference (types, efuns, applies, hot
  reload, guard rails) for the subset that executes today.

Check a mudlib without running it:

```
loom-cli check <mudlib-root>     # parses + gates + links every .wf file, exit 1 on errors
```

---

# Part 1 — Grammar (parsed by `loom-syntax`)

## Lexical structure

- **Statements end at a newline**; `;` is optional and also separates
  statements on one line. Newlines are insignificant inside `()`, `[]`, `{…}`
  literals and argument lists, after a binary operator, after `=` and after
  `=>`. Braces are mandatory for every body.
- **Comments:** `// line` and `/* block */` (block comments nest).
- **Identifiers:** `[A-Za-z_][A-Za-z0-9_]*`. `_` alone is the wildcard pattern.
- **Keywords (reserved):** `inherit import const var let fn pub protected
  private persistent override final atomic lightweight struct enum if else for
  in while break continue return match try catch throw true false null and or
  not super as`. `self`, `int`, `float`, `string` etc. are ordinary names.
- **Integers:** decimal, `_` separators: `42`, `1_000`. Out of range for i64
  is an error, with a hint to use a float.
- **Floats:** `2.5`, `1_000.25`, `1e20`, `1.5e-3`, `2E3`. `1..3` is a range
  (not a float) and `3.abs()` is a method call on `3`. Non-finite literals
  (`1e999`) are an error.
- **Strings:** `"…"` with escapes `\n \t \r \0 \" \\ \{ \}`. Single line.
  Interpolation: `$"Hello {name}, {len(xs)} items"` (any expression, nested
  strings allowed).
- **Operators and punctuation:** `+ - * / % == != < <= > >= = += -= *= /= %=
  ?? ?. . .. ... :: : , ; -> => | ? ( ) [ ] { }`.
- **LPC/C-isms get targeted errors.** `!`, `&&`, `||` and `&` are reported
  with a hint and then parsed as `not`/`and`/`or`, so there is no cascade.
  `#include`-style lines are rejected as a whole ("no preprocessor"). `->` as
  a call operator and `|` outside patterns are also rejected.

## Grammar (EBNF sketch)

`NL` is a newline. `{ x }` means zero or more, `[ x ]` optional. Lists in
brackets allow newlines and a trailing comma.

```ebnf
program     = header* item* ;
header      = "lightweight" NL
            | "inherit" [ IDENT "=" ] path NL          (* labelled: combat = /std/combat *)
            | "import" path [ "." ( "{" IDENT { "," IDENT } "}" | IDENT ) ] NL ;
path        = "/" seg { "/" seg } ;                    (* no spaces, no quotes, no ".wf" *)
seg         = word-chars and "-" ;

item        = mods ( var | const | fn | struct | enum ) ;
mods        = { "pub" | "protected" | "private" | "persistent"
              | "override" | "final" | "atomic" } ;    (* at most one visibility *)
var         = "var" IDENT [ ":" type ] [ "=" expr ] NL ;   (* type or init required *)
const       = "const" IDENT [ ":" type ] "=" expr NL ;
fn          = "fn" IDENT params [ "->" type ] block ;
params      = "(" [ param { "," param } ] ")" ;
param       = [ "..." ] IDENT [ ":" type ] [ "=" expr ] ; (* ...rest last, no default *)
struct      = "struct" IDENT "{" { field SEP } "}" ;
field       = IDENT ":" type [ "=" expr ] ;
enum        = "enum" IDENT "{" { variant SEP } "}" ;
variant     = IDENT [ "(" type { "," type } ")" ] ;
SEP         = "," | NL ;

type        = base { "?" } ;
base        = "int" | "float" | "bool" | "string" | "object" | "any" | "error"
            | "null" | IDENT                           (* struct / enum / imported *)
            | "[" type "]" | "{" type ":" type "}"
            | "fn" "(" [ type { "," type } ] ")" [ "->" type ]
            | "(" type ")" ;                           (* (fn(int) -> int)? *)

block       = "{" { stmt ( NL | ";" ) } "}" ;
stmt        = ( "let" | "var" ) IDENT [ ":" type ] [ "=" expr ]   (* let needs "=" *)
            | target assign-op expr                   (* target: x, a[i], p.f *)
            | "if" cond block [ "else" ( block | if ) ]
            | "while" expr block
            | "for" IDENT "in" expr block
            | "break" | "continue"
            | "return" [ expr ]
            | "try" block "catch" [ IDENT ] block
            | "throw" expr
            | expr ;
cond        = expr | "let" IDENT [ ":" type ] "=" expr ;   (* if let *)
assign-op   = "=" | "+=" | "-=" | "*=" | "/=" | "%=" ;

expr        = pratt ;                                  (* table below *)
postfix     = primary { "." IDENT [ args ] | "?." IDENT [ args ]
                      | "[" expr "]" | "[" [ expr ] ".." [ expr ] "]"
                      | args } ;
args        = "(" [ arg { "," arg } ] ")" ;
arg         = expr | IDENT ":" expr | "..." expr ;     (* named args after positional *)
primary     = INT | FLOAT | STRING | INTERP | "true" | "false" | "null"
            | IDENT [ args ]                           (* call *)
            | IDENT "::" IDENT args                    (* labelled inherit call *)
            | "super" "::" IDENT args
            | IDENT "{" [ IDENT ":" expr { "," … } ] "}"   (* struct literal *)
            | "." IDENT [ args ]                       (* enum variant, enum inferred *)
            | "fn" params [ "->" type ] ( "=>" expr | block )   (* closure *)
            | "match" expr "{" { arm SEP } "}"
            | "(" expr ")" | "[" exprs "]" | "{" kvs "}" | "{:}" ;
arm         = pattern [ "if" expr ] "=>" ( expr | block ) ;
pattern     = single { "|" single } ;
single      = "_" | IDENT | literal | [ "-" ] number
            | [ IDENT ] "." IDENT [ "(" pattern { "," pattern } ")" ] ;
```

### Precedence (loosest first)

| Level | Operators |
|---|---|
| 1 | `or` |
| 2 | `and` |
| 3 | `not` (prefix) |
| 4 | `==` `!=` `<` `<=` `>` `>=` `in` (non-associative: `a < b < c` is an error) |
| 5 | `??` (right-assoc) |
| 6 | `+` `-` |
| 7 | `*` `/` `%` |
| 8 | `e as T` (postfix cast) |
| 9 | unary `-` (so `-x as float` is `(-x) as float`) |
| 10 | calls `f()`, `ob.f()`, `ob?.f()`, field `p.x`/`p?.x`, index `a[i]`, slice `s[1..3]`, apply `fs[0](x)` |

### Disambiguation rules

- **Struct literals vs. bodies.** `Name {` starts a struct literal, except in
  the head of `if`, `if let`, `while`, `for … in` and `match`. There `{` opens
  the body, so write `if p == (Point { x: 1 }) { … }`. Inside any brackets
  struct literals are allowed again.
- **`a.b` without a call** is a `Field` node. It can be a struct field or a
  qualified enum variant (`DamageKind.slash`); the compiler resolves it.
  `Kind.B(3)` parses as a method-style call, which the compiler resolves to a
  variant constructor.
- **`.name` in expression position** is an enum variant whose enum is inferred
  from the expected type: `var kind: DamageKind = .slash`, `.Crit(10, "head")`.
- **`label::f()`** calls `f` in the parent labelled `label`. `super::f()`
  calls the (single or first) parent. `::` must be followed by a call; enum
  variants never use `::`.
- **`match` arms** end at a newline or `,`. An arm body starting with `{` is a
  block, so to return a map literal, parenthesise it: `_ => ({"k": 1})`.
- **`fn(` at the start of a statement** is a closure expression (so
  `fn() { … }()` works). `fn name` is a declaration. Inside a block that is
  read as a missing `}` before the next declaration.
- **Header order.** `lightweight`, `inherit` and `import` may be mixed, but
  must all come before the first declaration.

### The spec §5.3 example

`crates/loom-syntax/tests/golden/spec_weapon.wf` is the §5.3 sketch verbatim.
It parses cleanly and its AST is pinned in `spec_weapon.out`.

---

# Part 2 — What is parsed vs. what runs

"Parsed" means a spanned AST node plus golden tests (success and diagnostic)
under `crates/loom-syntax/tests/golden/<construct>{,_err}.wf`. "Runs" means
the Phase 0 evaluator executes it. Everything that parses but does not run is
rejected by the Phase 0 gate with a span, a message ending in `not yet
supported by the Phase 0 evaluator`, and a workaround hint where there is one
(golden: `crates/loom-vm/tests/fixtures/gate/v1_constructs.out`).

| Construct | AST | Parsed | Runs (Phase 0) | Planned owner |
|---|---|---|---|---|
| `int`, `bool`, `string`, `object`, `any`, `null`, `T?`, `[T]`, `{K: V}` | `TypeKind::*` | yes | yes | — |
| `float` type and literals | `TypeKind::Float`, `ExprKind::Float` | yes | no | V1/V3 (OBI-24, OBI-31) |
| `error` type | `TypeKind::Error` | yes | no | V5 (OBI-32) |
| function types `fn(A) -> R` | `TypeKind::Fn` | yes | no | V1/V5 |
| `struct` decl / literal / field `p.x` | `Item::Struct`, `ExprKind::StructLit`, `ExprKind::Field` | yes | no | V1/V3 |
| `enum` decl / `.A`, `Kind.A`, `.B(x)` | `Item::Enum`, `ExprKind::Variant` / `Field` / `Method` | yes | no | V1/V3 |
| `match` with literal, binding, `_`, variant, `\|` patterns and `if` guards | `ExprKind::Match`, `Pattern` | yes | no | V1/V2 |
| closures `fn(x) => e` / `fn(x) { … }`, computed calls `f(x)(y)` | `ExprKind::Closure`, `ExprKind::Apply` | yes | no | V5 (OBI-32) |
| function references `add_verb("v", do_it)` | `ExprKind::Ident` | yes | no (link error: "function values arrive in Phase 1") | V1/V5 |
| `try { } catch [e] { }`, `throw e` | `StmtKind::Try`, `StmtKind::Throw` | yes | no | V5 (OBI-32) |
| named args `f(x, exclude: [me])`, spread `f(...xs)` | `Arg { name, spread }` | yes | no | V1 |
| `...rest` params | `Param::rest` | yes | no | V1 |
| default args `fn f(a, b = 2)` | `Param::default` | yes | yes | — |
| single `inherit /p` + `super::f()` | `Program::inherits`, `SuperCall { label: None }` | yes | yes | — |
| labelled + multiple `inherit`, `label::f()` | `Inherit::label`, `SuperCall { label }` | yes | no | V1 (OBI-24) |
| `import /p.{A, B}` / `import /p` | `Program::imports` | yes | no | V1 |
| `const` | `Item::Const` | yes | no | V1 |
| `if let x = e { } else { }` | `StmtKind::IfLet` | yes | no | V1/V2 |
| slices `s[1..3]`, `s[..3]`, `s[1..]`, `s[..]` | `ExprKind::Slice` | yes | no | V3/V6 |
| `e as T` | `ExprKind::Cast` | yes | no | V1 |
| `break`, `continue` | `StmtKind::Break` / `Continue` | yes | no | V2 |
| `*=`, `/=`, `%=` | `AssignOp::{Mul, Div, Rem}` | yes | no | V2 |
| field assignment `p.x = e` | `Assign { target: Field }` | yes | no | V1/V3 |
| `pub`, `private`, `persistent`, `override` | `Modifiers` | yes | yes (`persistent` = plain `var`) | V4 for saving |
| `protected`, `final` | `Modifiers` | yes | no | V1 |
| `atomic fn` | `Modifiers::atomic` | yes | no | V5 (OBI-32) |
| `lightweight` | `Program::lightweight` | yes (provisional syntax, see below) | no | V3 |
| `upgrade(from_version, old)` apply | ordinary `fn` | yes | not called | V4 (OBI-34) |

### Spec gaps filled by this parser (for CTO review)

§5.3 is a *sketch*, so a few surface choices were made here. Each one is
recorded so the spec can adopt or overrule it:

1. **`lightweight`** is a header line of its own (spec §5.2 names the concept
   but gives no syntax).
2. **`catch` binding is optional**: `catch { … }` is allowed as well as
   `catch e { … }`.
3. **`import /p.Name`** (a single name without braces) is accepted besides
   `import /p.{A, B}` and whole-module `import /p`.
4. **Call-site spread `f(...xs)`** mirrors `...rest` params.
5. **Compound assignment** adds `*=`, `/=`, `%=` next to the Phase 0 `+=`/`-=`.
6. **`break`/`continue`** are included (the spec does not mention them).
7. **`as` precedence** is Rust-like (above `*`, below unary `-`).
8. **Not included** (not in the spec): `while let`, range expressions outside
   slices (`for i in 0..n`), inclusive `..=`, struct patterns in `match`,
   struct-literal field shorthand `P { x }`, hex/binary literals, `finally`.
   Each gets a targeted diagnostic where a builder is likely to try it.

---

# Part 3 — Phase 0 runtime reference (what executes today)

## Programs and objects

- **One file = one program.** `/domains/start/hall.wf` is program
  `/domains/start/hall`. The blueprint object has the program's name; clones are
  named `/path#N`.
- **Single inherit** (the first `inherit`; more are gated), first in the file: `inherit /std/room` (unquoted path, no
  extension). `super::fn(args)` calls the parent's version.
- **`override` is required** to redefine an inherited function, and is an error
  when nothing is overridden. Redeclaring an inherited variable is an error.
- Top-level declarations that run: variables and functions (`const`, `struct`
  and `enum` parse but are gated, see Part 2).

```weft
inherit /std/room

persistent var visits: int = 0          // `persistent` parses; same as `var` in Phase 0
private var secret: string = "x"
var exits: {string: string} = {:}

override fn create() {
    super::create()
    set_short("The Great Hall")
}

pub fn describe(viewer: object?, brief: bool = false) -> string {
    visits += 1
    return $"{short()} ({visits} visits)"
}
```

### Visibility

| Modifier | Functions | Variables |
|---|---|---|
| `pub` | callable from other objects via `ob.fn()` | (same as default) |
| *(default)* | this program and inheritors (unqualified calls only) | this program and inheritors |
| `private` | this program only; not inherited, not overridable | this program only |

The driver calls applies (`create`, `connect`, `logon`, `process_input`,
`net_dead`) regardless of visibility.

## Types

`int` (64-bit, overflow is an error), `bool`, `string`, `object`, `T?`
(e.g. `object?`), `[T]`, `{K: V}`, `any`, `null`.

- Annotations are required on program variables *or* an initialiser must be
  given; locals are inferred.
- Types are checked **at runtime** in Phase 0: parameters on call, return values,
  assignments to annotated variables/locals, variable initialisers. Element
  types of arrays/maps are not checked.
- **No truthiness.** `if`/`while` conditions and `and`/`or`/`not` operands must
  be `bool`. Write `x != null`, `len(xs) > 0`.
- Arrays and maps have reference semantics. Maps keep insertion order; keys must
  be `int`, `string`, `bool` or `object`.

## Statements

Newline-terminated (`;` optional, also separates statements on one line).
Braces are mandatory. Newlines are ignored inside `()`, `[]`, `{}` literals and
after a binary operator.

| Statement | Notes |
|---|---|
| `let x = e`, `let x: T = e` | immutable local (assignment is a compile error) |
| `var x = e`, `var x: T`, `var x: T = e` | mutable local |
| `x = e`, `x += e`, `x -= e` | also `a[i] = e`, `m[k] += e` |
| `if c { } else if c { } else { }` | `else` may start on the next line |
| `while c { }` | |
| `for x in xs { }` | arrays; maps iterate their keys. Iterates a snapshot. `x` is immutable |
| `return`, `return e` | falling off the end returns `null` |
| expression statement | usually a call |

## Expressions

Precedence, loosest first:

| Level | Operators |
|---|---|
| 1 | `or` |
| 2 | `and` |
| 3 | `not` (prefix) |
| 4 | `==` `!=` `<` `<=` `>` `>=` `in` (non-associative: `a < b < c` is an error) |
| 5 | `??` (right-assoc) |
| 6 | `+` `-` |
| 7 | `*` `/` `%` |
| 8 | unary `-` |
| 9 | calls `f()`, `ob.f()`, `ob?.f()`, indexing `a[i]` |

- Literals: `42`, `1_000`, `"text"` (escapes `\n \t \r \0 \" \\ \{ \}`), `true`,
  `false`, `null`, `[1, 2]`, `{"k": 1}`, empty map `{:}`.
- Interpolation: `$"Hello {name}, you have {len(items)} items"`.
- `+` works on int+int, string+string (build mixed strings with `$"…"`) and
  array+array (new array). `==` compares primitives/strings by value, objects by
  identity, arrays/maps by reference.
- `in`: element of array, key of map, substring of string.
- `a ?? b`: `a` unless it is `null`.
- Indexing: arrays and strings by int (out of range is an error), maps by key
  (missing key reads as `null`).
- `name(args)`: a function of this program or an ancestor (virtual dispatch on
  the object's current program; `private` functions resolve to the calling
  program's own), otherwise an efun. Unknown names are **link-time errors**.
- `ob.fn(args)`: late-bound call to a `pub` function; a missing function or a
  non-`pub` one is a runtime error. `ob?.fn(args)` yields `null` if `ob` is
  `null`. Objects have no fields.
- `self` (or `self()`) is the current object.
- Default arguments: `fn f(a: int, b: int = 2)`; defaults must come last.

## Efuns

| Efun | Signature / behaviour |
|---|---|
| `self()` | current object |
| `this_player()` | the player whose input/connection started this execution, or `null` |
| `load_object(path) -> object` | blueprint, compiling/loading it (and running `create()`) if needed |
| `clone_object(path) -> object` | new clone `path#N`, runs `create()` |
| `find_object(name) -> object?` | loaded object by name (`/p` or `/p#N`); never loads |
| `object_name(ob) -> string` | |
| `environment(ob?) -> object?` | container of `ob` (default: `self`) |
| `inventory(ob) -> [object]` | in move order |
| `move_to(dest)` | moves **self** into `dest` (containment cycles are an error) |
| `send(ob, text)` | writes `text` verbatim to the connection bound to `ob`; no-op if none or `ob` is `null`. The mudlib owns line breaks: end lines with `\n` (telnet gets `\r\n`); nothing is appended |
| `disconnect(ob)` | closes the connection bound to `ob` (e.g. `quit`); no-op if none or `ob` is `null`. `net_dead()` runs once the network layer reports the close, as for a dropped link |
| `bind_connection(ob)` | **master only**: rebinds the current execution's connection to `ob` |
| `compile_object(path) -> string?` | recompile (the `update` command); `null` on success, else the diagnostics |
| `len(x) -> int` | string (code points), array, map |
| `split(s, sep) -> [string]` | plain split, empty fields kept; `sep` must be non-empty |
| `join(xs, sep) -> string` | elements must be strings |
| `keys(m) -> [any]` | insertion order |
| `trim(s) -> string` | |

Argument counts of efuns are checked at link time.

## Applies (driver → mudlib)

| Object | Apply | When |
|---|---|---|
| any | `create()` | after load/clone (after variable initialisers). **Not** re-run on recompile |
| master (`/secure/master.wf`) | `connect() -> object` | new connection; the driver binds the connection to the returned object |
| interactive | `logon()` | right after the bind |
| interactive | `process_input(line: string)` | each input line |
| interactive | `net_dead()` | after disconnect (connection already unbound) |

The master is loaded at boot; a compile error or failing `create()` in the master
fails `World::boot`.

## Hot reload (`compile_object`)

1. The file is re-read and re-parsed, then linked. On any error the running
   program is untouched and the diagnostics are returned.
2. Programs that inherit the changed one are re-linked against it (their source
   is not re-read). If any dependent fails, **nothing** is installed.
3. On success the registry maps each path to version N+1 and **every existing
   object** of those programs (blueprint and clones) switches immediately.
4. Variables are matched by **(declaring program, name)**: kept if the old value
   still conforms to the declared type; otherwise, and for new variables, the
   initialiser runs (with `self` = the object). Removed variables are dropped.
   `create()` is not re-run. If an initialiser fails, every object and program
   is rolled back and the error returned.
5. Connections stay bound; object ids do not change. Code already executing
   (e.g. the `update` command itself) finishes on the old version.

**Consequence for mudlib authors:** state set in `create()` (e.g.
`set_long("…")` storing into a variable) survives a reload unchanged, so
editing that string and updating shows nothing new. Text that should change on
`update` must come from code, e.g. `override fn long() -> string { return "…" }`,
or the mudlib's update command must re-apply setup itself (e.g. call a `pub fn
setup()` on the blueprint after a successful `compile_object`).

## Guard rails

- **Ticks:** every statement/expression evaluation costs one tick; 1,000,000 per
  execution. Exceeding it aborts with `Too long evaluation`.
- **Call depth:** 200 Weft frames, plus a Rust-stack budget (32 MiB); exceeding
  either aborts with `Too deep recursion`. The world thread must be spawned with
  `loom_vm::WORLD_THREAD_STACK` (64 MiB).
- Strings are capped at 16 MiB and arrays/maps at 1M elements.
- A runtime error aborts the current execution only (no rollback of state it
  already changed; `atomic` is Phase 1). The player sees
  `*Error: path.wf:line:col: message` plus a short call trace; everyone else is
  unaffected.
- The parser caps nesting depth (96) and never panics (proptest harness in
  `crates/loom-syntax/tests/fuzz_smoke.rs`, `cargo fuzz` target in
  `crates/loom-syntax/fuzz`, CI smoke via `scripts/fuzz-smoke.sh`).

## Known Phase 0 deviations from spec v2

- Compilation runs on the world thread and reads the mudlib synchronously
  (spec §7.2: off-thread compiler pool).
- Instance upgrade is eager and immediate (spec: lazy by default, `upgrade()`
  apply, schema hashes).
- Types are enforced at runtime, not by a static checker.
