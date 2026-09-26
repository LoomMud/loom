# Weft — Phase 0 subset (reference)

This is the exact language and runtime surface implemented by the Phase 0 spike
(`loom-syntax` + the tree-walking evaluator in `loom-vm`, OBI-10). Anything not
listed here is **not** supported yet; the parser reports a targeted diagnostic
for the common out-of-subset features (see the last section). The full design
is spec v2 §5; Phase 1 replaces the evaluator with the register bytecode VM but
keeps this syntax.

Check a mudlib without running it:

```
loom-cli check <mudlib-root>     # parses + links every .wf file, exit 1 on errors
```

## Programs and objects

- **One file = one program.** `/domains/start/hall.wf` is program
  `/domains/start/hall`. The blueprint object has the program's name; clones are
  named `/path#N`.
- **Single inherit**, first in the file: `inherit /std/room` (unquoted path, no
  extension). `super::fn(args)` calls the parent's version.
- **`override` is required** to redefine an inherited function, and is an error
  when nothing is overridden. Redeclaring an inherited variable is an error.
- Top-level declarations are variables and functions only.

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
- The parser caps nesting depth (96) and never panics (property-tested).

## Not in Phase 0 (parser gives a targeted error)

`import`, `const`, `enum`, `struct`, `match`, `try`/`catch`/`throw`, `atomic`,
`protected`, `final`, labelled/multiple inherit, closures (`fn(x) => …`) and
function values, named arguments, `if let`, `float`, slices `s[1..3]`,
`call_out`/heartbeat, persistence, `upgrade()`, privilege classes/tiers beyond
the master-only `bind_connection`.

## Known Phase 0 deviations from spec v2

- Compilation runs on the world thread and reads the mudlib synchronously
  (spec §7.2: off-thread compiler pool).
- Instance upgrade is eager and immediate (spec: lazy by default, `upgrade()`
  apply, schema hashes).
- Types are enforced at runtime, not by a static checker.
