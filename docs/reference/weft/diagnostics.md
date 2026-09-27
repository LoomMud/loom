# Weft diagnostic codes

Every diagnostic `loom-syntax` and `loom-compiler` emit (and the `loom-vm`
Phase 0 linker/gate, which becomes the Phase 1 bytecode linker) carries a
stable, machine-readable code: `W` plus a 4-digit number, e.g. `W0201`.
Severity (error/warning) is a separate field, not part of the code — see the
Loom design spec v2 §5.9 and OBI-49.

- A code is assigned once and never reused or renumbered, even if the
  diagnostic that used to report it is deleted (see *Retired* below).
- Numbers are assigned in ranges by compiler phase (`00xx` lexer/parser,
  `01xx` resolver/imports/inherit, `02xx` type checker, `03xx` link, `04xx`
  Phase 0 evaluator gates, `09xx` warnings/lints).
- Text rendering shows the code in the `rustc`-style header, e.g.
  `error[W0201]: mismatched types: ...`. The same code will appear in the
  LSP JSON diagnostics (spec §5.9) once that ships.

TODO(Bilbo, OBI-49): expand this with worked examples and fix-it prose for
the most common codes once the doc pass lands. The table below is generated
and must not be hand-edited; regenerate it with
`LOOM_BLESS=1 cargo test -p loom-syntax --test diagnostics_doc` after adding
or retiring a code in `crates/loom-syntax/src/codes.rs`.

<!-- BEGIN GENERATED CODE TABLE (OBI-49; do not hand-edit) -->

### `00xx` — lexer / parser

| Code | Description |
| --- | --- |
| `W0001` | unterminated block comment |
| `W0002` | invalid {what} literal |
| `W0003` | float literal is out of range for `float` (64-bit) |
| `W0004` | integer literal is too large for `int` (64-bit) |
| `W0005` | unknown escape sequence |
| `W0006` | unclosed `{` in interpolated string |
| `W0007` | empty `{}` in interpolated string |
| `W0008` | unterminated string literal |
| `W0009` | unexpected character (LPC/C-style syntax not used by Weft) |
| `W0030` | expected one syntactic construct but found another token |
| `W0032` | expected {what}, found keyword {kw} |
| `W0033` | code is nested too deeply |
| `W0034` | `lightweight` is declared twice |
| `W0035` | `{what}` must come before any declarations |
| `W0036` | {what} paths are not quoted |
| `W0037` | expected a path segment after `/` |
| `W0038` | inherit paths have no file extension |
| `W0039` | empty import list |
| `W0040` | import paths have no file extension |
| `W0041` | duplicate modifier `{name}` |
| `W0042` | a declaration cannot be both `{first}` and `{second}` |
| `W0043` | `{name}` applies to {applies}, not {} |
| `W0044` | a program variable needs a type or an initial value |
| `W0045` | a constant needs a value |
| `W0046` | a top-level function needs a name |
| `W0047` | {what} takes no modifiers |
| `W0048` | `let` is only allowed inside functions |
| `W0049` | unmatched `}` |
| `W0050` | this `{` is never closed |
| `W0051` | this `{` is not closed before the next declaration |
| `W0052` | the `...{}` parameter must be last |
| `W0053` | a `...rest` parameter cannot have a default |
| `W0054` | this `{` is never closed |
| `W0055` | this `{` is not closed before the next declaration |
| `W0056` | expected end of statement, found {found} |
| `W0057` | `let` needs an initial value |
| `W0058` | `while let` is not part of Weft |
| `W0059` | `throw` needs an error value |
| `W0060` | `try` needs a `catch` block |
| `W0061` | `catch` without a matching `try` |
| `W0062` | `else` without a matching `if` |
| `W0063` | {what} is only allowed at the top level of a file |
| `W0064` | cannot assign to this expression |
| `W0065` | expected `{{` to start the `{kw}` body, found {found} |
| `W0066` | expected `{{` after the condition, found {} |
| `W0067` | expected `{{` or `if` after `else`, found {} |
| `W0068` | `->` is not a call operator in Weft |
| `W0069` | unexpected `|` in an expression |
| `W0070` | comparison operators cannot be chained |
| `W0071` | `{}` is ambiguous |
| `W0072` | a named function cannot be declared inside an expression |
| `W0073` | a function name after `{scope}::` |
| `W0074` | `{scope}::{}` must be called |
| `W0075` | enum variants are not written with `::` |
| `W0076` | `{n}(…)` is not a pattern |
| `W0077` | interpolated strings cannot be patterns |
| `W0078` | struct field `{}` needs a type |
| `W0079` | enum variants have no explicit values |
| `W0080` | function types list parameter types only |
| `W0081` | positional argument after a named argument |
| `W0082` | expected `:` after field `{}` |

### `01xx` — resolver / imports / inherit

| Code | Description |
| --- | --- |
| `W0100` | inherit label `{l}` is used twice |
| `W0101` | `{}` is inherited twice |
| `W0102` | variable `{name}` is inherited from both {} and {} |
| `W0103` | const `{name}` is inherited from both {} and {} |
| `W0110` | invalid program path (not absolute, or a bad segment) |
| `W0111` | {what} chain is too deep |
| `W0112` | {what} cycle through {ppath} |
| `W0113` | cannot {what} {ppath}: it has errors |
| `W0114` | cannot {what} {ppath}: {ppath}.wf does not exist |

### `02xx` — gradual type checker

| Code | Description |
| --- | --- |
| `W0200` | `{}` has type `{t}` but no initial value |
| `W0201` | `{}` needs a type |
| `W0202` | `{}` does not export a const named `{n}` |
| `W0203` | `{}` is imported from both {} and {} |
| `W0204` | `{}` is declared twice in this program |
| `W0205` | variable `{}` is already declared in {} |
| `W0206` | `{}` is declared twice in this program |
| `W0207` | const `{}` is already declared in {} |
| `W0208` | `struct` is not implemented by the type checker yet |
| `W0209` | `enum` is not implemented by the type checker yet |
| `W0210` | `{}` is declared twice in this program |
| `W0211` | function `{name}` is inherited from both {} |
| `W0212` | parameter `{}` is declared twice |
| `W0213` | parameter `{}` needs a type |
| `W0214` | a parameter without a default follows one with a default |
| `W0215` | `private fn {name}` cannot be an `override` |
| `W0216` | `override fn {name}` overrides nothing |
| `W0217` | `{name}` redefines a function inherited from {} |
| `W0218` | `{name}` is `final` in {} and cannot be overridden |
| `W0219` | `override fn {name}` does not match the inherited signature `{}` from {} |
| `W0220` | `override fn {name}` must stay `pub` like the inherited function |
| `W0221` | the `error` type is not implemented yet |
| `W0222` | unknown type `{n}` |
| `W0223` | `{}` may reach its end without returning a value |
| `W0224` | unknown variable `{n}` |
| `W0225` | this call returns no value |
| `W0226` | mismatched types: expected one type, found another |
| `W0228` | {what} must be `bool`, found `{ty}` |
| `W0229` | cannot infer a type for `{name}` from `null` |
| `W0230` | `{}` has type `{t}` but no initial value |
| `W0231` | `{}` needs a type or an initial value |
| `W0232` | cannot iterate over `{t}`: it may be null |
| `W0233` | cannot iterate over `{t}` |
| `W0234` | `return` outside a function |
| `W0235` | `{fname}` has no return type, so it cannot return a value |
| `W0236` | `{fname}` must return a value of type `{t}` |
| `W0237` | `if let` is not implemented by the type checker yet |
| `W0238` | `break` and `continue` are not implemented by the type checker yet |
| `W0241` | cannot assign to `{n}`: it was declared with `let` |
| `W0242` | cannot assign to `{n}`: it is a `const` |
| `W0243` | cannot assign to `self` |
| `W0244` | cannot assign to function `{n}` |
| `W0245` | cannot assign into a string |
| `W0246` | cannot assign to this expression |
| `W0247` | mismatched types in the assignment: expected `{pty}`, found `{rty}` |
| `W0248` | cannot negate a value of type `{t}` |
| `W0249` | cannot call `.{}()` on a value that may be null (`object?`) |
| `W0250` | cannot call `.{}()` on a value of type `{t}` |
| `W0251` | slices (`a[lo..hi]`) are not implemented by the type checker yet |
| `W0252` | field access is not implemented by the type checker yet |
| `W0253` | `match` is not implemented by the type checker yet |
| `W0254` | struct literals are not implemented by the type checker yet |
| `W0255` | enum variants are not implemented by the type checker yet |
| `W0256` | named arguments are not implemented by the type checker yet |
| `W0257` | spread arguments (`...expr`) are not implemented by the type checker yet |
| `W0258` | cannot cast `{}` as `{to}` |
| `W0259` | cannot cast `{from}` as `{to}` |
| `W0260` | closure parameter `{}` needs a type annotation |
| `W0261` | closure parameters cannot have defaults |
| `W0262` | this closure may reach its end without returning a value |
| `W0263` | array elements have different types: `{prev}` and `{t}` (element {}) |
| `W0264` | `{t}` cannot be a map key |
| `W0265` | {what} have different types: `{prev}` and `{t}` |
| `W0266` | cannot index a value that may be null (`{t}`) |
| `W0267` | cannot index a value of type `{t}` |
| `W0268` | cannot apply an arithmetic/comparison operator to these two types |
| `W0270` | mismatched types in `??`: the left side is `{lt}`, the fallback is `{rt}` |
| `W0271` | ordering works on two ints, two floats or two strings |
| `W0272` | `in` on a string needs a string on the left, found `{t}` |
| `W0273` | `in` needs an array, map or string on the right, found `{t}` |
| `W0274` | cannot compare `{a}` with `{b}` using `{sym}` |
| `W0275` | `{fname}` takes {}, but {} |
| `W0276` | unknown function `{n}` |
| `W0277` | `{what}` has type `{t}`, which is not a function |
| `W0278` | `{n}` takes {}, but {} |
| `W0279` | mismatched types in {what}: expected a string, array or map, found `{t}` |
| `W0280` | mismatched types in {what}: expected a map, found `{t}` |
| `W0281` | no inherit is labelled `{}` |
| `W0282` | `{}{}`: no inherited function with this name |
| `W0283` | `{}{}` is ambiguous: it is inherited from {} |
| `W0284` | program variable `{}` stores an object reference, so its type must be `object?` |
| `W0285` | const `{}` stores an object reference, so its type must be `object?` |

### `03xx` — link (efun arity, applies, unknown names)

| Code | Description |
| --- | --- |
| `W0300` | `{}` is declared twice in this program |
| `W0301` | variable `{}` is already declared in {} |
| `W0302` | `{}` is declared twice in this program |
| `W0303` | `{}` redefines a function inherited from {} |
| `W0304` | `override fn {}` overrides nothing |
| `W0305` | parameter `{}` is declared twice |
| `W0306` | a parameter without a default follows one with a default |
| `W0307` | unknown type `{n}` |
| `W0308` | cannot assign to `{n}`: it was declared with `let` |
| `W0309` | cannot assign to `self` |
| `W0310` | unknown variable `{n}` |
| `W0311` | `{n}` takes {want} argument{}, but {} were given |
| `W0312` | unknown function `{n}` |
| `W0313` | `super::{}`: no inherited function with this name |

### `04xx` — Phase 0 evaluator gates ("not yet supported")

| Code | Description |
| --- | --- |
| `W0400` | Phase 0 gate: `lightweight` programs is not yet supported by the tree-walking evaluator |
| `W0401` | Phase 0 gate: labelled `inherit` is not yet supported by the tree-walking evaluator |
| `W0402` | Phase 0 gate: multiple inheritance is not yet supported by the tree-walking evaluator |
| `W0403` | Phase 0 gate: `import` is not yet supported by the tree-walking evaluator |
| `W0404` | Phase 0 gate: `protected` visibility is not yet supported by the tree-walking evaluator |
| `W0405` | Phase 0 gate: `final` is not yet supported by the tree-walking evaluator |
| `W0406` | Phase 0 gate: `atomic` functions is not yet supported by the tree-walking evaluator |
| `W0407` | Phase 0 gate: `const` is not yet supported by the tree-walking evaluator |
| `W0408` | Phase 0 gate: `struct` is not yet supported by the tree-walking evaluator |
| `W0409` | Phase 0 gate: `enum` is not yet supported by the tree-walking evaluator |
| `W0410` | Phase 0 gate: `...rest` parameters is not yet supported by the tree-walking evaluator |
| `W0411` | Phase 0 gate: the `float` type is not yet supported by the tree-walking evaluator |
| `W0412` | Phase 0 gate: the `error` type is not yet supported by the tree-walking evaluator |
| `W0413` | Phase 0 gate: function types is not yet supported by the tree-walking evaluator |
| `W0414` | Phase 0 gate: `*=`, `/=` and `%=` is not yet supported by the tree-walking evaluator |
| `W0415` | Phase 0 gate: `if let` is not yet supported by the tree-walking evaluator |
| `W0416` | Phase 0 gate: `break` and `continue` is not yet supported by the tree-walking evaluator |
| `W0417` | Phase 0 gate: `try`/`catch` is not yet supported by the tree-walking evaluator |
| `W0418` | Phase 0 gate: `throw` is not yet supported by the tree-walking evaluator |
| `W0419` | Phase 0 gate: named arguments is not yet supported by the tree-walking evaluator |
| `W0420` | Phase 0 gate: `...` spread arguments is not yet supported by the tree-walking evaluator |
| `W0421` | Phase 0 gate: float literals is not yet supported by the tree-walking evaluator |
| `W0422` | Phase 0 gate: slices is not yet supported by the tree-walking evaluator |
| `W0423` | Phase 0 gate: field access is not yet supported by the tree-walking evaluator |
| `W0424` | Phase 0 gate: `as` casts is not yet supported by the tree-walking evaluator |
| `W0425` | Phase 0 gate: labelled calls `label::fn()` is not yet supported by the tree-walking evaluator |
| `W0426` | Phase 0 gate: calling a computed value is not yet supported by the tree-walking evaluator |
| `W0427` | Phase 0 gate: closures is not yet supported by the tree-walking evaluator |
| `W0428` | Phase 0 gate: `match` is not yet supported by the tree-walking evaluator |
| `W0429` | Phase 0 gate: struct literals is not yet supported by the tree-walking evaluator |
| `W0430` | Phase 0 gate: enum variants is not yet supported by the tree-walking evaluator |

### Retired

| Code | Description |
| --- | --- |
| `W0239` | `try`/`catch` is not implemented by the type checker yet |
| `W0240` | `throw` is not implemented by the type checker yet |

<!-- END GENERATED CODE TABLE -->
