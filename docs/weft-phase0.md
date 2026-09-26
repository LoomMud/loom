# Weft — Phase 0 subset (superseded)

This document is superseded by [`weft-grammar.md`](weft-grammar.md) (OBI-23).
That file covers the full v1 grammar that `loom-syntax` parses, a table of
what is parsed vs. what the Phase 0 evaluator runs, and the Phase 0 runtime
reference that used to live here (types, efuns, applies, hot reload, guard
rails).

Since OBI-24, `loom-cli check` runs the Phase 1 static checker
(`loom-compiler`, see `docs/hir.md`): strict types, nullability with flow
narrowing, `bool`-only conditions. It is stricter than the Phase 0 runtime, so
check-clean code runs.
