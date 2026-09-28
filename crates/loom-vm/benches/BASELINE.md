<!--
SPDX-FileCopyrightText: 2026 Oberfield
SPDX-License-Identifier: AGPL-3.0-only
-->

# VM benchmark baseline (bcvm register VM)

The VM benchmark suite (`crates/loom-vm/examples/vm_bench.rs`, OBI-72) times a
handful of Weft workloads through the public `World` API only
(`boot_with_limits`, `find_object`, `call`), so the identical file runs
unchanged against the Phase 0 tree-walker and the current bytecode VM
(bcvm). There is no `criterion` harness here: it is a plain `std::time::Instant`
loop that prints one Markdown table row per workload with median/p95/min over
`iters` samples (default 30), each sanity-checked against its first result so
a semantic break fails the run instead of timing an error path.

```
cargo run --release -p loom-vm --example vm_bench [iters]   # one-off numbers
scripts/bench-gate.sh [BASE_REF]                             # the CI gate, locally
```

## Workloads

All workloads are Weft functions compiled from string literals in
`vm_bench.rs` against a small on-disk mudlib the binary writes to a temp dir
each run (`secure/master.wf`, `bench/b.wf`, `builders/{b,c,d}/p.wf`).

| Workload | What one iteration does | Exercises |
|---|---|---|
| `arith` | 200 000-iteration `while` with `%`, `*`, `+=` | interpreter dispatch, tick checks |
| `recurse` | `fib(20)` (13 529 calls) | call/return, frames |
| `strings` | 5 000 × `s = s + "x"` | string concat/growth |
| `containers` | map/list ops over 5 000 iterations | map insert/get, iteration |
| `containers_50k` | same shape at 50 000 iterations | same, larger N (superlinear structures show here first) |
| `cross_object` | 20 000 `call_other`-style calls to `/bench/b` | call_other dispatch, frame setup, arg checks |
| `monocall` | 500 000 virtual self-calls in a tight loop | call *dispatch* overhead in isolation (OBI-78 inline cache target) |
| `monocall_other` | 500 000 `CallOther` dispatches in a tight loop | same, cross-object dispatch path |
| `priv_control` | 10 000 calls to `geteuid()`, an ungated P0 efun | baseline call cost with no security check, for isolating the checks' marginal cost |
| `priv_check_hot` | 10 000 calls to `seteuid("b")`, cache warm | cost of the two cached checks `seteuid` triggers (`valid_efun` + `valid_seteuid`) plus their audit entries, per gated efun call |
| `priv_check_guard3` | same 10 000-iteration `seteuid` loop, but with three distinct principals stacked (`b` → `c` → `d`, via `relay()` calling into `hot()`) | how cached-check cost scales with principal-stack width, not a count of extra checks |
| `priv_check_deep` | the `priv_check_hot` loop run at call depth 150 (`dive(150)`) | the guard check reads only the top guard entry and never walks the stack, so this should ≈ `priv_check_hot` regardless of depth |
| `priv_read_hit` | 1 000 calls through a cached `valid_read` check | cache-hit read-permission cost |
| `priv_miss` | 1 000 calls, security cache flushed every sample | full miss cost: one `valid_read` re-evaluation per call |
| `priv_creator_frame` | 10 000 `CallValue`s: `b` makes a trivial closure once, hands it to `d`, which invokes it 10 000 times | creator-frame push/pop cost isolated from ordinary dispatch (compare *per call* to `monocall_other`: same trivial callee, but a plain `CallOther` with one principal instead of a `CallValue` crossing two) |

## bcvm numbers (current `main`)

Recorded on `ecf9807` (`loom-vm: function values on the S1 guard model`,
OBI-87), `cargo run --release -p loom-vm --example vm_bench 30`, single run:

| Workload | Median | p95 | Min |
|---|---:|---:|---:|
| `arith` | 53.804 ms | 56.472 ms | 51.027 ms |
| `recurse` | 8.302 ms | 8.710 ms | 8.072 ms |
| `strings` | 1.903 ms | 1.940 ms | 1.881 ms |
| `containers` | 3.772 ms | 3.870 ms | 3.658 ms |
| `containers_50k` | 38.116 ms | 43.073 ms | 35.871 ms |
| `cross_object` | 9.157 ms | 9.908 ms | 8.894 ms |
| `monocall` | 190.623 ms | 208.708 ms | 184.383 ms |
| `monocall_other` | 230.322 ms | 275.711 ms | 214.588 ms |
| `priv_control` | 2.844 ms | 2.859 ms | 2.653 ms |
| `priv_check_hot` | 6.604 ms | 7.324 ms | 6.556 ms |
| `priv_check_guard3` | 9.326 ms | 11.237 ms | 8.898 ms |
| `priv_check_deep` | 7.356 ms | 8.900 ms | 6.851 ms |
| `priv_read_hit` | 2.883 ms | 3.094 ms | 2.855 ms |
| `priv_miss` | 3.466 ms | 3.977 ms | 3.443 ms |
| `priv_creator_frame` | 4.029 ms | 4.129 ms | 4.018 ms |

Derived: `(priv_check_hot - priv_control) / 10000` ≈ 376 ns per gated
`seteuid()` call — that is two cached checks (`valid_efun` +
`valid_seteuid`) plus their audit entries, not a single check; dividing by
two checks gives ≈ 188 ns per cached check. `priv_check_deep` tracking
`priv_check_hot` at call depth 150 confirms the guard check reads only the
top of stack and does not walk it, so depth is free. `priv_check_guard3`
(three stacked principals) vs. `priv_check_hot` (one) shows how cost scales
with principal-stack width rather than per-check count.
`(priv_miss - priv_read_hit) / 1000` ≈ 583 ns is the marginal cost of a
cache miss re-evaluating `valid_read`. `priv_creator_frame` and
`monocall_other` have different call counts (10 000 `CallValue`s vs.
500 000 `CallOther`s), so compare *per call*: `priv_creator_frame` ≈ 4.029
ms / 10 000 ≈ 403 ns/call, `monocall_other` ≈ 230.322 ms / 500 000 ≈ 461
ns/call. The creator-frame push/pop therefore does not add call overhead
beyond ordinary `CallOther` dispatch at this sample size.

Machine notes: this container's CPU/RAM (12 logical CPUs reported by
`nproc`), rustc 1.98.1, `release` profile (default codegen settings), single
run (not an A/B — see below for why the gate never compares this table
directly). GitHub Actions runners will read differently; the gate never
compares across machines (below). This table is the human-readable
snapshot; the number that actually gates PRs is always a fresh same-runner
A/B against the PR's base commit, not this file.

## CI regression gate

Job `bench` in `.github/workflows/ci.yml` runs on pull requests and calls
`scripts/bench-gate.sh <PR base sha>`. It is **not a required check** until a
release cadence exists to re-baseline against; treat a red `bench` job as a
signal to look, not an automatic block.

### Method (noise-tolerant)

1. **Same-runner A/B, never stored absolute numbers.** Shared CI runners vary
   by 20–30% between machines and runs, so comparing a PR's numbers against
   numbers stored from another machine would be dominated by hardware noise.
   The gate builds the base commit's `vm_bench` example (in a `git worktree`,
   separate `CARGO_TARGET_DIR`) and the working tree's, on the *same* runner,
   and compares them. The stored baseline is therefore a *commit* (the PR
   base); the table above is the human-readable record, kept in sync by hand
   when a PR intentionally moves these numbers.
2. **Interleaved rounds.** `BENCH_ROUNDS` (default 3) rounds of the full
   binary, alternating A-B, B-A, … so slow drift in the runner (thermal,
   neighbours) hits both sides equally. Each round uses `BENCH_ITERS` (default
   15) samples internally, same as the binary's own median/p95/min.
3. **Min of medians.** Per workload and side, take the binary's own median
   for each round and keep the minimum across rounds. Interference on a
   shared machine only ever adds time, so the minimum is the best estimate of
   the uncontended cost, and the median within a round already discards
   outliers.
4. **Threshold.** Fail if `head / base > 1 + BENCH_THRESHOLD` (default 0.15)
   for any workload present on both sides. Workloads only on one side are
   reported and skipped (new workloads start gating on the next PR).
5. **Confirmation pass.** If the first pass fails, run a second pass of the
   same size and recompute over all rounds; fail only if the regression
   survives. A real regression survives; a one-off noisy round does not.
6. If the base commit has no `vm_bench` example (there is no such commit on
   this tree today), the gate passes with a notice.

`scripts/bench_compare.py` parses the Markdown tables `vm_bench` itself
prints (stdlib Python, no external deps) and writes the comparison table to
the job summary.

### Updating the baseline

Intentional slowdowns (e.g. a new security check on the call path, like the
S1 guard model this table already includes) will trip the gate. Land them
with the justification in the PR and an updated row in this file; while the
job is non-required, a red `bench` job with a documented reason is
acceptable.
