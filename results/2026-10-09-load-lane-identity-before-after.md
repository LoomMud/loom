# Load lane: what a mechanical identity guard actually buys (OBI-397)

Date: 2026-10-09 (window: 2026-10-09T00:00Z → the sample end below) · Owner: Legolas
Task: OBI-397 · Predecessor: OBI-325 (`scripts/load-lane-classify.py`, PR #144)
Spec: design §8.12 (a release owes a real p99), Phase 1 exit criterion (`150 players, p99 < 50 ms`)

## The complaint, and what I could and could not measure

OBI-397: *a test-only diff still spends a load-lane slot on every re-stack, so PRs
cannot catch up to a busy main.* The guard (OBI-325) skips `crates/*/tests/**`; a
`#[cfg(test)]` block under `crates/*/src/**` is source, so it still enters
`loom-ci-load-lane`.

Two quantities get conflated whenever this is argued from the Actions UI, so they
are defined here and used consistently below:

* **lane occupancy** — seconds a `loadtest-e1-1` *step* actually executed on the
  lane host. `jobs/{id}/timing` (and the run's own `started_at`/`completed_at`)
  **include queue time inside "started"**, so job wall-clock is not occupancy;
  I re-derived both from per-step timestamps (`started_at`/`completed_at` of the
  job's steps, summed).
* **queue wait** — lane occupancy's shadow: `loadtest-e1-1` step sum subtracted
  from the same job's wall clock. That is the number a re-stacked PR feels.

Sampled window: every workflow run that reached a terminal state on 2026-10-09.

| measure | value |
| --- | --- |
| runs that held the lane (occupancy > 0) | 40 (38 `pull_request`, 2 `push`) |
| lane occupancy in the window | **234.4 min ≈ 39 % duty** on a single-host lane |
| longest single hold | 1 050 s (17.5 min), a `pull_request` |
| runs that skipped the lane | 48, costing **2.4 min** of `classify` between them |
| queue wait, max / mean / p50 | **63 min** / 6.4 min / 0 |

The `63 min` figure is the ticket's "~35–60 min" seen from the other side, and the
2.4-vs-234.4 comparison is why the guard was worth building at all. It is also the
whole problem: one lane, one host, and a queue that a re-stack cancels.

The symptom has a third number that matters: **12 of the 21 src-only PR runs in the
sample never executed at all** — `loadtest-e1-1` was cancelled while queued. On
re-stack `cancel-in-progress` kills the queued run and the replacement re-queues at
the back. That is "cannot catch up", and it is a *queue-position* problem, not a
lane-minutes problem.

## What widening the path table would have bought (the upper bound)

I ran the classifier over the **actual** changed-path list for every lane-holding
run (`gh api repos/…/compare/BASE...HEAD`, 40 diffs, replayed through the shipped
stage-one table plus the stage-two scope rule):

* PR lane-holding runs: 38 runs, 110.0 min of occupancy.
* Runs stage two is *allowed to ask about* (every relevant path is
  `crates/*/src/*.rs`, nothing unhashable: `Cargo.toml`/`Cargo.lock`, `*.rs.in`,
  `build.rs`, `benches/**`, `crates/loom-vm/src/codegen.rs`): **21 runs, 70.3 min —
  64 % of PR lane minutes.**

That 64 % is the number a path-based widening would have claimed, and it is wrong
in the worst available direction.

## What the compiler says (the realized number)

I then ran the real proof — `scripts/load-lane-identity.py`, the shipped code, on
the shipped toolchain — for all 21 eligible runs, sequentially, one dedicated
worktree parked on each run's `github.sha` first (21 × ~41 s, no parallel load;
the shared-host rule in OBI-306/307 is honoured).

| result | runs | lane occupancy |
| --- | --- | --- |
| `same=true` (release build byte-identical) | **3 of 21** | 3.8 min |
| `same=false` — `target/release/loom-cli` differs | 14 | 50.6 min |
| `same=false` — `target/release/loom-loadtest` differs | 3 | 15.9 min |
| `same=false` — both artefacts differ | 1 | 0.0 min |
| proof time | mean 41 s, min 25 s, max 51 s (warm `target/`) | — |

**18 of the 21 diffs that look test-only by path really do move the measured
program.** A widened path table would have skipped all 18 — 66.5 minutes of
measurements that were owed — and the CI that would have caught it is exactly the
CI that the skipped check silences (GitHub counts a skipped required check as
satisfied, which is OBI-325's review hole).

So the honest disposition of OBI-397 is:

* the *sound* widening is small: **3 of 38 PR lane holds (3.8 min of 110, 3 %)**
  are provably not worth a lane slot, and those three never take a queue position
  again — which is the thing the ticket actually complains about;
* the *remaining* lane minutes are not misclassification. They are genuine source
  changes, a single-host lane at 39 % duty, and a 17.5-minute E1.1 hold behind a
  queue that forgets your position on re-stack.

I am shipping the guard because it is the only widening that can be *proved*, not
because it recovers the day. Recovering the day needs capacity or a shorter soak,
and that is a different ticket — filed from this evidence rather than from this
report's guess.

The motivating case, measured directly rather than replayed: **PR #160**
(`warp/loadbot/mix.tsv` + loadtest harness, head `7c8545a` on base `8ef99a9`),
which the path table calls runtime-relevant —

```
same=true  reason=release build byte-identical at both ends of the range (loom-cli, loom-loadtest)
head_sha256=9a7073970ee7e853e2671791b04261889bb4755c2e48928b0f2f2af766241046 f3c0c1d78c1b7d4f95984d29a653f80b075bf3985d5d516013af330092951f5b
base_sha256=9a7073970ee7e853e2671791b04261889bb4755c2e48928b0f2f2af766241046 f3c0c1d78c1b7d4f95984d29a653f80b075bf3985d5d516013af330092951f5b
seconds=33
```

Controls on the same code path, as expected: appending a `#[cfg(test)]` module to
`crates/loom-loadtest/src/main.rs` does **not** move either hash; changing a real
`pub fn` **does**; a dirty working tree returns `same=false` ("refusing to hash a
tree that is in no commit").

## Why the proof and not a better path rule

I built the obvious cheap version first and measured it instead of trusting it: a
line-span tracker that subtracts `#[cfg(test)]` blocks from a file's hunk ranges
(`cfgspan.py`, 1 662 lines of replay over 39 real diffs). It got **17 of 39 files**
right. It missed a module-level `#[cfg(test)] mod …` whose `mod` item spans the
rest of the file, statement-level attributes, an attribute applied to a `use`
group, and it flagged `transport.rs:981` as `#[cfg(test)]` when the function
beside that line is `pub fn with_timeout` — a real runtime API. A predicate that
is wrong on half the files *and wrong in the open direction* is not a guard.

The compiler is not asked to guess. `cargo build --release -p loom-cli
-p loom-loadtest` at `base.sha` and at `github.sha`, hashed: rustc decides what is
code, and it also clears the cases no textual rule can — a change the optimiser
eliminates, an unused `pub fn` that no binary links, a renamed local, a `cfg`
the target does not select.

Two properties make that verdict trustworthy rather than merely convenient, and
both are asserted in CI rather than commented:

* **It hashes the thing the gate measures.** The same `BUILD_CMD`, the same two
  artefacts, the same `dtolnay/rust-toolchain` pin (`1.98.1`) and the same
  `Swatinem/rust-cache` pin as `loadtest-e1-1`; the same host label.
  `check-ci-load-lane.py` rule 14 reads those constants out of the script with
  `ast` and compares them to the gate's steps, string for string. A proof built
  differently is a hash of some other program.
* **Host determinism is not an assumption it relies on.** Both ends are built on
  *one* host in *one* job, so any host-dependent difference shifts both sides
  equally. The only inputs are `.rs` files under `crates/*/src/`: `build.rs`,
  `*.rs.in`, `Cargo.*`, `rust-toolchain.toml` and `.cargo/*` are outside the
  candidate scope, so the shapes where a byte hash could disagree across hosts
  are excluded by construction, and rule 15 walks the workspace for
  `include!(concat!(env!("OUT_DIR"), …))` so a generated source file cannot join
  the candidate set silently.

## The shipped gate

`classify` (same job, same verdict, same DAG — only `loadtest-e1-1` reads
`needs.classify.outputs.runtime`, so nothing downstream moves):

```
verdict   (stage one, ungated — a main push always gets a written verdict)
  └─ prove   runs only if: runtime && identity && event == pull_request
  └─ verdict merges downward only:  runtime stays true unless SAME=true && SCOPE=true && EVENT=pull_request
outputs: runtime, reason, files, identity_scope, identity_proof
```

* **Fail closed everywhere.** `runtime != 'false'` (never `== 'true'`), an
  unfinished proof step leaves `same` unset, the shell adds `same=false` if the
  output file has no line, `--github-output` is deliberately absent because it
  appends, and the proof writes its file only after all work so a killed build
  cannot leave a verdict beside a `true`.
* **A breakage delays merges; it does not wave regressions through.** Every
  toolchain/cache failure mode is `continue-on-error` and lands on the
  "not proven" side.
* **`main` never escapes.** The step and the merge both require
  `github.event_name == 'pull_request'`: the nightly schedule and every push to
  `main` still measure a real p99 (§8.12, Phase 1 exit criterion). The table step
  stays ungated so a push run still publishes a verdict.
* **Timeouts are arithmetic, not vibes.** `BUILD_TIMEOUT = 900 s` per build, the
  step caps itself at 1 980 s, and the `classify` job timeout went 10 → 45 min so
  the script answers "not proven" before Actions answers "no output". Rule 14
  checks those numbers.

Local verification (all green, and the workflow YAML parses):

```
load-lane-classify self-test:  86 cases, 0 failure(s)
load-lane-identity --self-test: 12 decision cases + the checkout-restore case
check-ci-load-lane ci.yml:      rc=0 (rules 1–15)
check-ci-load-lane --self-test: 75 cases, 0 failure(s)  (9 new mutants: the
  deleted proof, the main-push scope, a drifting toolchain pin, a build command
  that no longer matches the gate, a decider timeout below the proof's cap, an
  ungated proof, a step that cannot see the table's status, a raise-instead-of-clear
  merge, and the classifier scope losing `crates/*/src/**`)
```

## Where the minutes actually are (for whoever owns capacity)

Recorded because the next ticket should start from measurement, not from this
report's inference:

1. **One lane, one host, 39 % duty.** At 17.5 min per full hold, a burst of four
   real PRs plus a `main` push is enough to put the fifth behind a 30–60 min queue.
2. **Queue position is lost on re-stack** (`cancel-in-progress` kills the queued
   run; the replacement re-queues at the back). 12 of 21 src-only PR runs in the
   sample were cancelled while queued. If we want re-stacked PRs to catch up, the
   fix is in how the lane grants, not in the classifier.
3. **E1.1 occupancy itself.** 1 050 s of steps, ~90 s of which is fixed overhead
   and the rest the 15-minute soak. A shorter soak on PRs with the full soak on
   `main`/nightly is the only remaining lever that does not add a host.
4. **`cargo build --release` on the lane host stays as slow as 7 min** (measured
   during OBI-326's cache work) — which is why the proof's build runs in `classify`
   on the runner pool and not on the lane host.
