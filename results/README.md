# Load-test results (R4, OBI-40)

Reports committed by `loom-loadtest` runs (`crates/loom-loadtest`), one JSON +
one Markdown per run, named `<date>-<players>-players[-<label>].{json,md}`.

## E1.1 (150 players)

`2026-09-27-150-players.{json,md}`: **PASS**, p99 46.91 ms < 50 ms SLA.

Reference host: Intel Core i7-9750H @ 2.60GHz (12 logical CPUs), 32 GiB RAM,
Linux. `loom serve --mudlib warp` (a local `warp` checkout at whatever its `HEAD`
was that day -- nothing recorded it, which is the gap `warp.ref` closes; *Report
provenance* below attributes it to warp `618b90c`), `loom-loadtest` on
the same host (so this includes no network latency beyond loopback -- see
"Limitations" below).

Run command:

```
loom-cli serve --mudlib warp   # LOOM_TELNET_ADDR=127.0.0.1:41400

loom-loadtest \
  --addr 127.0.0.1:41400 \
  --mix warp/loadbot/mix.tsv \
  --players 150 \
  --duration-secs 90 \
  --ramp-per-sec 15 \
  --slow-reader-fraction 0.1 \
  --out results/2026-09-27-150-players \
  --fail-on-sla-miss
```

10% of bots (15) were the slow-reader cohort (README: "exercises
backpressure"); none were disconnected at 150 players — the Entrance Hall's
`say`/`look` fan-out wasn't enough to fill loom-net's 64-slot per-connection
output queue at this population. `loom serve`'s own stderr/stdout log was
empty at `RUST_LOG=warn` for the whole run: no slow-client disconnects, no
warnings.

## Re-run at Phase 1 exit: TCP_NODELAY (OBI-22)

Same reference host, same command, loom `main` `826aa17`, warp `618b90c`,
release build, in-memory accounts backend.

| Run | p50 | p95 | p99 |
|---|---|---|---|
| `2026-09-30-150-players-main-826aa17` (before) | 41.03 ms | 45.02 ms | 48.97 ms |
| `2026-09-30-150-players-nodelay` (this change) | 0.69 ms | 4.85 ms | **8.50 ms** |
| `2026-09-30-500-players-nodelay` (stretch) | 430 ms | 589 ms | 698 ms |

The ~40 ms floor in every earlier 150-player run (p50 41 ms) came from Nagle
plus the client's delayed ACK, not from the driver. A command's output and
its prompt go out as two small writes, and with Nagle the second one waits
for the ACK of the first, which Linux delays by ~40 ms. `loom-net` now sets
`TCP_NODELAY` on every accepted telnet socket, and `loom-cli` does the same
for HTTP/WebSocket sockets. The actual driver time at 150 players is
single-digit milliseconds.

500 players is still over the SLA. That load is bound by fan-out in the single
Entrance Hall (see below), and it is Phase 3's N1/N2 target, not Phase 1's.

## Stretch run (500 players)

`2026-09-27-500-players-stretch.{json,md}`: **FAIL** relative to the 50 ms
SLA (expected — 500 is the stretch target, not the E1.1 gate). Same host,
same mix, `--ramp-per-sec 25`.

**Findings:**
- Command p99 rose to ~1.15 s (mean ~754 ms); this is dominated by the
  Entrance Hall fan-out (`say`/`look` list every player in the room) at 5x
  the population sized for the alpha, not by connection count alone — see
  the mudlib's `loadbot/README.md` on why "150 in one hall" is deliberately
  the realistic worst case, and 500 pushes well past it.
- Login latency also degraded badly under the ramp (p50 198 ms but p99
  ~5.1 s): Argon2id hashing is real CPU work per the R4 contract, and 500
  logins at 25/s on a 12-core host contends with the fan-out load already
  running.
- No disconnects, no server-side errors/warnings — the driver stayed up and
  responsive, just slower. This is a scaling/tuning finding, not a
  stability bug.
- Follow-up (not in this issue's scope): a fan-out-heavy scenario like "150
  players in one room" is the realistic *ceiling* per the mudlib contract;
  500 in one room is an intentionally unrealistic stress case. A future
  stretch run spreading players across more rooms would better isolate
  "how many connections can the driver hold" from "how much fan-out can one
  room take."

## CI smoke mode

`.github/workflows/ci.yml`'s `loadtest-smoke` job (non-required) runs 20
players / 60 s against a real `loom serve` on every push/PR, using
`LoomMud/warp`'s `loadbot/mix.tsv`, and uploads its report as a build
artifact (`results/ci-smoke.*` is `.gitignore`d, not committed).

## CI regression gate: `loadtest-e1-1` (OBI-177)

The same workflow's `loadtest-e1-1` job is a **required** status check: the
full E1.1 run (150 players, 90 s, `--fail-on-sla-miss`) against a real
`loom serve` on every push/PR, scraping `loom-http`'s `/metrics` into the
report. A PR that regresses p99 past the 50 ms SLA fails this check and
cannot merge (branch protection lists it alongside `rust`/`deny`/`dco`/
`hygiene`). Its report is uploaded as a build artifact
(`results/ci-e1-1.*`, also `.gitignore`d — CI runners vary in CPU/host
noise from the reference host above, so this job proves "no regression
*on this runner*", not the headline number; the committed reports above
remain the reference-host record). When this gate landed, the scraped
`/metrics` body was typically empty in CI runs: `loom-net`/the world
thread recorded no `metrics::counter!`/`histogram!` values on
the connection/command path, so there was nothing for `loom-obs`'s
recorder to render. That instrumentation gap is what **OBI-344** closed -- see
the next section for what the report carries now.

## Tail attribution in the E1.1 report (OBI-344)

The paragraph above is now closed. The gate went red intermittently on a p99
tail that nothing in the artifact could explain: the first two reports we
compared (failed run 37788128494, passed run 37814776730) showed p50 2.08 ms /
p95 14.55 ms but p99 227.87 ms and max 475.68 ms on the red run against p99
23.92 ms / max 78.27 ms on the green one -- a bimodal tail of roughly a hundred
samples, not a throughput regression (the red run's *median* was faster). With
one post-run scrape and no per-sample timestamps, the run could not say whether
the world thread, the net task, the bot process, or the login ramp was
responsible.

What the report carries now:

- **Latency timeline** -- p50/p95/p99/max per `--timeline-bucket-ms` slice,
  each slice stamped with whether a server stall window overlapped it
  (`no` vs `unmeasured` is a real distinction; an uninstrumented server must
  never render as a quiet one).
- **Slowest samples** with their offset from the start of the run.
- **Tail attribution** -- the SLA-breaching samples split across server
  world-loop stall windows, loadtest-process timer starvation, and the login
  ramp, with p99 recomputed excluding server-stall-attributed slices as an
  informational number. The gate stays the measured p99.
- **Server world-loop counters scraped during the run** (default every 1 s):
  tick id, loop iterations, stall count/stall ms, slowest iteration, longest
  between-iteration gap, blocked world->net command sends, runtime errors --
  published by `loom_obs::WorldLoopProbe`/`NetCommandProbe` from the world
  thread's own event loop (`LOOM_WORLD_STALL_MS`, default 50 ms -- the same
  number the SLA is written against).
- **Loadtest process timer lag**, self-measured: how late the bot's own fixed
  intervals fired. Lag here inflates every number in the report, including the
  gate's, so it is measured rather than assumed away.
- The `loadtest-e1-1` job now runs `loom serve` with `RUST_LOG=info` and
  `LOOM_SERVE_ERROR_LOG=1` and uploads `/tmp/loom-serve.log`; previously the
  serve log was captured at the default level, which printed nothing.

The first finding that visibility produced: the
`loom_runtime_errors_total{program="/std/player"}` count of exactly 150 that
every CI run carried is `/std/player::save_character` (line 251) failing as
`save_object("/players/<bot>") failed: <mudlib>/../saves: No such file or
directory (os error 2)` -- CI never creates the save root, so in the E1.1 job
no character ever persists and each player logs one runtime error. Running the
same binary with `--save-dir` pointing at a real directory produces zero
errors and one `.o` file per bot.

### The save root: E1.1 now measures persistence (follow-up to the above)

That was not a cosmetic error: **no E1.1 run before this ever wrote a
character**, so the gate's claim to model a live player population silently
excluded the save path. Both load jobs now create a run-scoped save root and
pass it to the driver:

```sh
SAVES="${RUNNER_TEMP:-/tmp}/loom-saves"; rm -rf "$SAVES"; mkdir -p "$SAVES"
./target/release/loom-cli serve --mudlib warp --save-dir "$SAVES" ...
```

`RUNNER_TEMP` is wiped by the runner at the end of the job, nothing is written
inside the mudlib checkout, and no save file is uploaded as an artifact. The
`rm -rf` at the start matters too: a leftover character would make the next
run's login take the "existing character + password" branch instead of the
"new character" branch, which is a different measurement.

The job then *asserts the path was exercised* rather than trusting it, and
prints both numbers into the log and the serve-log artifact. The healthy shape
is:

```
save_path: objects_saved=150 players=150 save_dir=/home/runner/work/_temp/loom-saves
runtime_errors_total=0
```

| | before | after |
|---|---|---|
| `loom_runtime_errors_total{program="/std/player"}` | 150 (one per player) | 0 (series absent -- the family is created on first error) |
| saved objects on disk | 0 | one `players/<bot>.o` per connected player |
| what the world thread did | `save_object` failing on ENOENT | the same call, writing |

And the measured cost of finally exercising the path, from four consecutive
`loadtest-e1-1` runs of the same runner set (8 vCPU, `loadavg` at job start in the
last column; ms throughout):

| run | p50 | p95 | p99 | max | n | slowest world iteration | samples over 50 ms | runtime errors | loadavg |
|---|---|---|---|---|---|---|---|---|---|
| before, `75ebef1` (37837002588) | 3.196 | 16.660 | **23.669** | 40.755 | 9977 | 32 ms | 0 | 149 | 5.96 |
| after, `31faf3f` (37838121286) | 2.800 | 14.405 | **22.538** | 38.159 | 9909 | 24 ms | 0 | 0 | 5.20 |
| after, `92f4526` (37840315609) | 3.030 | 15.427 | **22.827** | 42.171 | 10035 | 25 ms | 0 | 0 | 6.87 |
| after, on `main`, `ad489db` (37843414478) | 3.110 | 16.427 | **24.270** | 38.446 | 10181 | **562 ms** | 0 | 0 | 6.05 |

The first three rows support the narrow claim: writing 150 characters does not move
the sampled tail. **The fourth row says the claim was incomplete, and it is the
reason the last column is not enough.** That run passed -- p99 24.27 ms, zero
SLA-breaching samples -- while the world thread spent **562 ms inside one
iteration**, with 31 iterations over the 50 ms stall budget totalling 4 905 ms, every
one labelled `kind="disconnect"`:

```text
loom_world_loop_stalls_total{kind="disconnect"} 31
loom_world_loop_stall_ms_total 4905
loom_world_loop_duration_ms_max 562
```

All 31 landed between t+91 s and t+94 s, *after* `--duration-secs 90` had stopped
issuing commands: that is the 150 bots logging out at once. `World::disconnect`
(`crates/loom-vm/src/world.rs`) applies `autosave` -- which is `save_character`,
whose `save_object` PR #151 just made succeed -- and then `net_dead`, both on the
world thread; the serve loop handles one event per iteration, so 562 ms is the cost
of **one** logout, not of the batch. The tick counter confirms it: ticks froze at 901
while iterations kept advancing.

So the honest sentence is: *persistence costs nothing in the numbers this gate
reports, and up to half a second of world-thread time per logout when many sessions
drop together.* The gate cannot see the second part because its sampling window
closes first. Two consequences, both recorded so nobody has to rediscover them:

- A green `loadtest-e1-1` is **not** evidence that the world thread never blocked
  for longer than the SLA. The job now prints `world_loop: worst_iteration_ms=…
  stall_events=… kinds=…` after every run and raises a warning annotation when that
  number exceeds 50 ms, precisely so "passed" cannot be read as "no stall
  happened". It is still not gating: making teardown stalls fail the job would be a
  change to what the gate means, not just what it measures, and that is a CTO call.
- The stall WARN lines in `results/loom-serve.log` are rate-limited to one per 5 s
  (`STALL_LOG_INTERVAL` in `crates/loom-obs/src/world.rs`), so 31 events print as 3
  lines. The counters are the census; the log is a sample. Read
  `loom_world_loop_stalls_total`, not `grep -c`.
- A **red** `loadtest-e1-1` whose report says `E1.1 (p99 < 50 ms): PASS` is a broken
  harness, not a missed SLA. The evidence tail that prints the `world_loop:` line ran
  under the runner's default `bash -e -o pipefail`, so on main run 37862921160
  (`eaf9ceb`) the third bullet's own census aborted the step: the world thread
  recorded **zero** stalls, the scrape therefore carried no `kind="…"` label, `grep -oE`
  exited 1, `pipefail` carried that through the pipeline, and the command substitution
  failed the step *after* `exit $status` would have returned 0 -- p99 21.47 ms, PASS.
  The tail now runs under `set +e` and rule 7 of `scripts/check-ci-load-lane.py` keeps
  it there, with a mutant for each beat (`set +e` removed, `exit $status` dropped,
  `status=$?` gone). Reproduced deterministically against both archived scrapes, and the
  rule states the invariant plainly: the p99 verdict is the only thing that can turn
  this check red, and the evidence below it can only ever inform, never decide.
- The tail now **waits for the save queue before it reads it**, printing
  `save_settle: objects_saved=… waited=…s drain_complete=…`. Both the save count and
  `loom_world_loop_stalls_total` are sampled at a single instant, and character
  persistence is work that can still be running after the last command -- PR #159
  makes that explicit by taking it off the world thread. A run whose writes land
  late would otherwise report fewer saved objects *and* fewer stall events than
  actually happened, i.e. look better for a pure reporting-timing reason. The wait
  is non-gating and capped at 60 s. Measured on a build off current `main`, where
  teardown is still synchronous, one save still landed *after* the last command:
  `save_settle: objects_saved=6 waited=1s drain_complete=yes` -- so the wait is
  already load-bearing, not a placeholder. A `drain_complete=no` is an evidence
  gap to read, never a verdict.

This is also why the historical tail is still open. Before PR #151 the same
disconnect path failed instantly on ENOENT and the worst iteration in a green run
was 32 ms, so the logout-save cost cannot be what made `2872bcd` and its siblings
red: those runs had 250-475 ms samples *inside* the window. What `ad489db` adds is
a recorded instance of the right shape -- one event handler holding the world thread
for hundreds of milliseconds -- so a future red run has a specific thing to look
for (`tail_attribution.server_stall` against `kind="disconnect"` windows) instead of
a guess. It is intermittent: the two runs above with identical code recorded no
stalls at all, and a local 20-player run never exceeded 12 ms per iteration.

Deliberately not a gate: a non-zero runtime-error count raises a workflow
*warning annotation* (`::warning title=OBI-344 runtime errors::`), it does not
fail the job. The p99 verdict is the only pass/fail signal in E1.1, and adding
a second failure mode to a required check would change the gate's meaning
without changing what it measures. A warning is loud enough to keep the
finding from being silently counted again.

Two consequences for reading the numbers from here on. First, E1.1 now costs
the world thread real file writes on the save path, so its tail may differ
from the pre-change runs; that is a *more* honest measurement, not a
regression, and the attribution section is what distinguishes the two. Second,
`loom_runtime_errors_total` disappearing from the final scrape is now the
expected healthy shape -- its presence is the anomaly to read.

The alternative fix -- have `loom-cli serve` `create_dir_all` the default save
root at boot -- was not taken here: it would let a driver bug write into a
mudlib tree silently, and it removes the very failure this run was counting.
That is a design call for the CTO if we want it; the CI job no longer depends
on the answer.

## CI load lane (OBI-308)

**Invariant: `loadtest-e1-1`, `loadtest-smoke` and `bench` must never run at
the same time as each other, on the same runner set, as anything else that
loads that host.** Their output is wall-clock latency, not correctness: a
neighbour on the machine does not flip a pass to a *different* pass/fail
signal, it silently moves the percentiles. So a p99 measured under
contention is not "a slower p99", it is a number that means nothing.

What that looked like on 2026-10-07, one host, two runs in flight:

| Run | In flight at the same time | command p50 | p99 | max | login failures | disconnects |
|---|---|---|---|---|---|---|
| 37654269961 (PR #124, `ad944c6`) | nothing | quiet-host numbers | **< 50 ms** | — | 0 | 0 |
| 37658696127 (PR #124, `4c1f631`) | run 37658252388 (PR #126): a second `cargo build --release` + a second 150-player E1.1 | 76 ms | **593 ms** | 784 ms | 0 | 0 |

`4c1f631` differs from `ad944c6` by a test file only. A 12x SLA miss with
zero errors and zero disconnects is a contention signature, not a latency
regression -- and `bench`/`loadtest-smoke` passed on the same commit, because
a >15% relative gate and a 20-player smoke run tolerate noise that a 50 ms
absolute p99 budget does not.

How the lane is held (`.github/workflows/ci.yml`, header comment):

- Every latency-measuring job **and every CPU-heavy build/fuzz job** is in the
  job-level concurrency group `loom-ci-load-lane`: `loadtest-e1-1`,
  `loadtest-smoke`, `bench`, plus `rust`, `fuzz-smoke`, `fuzz-smoke-bytecode`
  and `fuzz-smoke-lsp`. Job-level groups are keyed by *name across the jobs of
  a workflow* (measured, see below), so at most one heavy thing runs repo-wide
  at a time and a second PR's gate **queues** instead of racing.
- `cancel-in-progress: false` -- a measurement already running is never
  killed. `queue: max` -- pending runs all wait (one at a time; the order is
  not guaranteed, observed roughly FIFO) instead of the default
  `single`, where the third run cancels the pending one. A *cancelled*
  required check blocks a PR exactly like a failed one, so queueing (not
  replacing) is part of not weakening the gate.
- The jobs are also chained with `needs` inside a run:
  `classify` -> `loadtest-e1-1` -> `loadtest-smoke` -> `bench`. The required
  gate has exactly one `needs:` -- `classify`, the job that decides whether this
  diff has to be measured at all (OBI-325, below) -- and no `if:` of its own,
  so nothing upstream can skip it; the two non-required gates wait for it
  instead of competing with it.
- The CPU-heavy jobs (`rust`, `fuzz-smoke`, `fuzz-smoke-bytecode`,
  `fuzz-smoke-lsp`) hold the same group, unconditionally (OBI-311, see below);
  `deny`/`dco`/`hygiene`/`web-client` stay out of it.
- Each gate carries wall-clock headroom (`timeout-minutes` 30 for E1.1, 20 for
  the smoke run) because lane jobs queue behind every other heavy job in the
  group, and a starved release build does not fail the check -- it gets
  **cancelled**, which blocks a PR just as hard and leaves no p99 to read
  (run 37663331238, 2026-10-07 18:01:00Z -> 18:16Z, cancelled mid-build while
  an intentionally contending probe PR ran eight jobs beside it). Slow is
  survivable; cancelled is not.
- A stale SHA is not allowed to hold a place: the workflow also carries a
  workflow-level `concurrency` group that cancels a PR's *superseded* runs and
  nothing else -- no required check on a mergeable candidate is ever cancelled
  -- and the PR trigger is narrowed to the activities that change the commit.
  See "Which runs may be cancelled" below.
- `scripts/check-ci-load-lane.py` asserts all of the above (and that the
  gate still runs 150 players with `--fail-on-sla-miss`, keeps its timeout
  headroom, that no required check became skippable or optional, and that the
  workflow-level block can only ever cancel a superseded `pull_request` run),
  plus a `--self-test` of 73 mutations (74 cases, among them the gate losing its
  `if: ${{ !cancelled() }}`, the three verdict-isolation beats #154 added, a
  `${{ }}` written inside a `run:` block, and the mudlib checkout going floating,
  unverified or unstamped). Both run in the required `hygiene` job, with the
  classifier's own path table (`scripts/load-lane-classify.py --self-test`,
  40 cases: 34 classification rows plus 6 that build a throwaway git repo), so the
  lane cannot rot silently and the comment here
  cannot drift from the workflow.
  The mutation set includes "`rust` leaves the lane" and "`web-client` joins
  the lane", i.e. it guards both directions of membership.

**How job-level groups are actually scoped (measured, not assumed).** The
first version of this section claimed GitHub scopes a job-level concurrency
group "per workflow *and job*". The workflow-syntax docs never say that, and
probe run `37680869590` (draft PR #132, 2026-10-07) disproved it: `web-client`
-- a *different job id* given the same group name -- was serialized against
`loadtest-e1-1` inside a single run. It sat `pending` from 20:17 while only
gate-family jobs held the group (with `deny`, `dco`, `rust` and all three
`fuzz-smoke*` jobs getting runners in that window), then ran 20:44:43 ->
20:45:01 while the gate stayed `pending` and started 39 s later. So a
job-level group is keyed by **name**, across the jobs of a workflow.

That is the lever that closes the residual, and the residual was real: run
`37674844425` (PR #124) had the lane to itself from 19:45 -> 19:55 and still
reported **p99 1977 ms** with 7725 commands sent -- 22% fewer than the gates
that passed either side of it -- with 0 login failures and 0 disconnects,
because its own `cargo clippy --workspace` had been running on that host since
19:31 and took 35 minutes. Starved, not slow: the tell is the command count
with zero connection errors. Putting the heavy jobs in the group fixes it; on
the probe run the gate measured **p99 23.71 ms** (p50 3.05 / p95 16.09 / max
49.29, n 10077, 0 failures, 0 disconnects) once nothing else was running --
2.1x under the SLA, first try, no manual retry.

**Cost, stated plainly.** The lane now admits every CPU-heavy job, so one
heavy job at a time repo-wide. Observed queue depth on 2026-10-07: run
`37675041540`'s `loadtest-smoke` waited 16 min and its `bench` 33 min (both
non-required). Contention is not free either: `rust` took 6 min on a quiet
host, 10 min beside three fuzz jobs, and 35+ min with three runs piled on, and
`fuzz-smoke-bytecode` once burned its whole 15-minute budget inside the
cache-restore step without ever running its payload. If the resulting CI
latency is unacceptable, the fix is capacity, not YAML: a dedicated
load-runner label for the gates, which is OBI-311's remaining decision.

**If you see `loadtest-e1-1` waiting** ("Waiting for job to run" on the
checks tab): that is the lane working, and it has been watched working three
times. (1) PR #128 held the lane from 18:01:00Z; probe PR #129's gate sat
`pending` for ~19.5 min and started at 18:20:35Z only after #128 released the
group -- never cancelled, never co-scheduled -- then measured p99 24.47 ms
(n 9916). (2) `main` `8174d57` (19:37->19:44, PASS), PR #124 (pending
19:31->19:45, gate 19:45->19:55) and PR #126 (pending 19:31->19:55, gate
19:55->20:01, PASS) ran strictly FIFO, one gate at a time, with no human
re-runs. (3) The #132 probe above serialized a *build-class* job against a
gate inside one run. Do not respond to a wait, or to a p99 miss, by raising
the threshold, dropping the population, marking the check optional, or
re-running it into a quiet window by hand -- `hygiene` fails those changes.
Before believing a miss, check that run's own job timeline: a low `commands
sent` with 0 login failures and 0 disconnects means the host was busy, not
that the driver got slower.

### Who has to wait for the lane at all (OBI-325)

Serialising the lane made the numbers honest and made *every merge* wait for
one. With `strict: true` a queued gate is invalidated each time `main` moves, so
the queue is not a cost you pay once, it is a cost you pay until you win. PR
#124 is the case study: rebased four times in about five hours (`b3a9998` 02:09,
`7db7279` 02:28, `db18202` 03:30), each push re-queued `loadtest-e1-1` for
35-60 minutes, and when the gate finally went green on `db18202` (run
37723058077, ~04:50Z) `main` had advanced to `7bb86ce` (PR #122) and the PR
flipped back to `BEHIND`. What all that waiting measured was a commit whose
diff from its base was one file, `crates/loom-cli/tests/supervise_handoff.rs`
-- a test file the release build does not even compile.

So the gate now asks a narrower question first, in
`scripts/load-lane-classify.py`: **could this diff change what E1.1 measures at
all?** E1.1 builds `cargo build --release -p loom-cli -p loom-loadtest` from the
checkout and drives `loom serve --mudlib warp` over telnet, so the inputs are
the two crates' source, their manifests and features, `Cargo.lock`,
`rust-toolchain.toml`, `.cargo/` config, `build.rs`, `mudlib/` content (kept
relevant even though today it is only a Docker mount point -- being unsure
costs a lane run, it never hides a regression), the `tests/fixtures/**` mirror of
the mix the gate replays, and the bench workloads and harness that `bench`
measures in the same lane.

The fixture rule's reason was wrong in the first cut of this PR, and the OBI-327
review caught it: `loom-loadtest`'s `src/mix.rs` does
`include_str!("../tests/fixtures/mix.tsv")`, but inside `#[cfg(test)]`: the
fixture is a unit-test guard that the in-repo copy of the mix still parses, not a
byte of the release binary `cargo build --release` produces. The rule stays, for
the honest reason: E1.1 replays `--mix warp/loadbot/mix.tsv` at runtime, and that
in-repo file is its mirror, kept in sync by the contract's "same PR" rule. An
edit to the mirror is an argument about the mix being measured, so it pays for a
lane run rather than getting a path-based exemption. The real blind spot is the
unpinned `warp` checkout that supplies the measured mix, not this rule -- that is
OBI-326, and the corrected premise raises its priority: the mix E1.1 measures is
not compiled in, not pinned, and not in this repo.

One thing the classifier could not see, until OBI-326: the `warp` mudlib E1.1
serves lives in a *second* repository, checked out inside the job. While that
checkout floated on warp's default branch, a warp-side change could move the p99
with no loom diff to attach it to -- and after the skip landed, a run that never
took the lane could be blamed on the next source PR. It also moved the *session
mix*, because E1.1 replays `--mix warp/loadbot/mix.tsv` out of that same
checkout, and the `include_str!` of `tests/fixtures/mix.tsv` is `#[cfg(test)]`-only.
So the mudlib is now an input the repository names: `warp.ref` at the repo root
holds one line, a full 40-character commit SHA, each load job's `warp-pin` step
reads it and checks out exactly that commit of `LoomMud/warp`, the job re-reads
the file to verify what landed on disk, and `loom-loadtest --note` stamps
`LoomMud/warp@<sha>` into the report. There is no fallback: a missing,
comment-only or branch-named pin fails the gate rather than serving whatever
warp's default branch points at today. The numbers above, recorded before the
pin, stay attributed to warp `618b90c` by hand -- which is the archaeology this
file exists to stop requiring.

A cheap `classify` job answers it, and the three lane jobs read the verdict
twice: through a conditional `concurrency.group` (runtime-relevant, or
undecided, takes `loom-ci-load-lane`; irrelevant takes a `github.run_id`-scoped
group no other run is in) and through the same test on every step that could put
load on the host. Both halves are keyed on `!= 'false'` and never `== 'true'`,
so a missing or unreadable verdict means "take the lane and measure". Rule 8 of
`scripts/check-ci-load-lane.py` pins the whole shape -- the expression, its
run-scoped arm, the classifier's inability to be skipped or to fail the job, and
a step guard beside every measurement -- because each of those has a fail-open
mutation: 73 of them now, all run in `hygiene`.

Putting `.github/**` on the irrelevant list is only safe because of rule 9: the
workflow may not install a `toolchain:` that `rust-toolchain.toml` does not
declare. The compiler is an input the lane measures, so it may have exactly one
place where it is pinned -- and that file is runtime-relevant, which means a
toolchain bump is measured instead of skipped. Before rule 9, bumping the
version in `ci.yml` alone would have changed what every later run builds and
never entered the lane.

**How the paths are read is part of the decision (OBI-325 review).**
`git_paths` passes `--no-renames`. Git detects renames by default and reports a
detected one as its *destination* only, so moving
`crates/loom-loadtest/tests/fixtures/mix.tsv` -- the mirror of the mix E1.1
replays, therefore runtime-relevant -- into `crates/loom-cli/tests/` would have
listed one allow-listed path and skipped the lane. Both ends of a move are inputs
now; `--self-test` builds a throwaway repo to prove it, and asserts the
counterfactual (`-M` lists only the two destinations
and classifies as skip) so the case cannot rot into vacuity. The table was 36
cases after OBI-325; OBI-326's pin rows make it 40.

**Two deliberate over-measures, so nobody "fixes" them into a hole.** A
`Cargo.lock` delta counts as runtime-relevant even when it only touches
dev-dependencies, which `cargo build --release -p loom-cli -p loom-loadtest`
never links -- that lane run measures a byte-identical binary. Asked on OBI-325
whether that is a wasted slot: yes, on purpose. The alternative is a rule about
"lockfile deltas whose resolved set reaches the release build graph", which reads
a resolver's behaviour off a text file and can fail *open*; one wasted slot is the
cheaper mistake. And `mudlib/**` counts as relevant even though nothing there
reaches `loom serve --mudlib warp` today. The general shape: where a rule could
be made cheaper by reading something dynamic, the cheap-but-structural rule wins.

Rule 11 (OBI-326) closes the same gap for the world under test. It reads
`warp.ref` and refuses a workflow that serves a mudlib from anything other than
that rev: every external `actions/checkout` must take its `ref` from the
`warp-pin` step and its `repository` from the one name this repo measures
against (`LoomMud/warp`), that step must be guarded by the same lane test as the
steps beside it and must validate the rev as a commit SHA, the job must re-read
the pin to verify what it checked out, the report must carry the `--note`, and
the classifier must count `warp.ref` runtime-relevant -- so a bump takes a lane
place instead of moving the goalpost under a queue of skips. The last of those is
the one that needs a second look: an unlisted path already falls closed to
"relevant", so what the explicit rule buys is a reason a reviewer can read and a
property a guard can test, not the behaviour itself.

The rev comes from the file and the repository name does not, and that asymmetry
is deliberate. A name is stable -- and `hygiene` runs rule 11 on *every* PR
whatever `classify` decides, so retargeting the load jobs at a fork fails a
required check even though `.github/**` is on the skip list. A rev is not stable:
it is the thing warp moves, so it may only ever be read from a file this repo
owns and the classifier counts.

**Rule 12: the drift backstop (OBI-326).** Pinning the world does not make it
stop moving -- `warp.ref` bumps land on warp's schedule, and a run of
runtime-irrelevant loom diffs can leave `main` unmeasured for weeks. So `ci.yml`
also carries `on.schedule` (a nightly run) and `on.workflow_dispatch`. Neither
event carries a commit range, which is precisely why they measure: the
classifier's fail-closed rule (an unreadable or absent range is never evidence
that nothing changed) makes them take the lane. The release policy follows: **a
release SHA needs a measured, green `loadtest-e1-1`, taken from the nightly run
or by dispatch** -- not a green that means "not applicable". Rule 12 asserts both
triggers stay in the workflow, for the same reason rule 8 asserts the toolchain:
they live on the skip list.

**First live skip (PR #144, run 37736253093, 2026-10-08).** The PR that
introduces this decides its own diff irrelevant, and the numbers are what the
case study was about: `classify` 7 s end to end, `loadtest-e1-1` **12 s** with
`run loom serve + E1.1 load test (150 players)`, the release build, the warp
checkout, the toolchain install and the artifact upload all reported *skipped:*
`loadtest-smoke` 8 s and `bench` 7 s behind it. The whole required chain went
from a 35-60 minute lane wait to about 90 seconds of nothing, and the only
classifier verdict that ever produced a warning was the local drill where
`python3` was missing.

**What OBI-325 does *not* fix, and what it does.** This is a throughput change,
not a measurement-integrity change. The board's own root-cause note on PR #124
is that a gate miss there came from *the same run's* `rust` job
(`cargo clippy --workspace --all-targets`, still going 35 minutes into the
measurement window) while the lane had given the gate the host to itself -- so a
path filter cannot fix that mechanism, and nobody should read this section as if
it did. The mechanism fix is a quiet runner (`CI_LOAD_RUNS_ON`, PR #131 /
OBI-311) or serialising `rust`/`fuzz` against the gate inside a run.

What it does change, besides the queue, is *who may be the neighbour*. Everything
in the lane builds the release binary, and a second release build beside a
measuring run is exactly what turned 46.91 ms into 593 ms in the table above
(37658696127 against 37658252388). An irrelevant run that skips no longer starts
that build, so it stops being a disturber as well as a queue place -- but the
same-run `rust` and `fuzz-smoke*` jobs still overlap an E1.1 measurement that
*does* take the lane, and `release-image.yml` stays outside all of it.

Both changes edit the same three files as PR #131 (`.github/workflows/ci.yml`,
`scripts/check-ci-load-lane.py`, `results/README.md`), so whichever lands second
rebases; the overlap is textual, not semantic (#131 swaps the lane jobs'
`runs-on:` for a configurable runner set, this adds a job and rules 8-10).

**What a green `loadtest-e1-1` means now.** Two different greens. On a
runtime-relevant diff it is the 150-player measurement, unchanged. On a
runtime-irrelevant one it means "not applicable": no release build, no players,
no p99, and the job writes a step summary saying so and naming the rule that
decided it. The gate is never `if:`-ed away except by `if: ${{ !cancelled() }}`,
and that one expression is not a convenience: GitHub counts a *skipped* required
check as **passing**, so `needs: classify` without it meant a classifier that
dies in infrastructure would skip the gate and hand the PR a green that had never
measured -- the fail-open the OBI-325 review caught, and the reason rule 4 checks
`needs:` and `if:` as a pair (and rejects `always()`, which would run 150 players
on a host GitHub is already cancelling). If a p99 regression is ever found on a
commit that skipped, the classifier was wrong: fix the rule (`--self-test` is the
test), not the threshold, the population, or the check.

### A workflow file that does not compile looks exactly like a stuck queue (2026-10-09)

PR #144 rebased, pushed, and then reported nothing: `gh pr checks 144` said "no
checks reported on the branch", and the only runs for the head SHAs were two
`push` entries named `.github/workflows/ci.yml` (37865259655, 37865793025) with
**0 jobs** and no downloadable logs. The reading was "Actions has stopped
scheduling this PR", and there is nothing in that shape to argue with: no check
suite, no run, no annotation. It was not a queue problem -- other PRs were being
scheduled and running at the same minutes. The cause was one line of mine inside
the `classify` job's `run: |` block:

```sh
# `loadtest-e1-1` runs `if: ${{ !cancelled() }}` now, so that hole is
```

A `#` in a script stops the shell, not Actions: `${{ ... }}` is substituted
before the script is handed over, and `cancelled()` is only available in an `if:`
condition, so the expression is invalid and the *whole file* fails to compile.
A workflow that cannot compile produces no jobs and, for `pull_request`, no check
run at all -- a required check that never posts is what branch protection reports
as "waiting for status", which is why the merge order appeared to stall on a PR
with five green checks an hour earlier. Fix (`cfef45e`): the bare expression in a
script (`if: !cancelled()`), `${{ }}` kept only where GitHub evaluates it as a
condition. Rule 10 of `check-ci-load-lane.py` now fails any `${{ }}` inside a
`run:` block that calls a status function, so the next time it is a red `hygiene`
check with a sentence instead of an absent suite, and `actionlint` (1.7.7) flags
the same class -- its `queue:` complaints are a schema lag behind the lane's own
`concurrency.queue: max`, which `main` runs with, so the parity check is
"same complaints as main, no expression errors".

### Which runs may be cancelled, and which may never be (OBI-313)

Queueing is not the only way the lane gets stuck. Because
`loom-ci-load-lane` is a queue **across runs**, one PR that takes three pushes
holds three places in it until they drain -- including the two pushes nobody
meant to measure. Run 37698132725 (2026-10-07 22:44:59Z) was a *draft* PR whose
diff was two README paragraphs and a comment block: it opened a full CI run,
took lane places, and was cancelled by hand at 22:45:42Z. Draft state does not
suppress `pull_request` runs in this repo, so "I'll keep it draft to avoid
load" is not a control we have, and a job-level `if:` that skipped runs for
drafts would *skip required checks* -- the one thing the lane rules forbid.

So `.github/workflows/ci.yml` carries a workflow-level `concurrency` block, and
the policy is written down rather than inferred from YAML.

**The rule, accepted by the CTO on 2026-10-08: no required check on a
*mergeable candidate* may be cancelled.** A mergeable candidate is the commit
branch protection actually evaluates. For a pull request that is its newest
commit, because `strict: true` means a stale SHA never satisfies the branch;
for `main` every push is a mergeable candidate, and so is any run already in
flight. A superseded PR SHA is therefore the only measurement the block is
allowed to throw away.

| Run | Cancellation | Why |
|---|---|---|
| `pull_request`, commit already superseded by a newer push to the same PR | **may be cancelled** | not a mergeable candidate: its measurements describe a SHA branch protection never evaluates, and holding its lane place only delays the gates that do count |
| `pull_request`, newest commit, anything already running | **never cancelled** | this is the mergeable candidate. `cancel-in-progress: false` + `queue: max` on the lane jobs; a cancelled required check blocks a PR exactly like a failed one |
| `push` to `main` | **never cancelled** | the group falls back to `github.run_id`, so each main run is its own group and there is nothing to cancel. OBI-311's "5 sequential un-retried E1.1 runs" on `main` stays measurable |
| `workflow_dispatch` / a re-run of any job | **never cancelled** | same `github.run_id` fallback: a re-run cannot displace the run it is re-measuring |

What it costs: the check on the superseded commit ends `cancelled` and the
newer commit is measured again, so a PR gets exactly one live E1.1 measurement
instead of one per push. Nothing measured on a mergeable candidate is ever lost,
because the newest commit is always the survivor of the cancel -- which is the
reason the OBI-308 rule ("no required check may be cancelled or skipped") and
this one are the same rule, not two competing ones.

**The trigger had to be narrowed for that to be safe.** With `types:` omitted,
GitHub fires a `pull_request` workflow for *every* activity -- `labeled`,
`assigned`, `edited`, `review_requested` -- and each of those used to start a
whole CI run that took a fresh lane place for a diff that had not changed.
Once the workflow-level block can cancel, one of them would have killed that
PR's own in-flight 150-player gate for a label. So `on.pull_request.types` is
now `[opened, synchronize, reopened]`: the only activities that change what is
being measured. `opened` and `synchronize` may not be dropped -- that is how a
required check gets quietly skipped under cover of "narrowing the trigger", and
the guard fails it.

The guard is the load-bearing part, because a workflow-level cancel reaches
into jobs whose own `cancel-in-progress: false` forbids being cancelled.

* Rule 5, if the block exists at all: `group` must contain `github.workflow`
  (a constant group name would be a repo-wide mutex where one PR cancels
  another PR's in-flight gate) **and** `github.run_id` as the non-`pull_request`
  fallback; and `cancel-in-progress` must be an expression true only for
  `pull_request` -- a literal `true`, a `!=`, an `||`, or any mention of another
  event name fails.
* Rule 6, if that block cancels PR runs: `on.pull_request.types` exists, fires
  on nothing but `opened`/`synchronize`/`reopened`, and keeps `opened` and
  `synchronize`.

The mutants aimed at rules 5 and 6 include flipping the required gate's own
`cancel-in-progress` to `true` beside the new block and putting `labeled` back
in the trigger.

## Report provenance

A number in this directory is only usable if a reader can name the world it was
measured against. Four things belong with every committed report:

| Input | Where it comes from |
|---|---|
| loom commit | the run's `github.sha` / `git rev-parse --short HEAD` |
| **warp commit** | `warp.ref` at the repo root -- one line, one 40-char SHA |
| session mix | `warp/loadbot/mix.tsv`, replayed by the load bot |
| host + build profile | the reference host table above, release build |

The warp commit is the one an agent cannot see from this repo's history, so it is
the one that silently moved: every 150-player number above was taken against
whatever `LoomMud/warp`'s default branch pointed at that day. The Phase 1
numbers are attributed to warp `618b90c` by hand, from the host's working copy --
archaeology that `warp.ref` + `--note` makes unnecessary from here on. `warp.ref`
currently names `1b0cd394d4cd41586e1a2d5fd449786b75c96976`, which is the tip the
gate was measured green against; bump it only with a load run attached to the PR.

What is *not* yet automated: the `## Notes` block that `--note` writes into the
report lands in the downloaded artifact and in the job summary, but copying it
into the header of a committed `results/ci-e1-1.md` is still a human step. That
promotion is OBI-326's follow-up.

### The first rows recorded *by* the mechanism, not by archaeology

Both taken at loom `39e2bad` on the CI lane host, with `warp.ref` naming
`1b0cd394d4cd41586e1a2d5fd449786b75c96976`, and both entered the lane because the
change touched the pin -- one by commit range, one because it had no range at all:

| Run | Event | p50 / p95 / p99 (150 players, 90 s) | Verdict | Report `## Notes` |
|---|---|---|---|---|
| 37755092634 | `pull_request` | 3.15 / 15.83 / **22.35 ms** (10 061 cmds, 0 disc, 0 login fails) | E1.1 PASS | `mudlib LoomMud/warp@1b0cd394d4cd41586e1a2d5fd449786b75c96976 (pinned in warp.ref)` |
| 37755215021 | `workflow_dispatch` | 3.27 / 16.36 / **23.91 ms** (10 011 cmds, 0 disc, 0 login fails) | E1.1 PASS | same |

The two numbers are 1.6 ms apart on the same world, which is the point: the pair is
comparable in a way the 37.6 / 39.6 / 47.7 ms records above were not. Step sequence on
both: `read the pinned mudlib rev` -> external checkout at that rev -> `verify the mudlib
under measurement` -> build -> measure -> upload, all green, so the rev in the report is
the rev served, not the rev a default branch happened to point at.

The release policy that goes with it: a release SHA needs a **measured** green
`loadtest-e1-1` -- one from the nightly `on.schedule` run, or one started by
`on.workflow_dispatch`. Since OBI-325 a PR can be green while having no p99 in it
at all, so "the check is green on the release commit" is not sufficient evidence;
the run has to be one that took the lane. Both triggers are asserted by rule 12
because they live in a path the lane itself counts irrelevant.

A trigger nobody can read the result of is no backstop either, which is what rule
13 guards. Neither `schedule` nor `workflow_dispatch` carries a commit range, and
the first dispatch run (37752599276) went red on `dco` because of it: the step's
fallback for a range-less event was an audit of *every commit reachable from HEAD*,
and this repository's merged history contains commits authored by the founder and
signed off by the agent who wrote them, so the comparison against the author fails
on the same pair (`a1d3dc4`, `7f1b074`) on every run, forever. Not strict --
unsatisfiable. The event-scoped audit now names the commits the run stands on, and
rule 13 fails any `check-dco.sh` call handed a bare rev, because the next range-less
fallback would arrive as a plausible-looking tightening of the sign-off gate. Whether
an agent's `Signed-off-by` should satisfy DCO on a human-authored commit is a policy
question for the CTO; it is not something a nightly should answer by re-judging
history the gate already accepted.

## Limitations

- **Negotiated telnet options (R1a/OBI-26)** are exercised from the bot side
  (`loom-loadtest`'s `telnet` module offers NAWS/TTYPE/CHARSET/GMCP/MSSP on
  connect and answers subnegotiation), but the driver's Phase-0 stub still
  refuses everything — R1a's own implementation was not merged (see
  OBI-26). The same bot will exercise the real negotiation once that lands,
  with no changes needed here.
- Both runs were bot and server on the same host (loopback), which is
  standard for this kind of latency proof (spec's "reference host") but
  does not model real client network RTT/jitter.
