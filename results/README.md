# Load-test results (R4, OBI-40)

Reports committed by `loom-loadtest` runs (`crates/loom-loadtest`), one JSON +
one Markdown per run, named `<date>-<players>-players[-<label>].{json,md}`.

## E1.1 (150 players)

`2026-09-27-150-players.{json,md}`: **PASS**, p99 46.91 ms < 50 ms SLA.

Reference host: Intel Core i7-9750H @ 2.60GHz (12 logical CPUs), 32 GiB RAM,
Linux. `loom serve --mudlib warp` (this checkout's mudlib snapshot, `HEAD` at
run time), `loom-loadtest` on the same host (so this includes no network
latency beyond loopback — see "Limitations" below).

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

- Each of the three jobs is in the job-level concurrency group
  `loom-ci-load-lane`, so a second PR's copy of the same gate **queues**
  instead of racing.
- `cancel-in-progress: false` -- a measurement already running is never
  killed. `queue: max` -- pending runs wait in FIFO instead of the default
  `single`, where the third run cancels the pending one. A *cancelled*
  required check blocks a PR exactly like a failed one, so queueing (not
  replacing) is part of not weakening the gate.
- The jobs are also chained with `needs` inside a run:
  `loadtest-e1-1` -> `loadtest-smoke` -> `bench`. The required gate goes
  first and has no `needs:`/`if:` of its own, so nothing upstream can skip
  it; the two non-required gates wait for it instead of competing with it.
- Each gate carries wall-clock headroom (`timeout-minutes` 30 for E1.1, 20
  for the smoke run). The lane removes a second *gate* from the host, not
  this run's own `rust` job or another PR's builds, and a release build
  starved past the old 15-minute budget does not fail the check -- it gets
  **cancelled**, which blocks a PR just as hard and leaves no p99 to read
  (run 37663331238, 2026-10-07 18:01:00Z -> 18:16Z, cancelled mid-build while
  an intentionally contending probe PR ran eight jobs beside it). Slow is
  survivable; cancelled is not.
- A stale SHA is not allowed to hold a place: the workflow also carries a
  workflow-level `concurrency` group that cancels a PR's *superseded* runs and
  nothing else -- no required check on a mergeable candidate is ever cancelled
  -- and the PR trigger is narrowed to the activities that change the commit.
  It only reaches runs whose own workflow copy declares the block, so a PR that
  has not rebased onto `0b8ca74` yet is cancelled by hand instead. See "Which
  runs may be cancelled" below.
- `scripts/check-ci-load-lane.py` asserts all of the above (and that the
  gate still runs 150 players with `--fail-on-sla-miss`, keeps its timeout
  headroom, that no required check became skippable or optional, and that the
  workflow-level block can only ever cancel a superseded `pull_request` run),
  plus a `--self-test` of 26 mutations. Both run in the required `hygiene`
  job, so the lane cannot rot silently and the comment here cannot drift from
  the workflow.

**What the lane does *not* claim.** GitHub scopes a job-level concurrency
group per workflow *and job*, so the hard guarantee is "the same gate never
runs twice at once". Two *different* gates from two different PRs (PR A's
`bench` against PR B's `loadtest-e1-1`) can still land on the host together;
the `needs` chain removes that overlap inside a run, not across runs. The
same-run `rust` job (`cargo test --workspace`) and the `fuzz-smoke*` jobs also
stay parallel, and `release-image.yml` builds are outside the lane. All of
that is runner capacity, not YAML: the durable fix is a dedicated/ephemeral
load host, which is a CTO call and explicitly out of scope for OBI-308.

**If you see `loadtest-e1-1` waiting** ("Waiting for job to run" on the
checks tab): that is the lane working, and it has been watched working. On
2026-10-07 PR #128 (carrying this change) took the lane at 18:01:00Z; the
probe PR #129's `loadtest-e1-1` sat `pending` from 18:00:58Z and only started
at 18:20:35Z, ~19.5 minutes later, *after* #128's job left the group -- it was
never cancelled and never co-scheduled. One E1.1 slot costs ~3.5 min of
runner wall-clock (build cache warm), so a queue of two PRs clears in well
under ten. Do not respond to a wait, or to a p99 miss on a run that overlapped
another, by raising the threshold, dropping the population, marking the check
optional, or re-running it into a quiet window by hand -- `hygiene` fails
those changes.

### Which runs may be cancelled, and which may never be (OBI-313)

Queueing is not the only way the lane gets stuck. Because
`loom-ci-load-lane` is a FIFO **across runs**, one PR that takes three pushes
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
commit, because `strict: true` + `required_linear_history: true` mean a stale
SHA never satisfies the branch; for `main` every push is a mergeable candidate,
and so is any run already in flight. A superseded PR SHA is therefore the only
measurement the block is allowed to throw away.

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

**What the block can reach (OBI-322).** A run joins this group only if *its
own* copy of `ci.yml` declares the block: `concurrency` is read per run, from
the workflow file at that run's commit. A superseded commit that does not
contain `45d85b6` -- the commit that adds this block, on main since the `0b8ca74`
merge -- sits in an implicit per-run group that nothing on `main` can cancel --
not this block, and not a guard step added to `ci.yml` later either, because a
step only exists in runs that already contain it. Those runs are cancelled by
hand, which is expected practice during the transition and not an incident:

```bash
gh run list --repo LoomMud/loom --workflow ci --branch <pr-head-branch> \
  --json databaseId,number,headSha,status,createdAt \
  --jq '.[] | select(.status != "completed")'   # runs still holding lane places
gh run cancel <databaseId>                       # only when nothing is measuring
```

Check the required gate is not mid-flight first. GitHub stamps `started_at` on a
lane job the moment it *starts waiting*, so `started_at` alone proves nothing --
run 37717596409's `loadtest-smoke` and `bench` both carry `started_at`
02:50:43Z, the second that run was cancelled, and never executed. But a job
still pending after its own `timeout-minutes` cannot have been executing,
because it would have finished or hit the budget. Two runs were cancelled on
2026-10-08 on that basis, both for a documented reason and neither mid-gate:

* 37720694440 (PR #138's superseded `9a23ab5`) at 03:51:41Z -- its
  `loadtest-e1-1` had been pending 50 minutes against a 30-minute budget, and
  it went `cancelled` without a measurement.
* 37716516501 (PR #124's twice-superseded `b3a9998`) at 03:58:38Z -- its
  required gate and `loadtest-smoke` had already gone green on that commit, and
  its `bench` had been pending 28 minutes against a 20-minute budget.

**The two reports that started OBI-322 were not the queue swallowing a cancel.**
Run 37718540063 (PR #124, `7db7279`) and run 37717596409 (PR **#122**, `8d160e8`
-- not PR #180 as first written down) both carry a `ci.yml` with no workflow-level
`concurrency` block at all, checked per head with
`GET /repos/{owner}/{repo}/contents/.github/workflows/ci.yml?ref=<head_sha>`. So
neither was ever a member of `ci-refs/pull/<n>/merge`, and neither was available
to be cancelled by the block. 37717596409 in particular ended `cancelled` at
02:50:43Z while its `loadtest-e1-1` was **executing** (02:46:40Z -> 02:50:42Z),
49 s after its successor run 37719788325 was created -- something outside the
block did that, so it is evidence for neither side. Coverage moves as PRs get
rebased, so re-measure instead of trusting these numbers: at 2026-10-08 03:42Z, 3
of 8 open PRs carried the block (`#122 3554996`, `#124 db18202`, `#139 8ca37b5`);
rescanned at 04:25Z the same day, 5 of 10 did (`#122 3554996`, `#124 db18202`,
`#139 d8af8a6`, `#140 b108d49`, `#141 9301a0c`; missing `#101`, `#127`, `#131`,
`#134`, `#138`). The rest reach the rule only by rebasing onto current `main` --
there is no other way a PR gets inside it:

```bash
for pr in $(gh pr list --repo LoomMud/loom --state open --json number --jq '.[].number'); do
  sha=$(gh pr view "$pr" --repo LoomMud/loom --json headRefOid --jq .headRefOid)
  has=$(gh api "repos/LoomMud/loom/contents/.github/workflows/ci.yml?ref=$sha" \
          --jq .content | base64 -d | grep -c '^concurrency:')
  [ "$has" -ge 1 ] && echo "#$pr ${sha:0:7} CARRIES" || echo "#$pr ${sha:0:7} missing"
done
```

The marker is a workflow-level `^concurrency:` at column 0. Do not grep for the
rendered group name: `${{ github.workflow }}` is `ci`, and `ci-refs/pull/<n>/merge`
only exists once the expression is evaluated at run time.

**A merged PR's leftover gates are covered by nothing.** PR #136's own run
37717628548 (head `5429a0b`) is the counter-example: the PR merged at 03:14Z and
the run kept measuring afterwards -- its `loadtest-smoke` took a lane slot
04:04:42Z -> 04:07:24Z, 50 minutes after the merge, with `bench` queued behind
it. A merge does not create a new `pull_request` run, so nothing ever joins
`ci-refs/pull/136/merge` to displace it, while `main`'s push run 37721777219
(`0b8ca74`) measures the same tree plus the merge. By the argument that makes a
superseded SHA cancellable -- a commit branch protection will never evaluate --
these are stale measurements too, but the rule as accepted names only "superseded
by a newer push to the same PR", so cancelling one would be acting outside the
written rule. It is a CTO question, not an edit: are a merged PR's still-queued
gates a cancellable category? Until that is answered they run to completion.
(Attribution caveat while checking: `GET /actions/runs/{id}` returns
`pull_requests: []` once a PR has merged, so map runs to PRs by `head_branch`
plus `event`, not by that field.)

**The queue question, settled by wording and then by observation.** The
[workflow syntax reference](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idconcurrency)
says of a concurrency group: "When a concurrent job or workflow is queued, if
another job or workflow using the same concurrency group in the repository is in
progress, the queued job or workflow will be `pending`. By default, any existing
pending job or workflow in the same concurrency group will be canceled and the
new queued job or workflow will take its place. To also cancel any currently
running job or workflow in the same concurrency group, specify
`cancel-in-progress: true`." Both states are covered for our case, because the
block sets `cancel-in-progress` true for `pull_request`. Run 37723058077 (PR
#124's head, `db18202`) is in exactly that shape as of 04:05Z: 8 of its 9 jobs
are green and only `loadtest-e1-1` waits on the lane, and the *run* reports
`status: pending`. That is also why a run's `status` is not the safety signal for
hand-cancelling -- the per-job timestamps are.

What the same reference does settle is the cost of leaving a stale run alive:
"Jobs or workflow runs in the same concurrency group are processed in
first-in-first-out (FIFO) order according to the time each one started waiting on
the concurrency group, not the time each workflow was dispatched." Inside PR #124
on 2026-10-08 the timestamps say exactly that -- the twice-superseded run
37716516501 held a lane slot for `loadtest-smoke` 03:18:45Z -> 03:30:38Z, the
superseded run 37718540063 held one for `loadtest-e1-1` 03:31:48Z -> 03:35:05Z,
and 37723058077, the actual head, created 03:30:35Z, waited behind both. A stale
run that is not cancelled does not merely waste a measurement: it takes the lane
*before* the mergeable candidate.

**The queued case is now observed, and it does cancel.** The boundary between
the two levels -- a workflow-level cancel landing on a job sitting mid-queue in
`loom-ci-load-lane`, whose own `cancel-in-progress: false` forbids being
cancelled -- was demonstrated on this very PR on 2026-10-08. Run 37725992152
(head `c167498`) had `loadtest-e1-1` waiting in the lane since 04:07:50Z, with no
measurement taken, because `loadtest-e1-1` carries no `needs:` and queues on the
lane from the first second. Pushing `ccd23a5` created run 37726332056 at
04:12:03Z, and one second later `loadtest-e1-1` ended `cancelled` (04:12:04Z),
`loadtest-smoke` and `bench` with it; the run closed `cancelled` at 04:12:39Z
when its last non-lane job let go. Nothing in the lane lost a measurement -- the
cancelled gate had never started, which is exactly what `queue: max` on the jobs
plus `cancel-in-progress: true` on the PR-scoped group is meant to buy. The same
shape repeated one commit later: run 37726332056's `loadtest-e1-1`, queued since
04:12:39Z and never started, ended `cancelled` at 04:16:18Z, one second after run
37726682123 (`7f4ee86`) was created.

So OBI-322's "queued in the load lane" gap does not exist for runs that are
inside the group, and option 1 (an in-workflow "am I still the PR head?" guard,
needing a `pull-requests: read` token on a workflow that today holds only
`contents: read`) has no remaining justification: the two real gaps -- heads that
lack the block, and a merged PR no successor will ever displace -- are both
outside its reach as well, because a step only runs in runs that already contain
it. What is left to do is ordinary branch hygiene (rebase the open PRs that the
command above reports as `missing` onto current `main`, which is what puts them
inside the rule) plus the CTO question above.

One correction this experiment also settles: #136's header claimed a
workflow-level cancel reaches into jobs whose own `cancel-in-progress: false`
forbids being cancelled. That was written from GitHub's wording without an
observation behind it, and it is right.

Nothing in any of this licenses changing the lane to make stale runs disappear:
`cancel-in-progress: true` on `loom-ci-load-lane` kills live measurements, which
is the invariant OBI-308 exists to protect and rule 1 pins -- and as a `queue:
max` group it would not even pass workflow validation, since GitHub rejects that
combination outright. The lane may queue up to 100 waiters or replace them, never
both.

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

The guard is the load-bearing part, because a workflow-level cancel really does
reach into jobs whose own `cancel-in-progress: false` forbids being cancelled --
observed on 2026-10-08 in the section above.

* Rule 5, if the block exists at all: `group` must contain `github.workflow`
  (a constant group name would be a repo-wide mutex where one PR cancels
  another PR's in-flight gate) **and** `github.run_id` as the non-`pull_request`
  fallback; and `cancel-in-progress` must be an expression true only for
  `pull_request` -- a literal `true`, a `!=`, an `||`, or any mention of another
  event name fails.
* Rule 6, if that block cancels PR runs: `on.pull_request.types` exists, fires
  on nothing but `opened`/`synchronize`/`reopened`, and keeps `opened` and
  `synchronize`.

Eleven mutants prove both bite, including flipping the required gate's own
`cancel-in-progress` to `true` beside the new block and putting `labeled` back
in the trigger.

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
