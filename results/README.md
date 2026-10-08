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
remain the reference-host record). As of this gate landing, the scraped
`/metrics` body is typically empty in CI runs: `loom-net`/the world
thread don't yet record any `metrics::counter!`/`histogram!` values on
the connection/command path, so there's nothing for `loom-obs`'s
recorder to render. That's a separate instrumentation gap, not a bug in
the scrape itself -- `--metrics-url` will start carrying real server-side
histograms once that lands.

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
block did that, so it is evidence for neither side. As of 2026-10-08 03:42Z, 3 of
8 open PRs carry the block (`#122 3554996`, `#124 db18202`, `#139 8ca37b5`); the
other five reach it by rebasing onto current `main`, which is the only way a PR
gets inside the rule at all.

**The queue question has a documented answer, and an unobserved half.** The
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

The half that stays unobserved is the interaction between the two levels -- a
workflow-level cancel landing on a job that is mid-queue inside
`loom-ci-load-lane`, whose own `cancel-in-progress: false` forbids being
cancelled. #136's header asserts the cancel reaches it, the wording above
supports it, and no run has demonstrated it yet: until #136 merged there was
never a pair of runs sharing a group, and every supersede since has involved a
head that lacks the block. The first natural test is the next `synchronize` on
#122, #124 or #139 -- the three PRs that carry it -- and the observable is
whether the superseded run's *waiting* `loadtest-e1-1` ends `cancelled`. Record
the result here either way. If it does not, option 1 from OBI-322 (an
in-workflow "am I still the PR head?" guard) is the fallback, and it goes to the
CTO: it costs a `pull-requests: read` token on a workflow that today holds only
`contents: read`, and it would inherit the same coverage limit as the block.

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

The guard is the load-bearing part, because a workflow-level cancel is assumed
to reach into jobs whose own `cancel-in-progress: false` forbids being cancelled
(see the unobserved note above).

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
