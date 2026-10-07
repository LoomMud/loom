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

- Every latency-measuring job **and every CPU-heavy build/fuzz job** is in the
  job-level concurrency group `loom-ci-load-lane`: `loadtest-e1-1`,
  `loadtest-smoke`, `bench`, plus `rust`, `fuzz-smoke`, `fuzz-smoke-bytecode`
  and `fuzz-smoke-lsp`. Job-level groups are keyed by *name across the jobs of
  a workflow* (measured, see below), so at most one heavy thing runs repo-wide
  at a time and a second PR's gate **queues** instead of racing.
- `cancel-in-progress: false` -- a measurement already running is never
  killed. `queue: max` -- pending runs wait in FIFO instead of the default
  `single`, where the third run cancels the pending one. A *cancelled*
  required check blocks a PR exactly like a failed one, so queueing (not
  replacing) is part of not weakening the gate.
- The jobs are also chained with `needs` inside a run:
  `loadtest-e1-1` -> `loadtest-smoke` -> `bench`. The required gate goes
  first and has no `needs:`/`if:` of its own, so nothing upstream can skip
  it; the two non-required gates wait for it instead of competing with it.
- Each gate carries wall-clock headroom (`timeout-minutes` 30 for E1.1, 20 for
  the smoke run) because lane jobs queue behind every other heavy job in the
  group, and a starved release build does not fail the check -- it gets
  **cancelled**, which blocks a PR just as hard and leaves no p99 to read
  (run 37663331238, 2026-10-07 18:01:00Z -> 18:16Z, cancelled mid-build while
  an intentionally contending probe PR ran eight jobs beside it). Slow is
  survivable; cancelled is not.
- `scripts/check-ci-load-lane.py` asserts all of the above (and that the
  gate still runs 150 players with `--fail-on-sla-miss`, keeps its timeout
  headroom, and that no required check became skippable or optional), plus a
  `--self-test` of 17 mutations (18 cases). Both run in the required `hygiene`
  job, so the lane cannot rot silently and the comment here cannot drift from
  the workflow. The mutation set now includes "`rust` leaves the lane" and
  "`web-client` joins the lane", i.e. it guards both directions of membership.

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
