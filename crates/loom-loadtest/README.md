# loom-loadtest (R4, OBI-40)

Drives N simulated telnet players against a running `loom serve`, using
Warp's alpha command mix, to prove exit criterion **E1.1**: 150 players at
p99 < 50 ms (command send -> prompt received). See `LoomMud/warp`'s
`loadbot/README.md` for the login/prompt/command-mix contract this bot
implements, and `../../results/README.md` for committed run reports.

## Usage

```
loom-loadtest --addr 127.0.0.1:4000 --mix /path/to/warp/loadbot/mix.tsv \
  --players 150 --duration-secs 90 --out results/my-run
```

Run `loom-loadtest --help` for the full flag list (ramp rate, slow-reader
cohort size/delay, think-time range, SLA threshold, `--fail-on-sla-miss`
for CI/scripted gating, `--metrics-url` to scrape `loom-http`'s `/metrics`
into the committed report, OBI-177).

For attributing a p99 tail (OBI-344), pass `--metrics-url` and, optionally,
`--metrics-scrape-ms` (default 1000: `/metrics` is polled *during* the run, so
server-side stall counters can be lined up against the slow samples instead of
only being read after the fact) and `--timeline-bucket-ms` (default 5000, the
width of the report's latency-over-time buckets).

`--note <text>` (repeatable, OBI-326) carries provenance into both the JSON and
the Markdown report. The CI load lane uses it to stamp the mudlib a number was
measured against -- `mudlib LoomMud/warp@<sha> (pinned in warp.ref)` -- so a
committed report names its inputs instead of leaving the next reader to guess.
Notes you pass are written before the run's own warnings (login failures,
disconnects), in the order given.

## Design notes

- `telnet.rs`: client-side telnet option negotiation (NAWS, TTYPE, CHARSET,
  GMCP, MSSP) and IAC stripping. Forward-compatible with R1a
  ([OBI-26](/OBI/issues/OBI-26)); degrades to a no-op against Phase 0's
  refuse-all stub.
- `mix.rs`: parses the `weight<TAB>step[;step...]` mix format and does the
  `{peer}`/`{n}` placeholder substitution per send.
- `session.rs`: one bot's connection — send a line, wait for a regex
  (usually the `<HP/MAXHPhp> ` prompt) in the decoded stream, with an
  optional artificial read delay for the slow-reader cohort.
- `bot.rs`: the login state machine (name / password / create-or-reconnect
  / class) and the run loop (pick a mix entry, run its steps, think, repeat
  until the deadline).
- `report.rs`: nearest-rank percentiles and the committed report format
  (JSON + Markdown). Every latency sample also carries its offset from the
  start of the run, which is what makes the timeline and the attribution
  below possible.
- `server_metrics.rs`: parses the scraped `/metrics` text into a per-scrape
  timeline of `loom-obs`'s world-loop counters, and turns a counter that
  *increased between two scrapes* into the interval it covers. Absent series
  are `None`, never `Some(0.0)`: "this server records no world-loop metrics"
  and "this server had no stalls" are different findings and must not render
  the same way.
- `attribution.rs`: given the tail (samples at or over the SLA) and the
  candidate cause windows -- server world-loop stalls, loadtest-process timer
  starvation, the login ramp -- ranks each sample's cause and reports the
  split, plus p99 with server-stall-attributed slices removed as an
  *informational* number only. The gate remains the measured p99.

## Known gaps (tracked, not blocking this issue)

- 500-player run is a stretch target with findings, not a second SLA gate;
  see `../../results/README.md`.
- Tail attribution resolves server-side stalls to the scrape interval
  (`--metrics-scrape-ms`, default 1 s), not to the millisecond. A stall that
  starts and ends inside one interval is attributed to that whole interval --
  which is why attribution says "overlapped a stall window", not "caused by".
- The loadtest measures the bot's own scheduling lag (think-pause overshoot,
  reported as "Loadtest process timer lag") but the bot process and the server
  share the CI runner, so a starved bot and a stalled world can look alike in
  a single run. Read both sections together.
