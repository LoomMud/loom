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
for CI/scripted gating).

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
  (JSON + Markdown).

## Known gaps (tracked, not blocking this issue)

- No server-side (R3 / `loom-http` `/metrics`) scrape yet: that crate isn't
  on `main` (OBI-28 needs re-landing). `RunReport` has room for it.
- 500-player run is a stretch target with findings, not a second SLA gate;
  see `../../results/README.md`.
