# Load-test run: 500 players

- Requested duration: 90s (actual: 92.0s)
- Slow-reader cohort: 10%
- Login failures: 0
- Disconnects (incl. slow-reader backpressure drops): 0
- Commands sent (normal cohort): 19127
- Prompt timeouts, excluded from the distribution: 0

## Command latency (normal cohort, send -> prompt)

| p50 | p95 | p99 | max | mean | n |
|---|---|---|---|---|---|
| 872.76 ms | 1060.67 ms | 1152.99 ms | 1273.69 ms | 753.84 ms | 19127 |

**E1.1 (p99 < 50 ms): FAIL**

## Command latency (slow-reader cohort, informational only)

| p50 | p95 | p99 | max | mean | n |
|---|---|---|---|---|---|
| 1203.05 ms | 2005.58 ms | 2806.61 ms | 2808.02 ms | 1299.43 ms | 1635 |

## Login latency (name -> first prompt, Argon2id included)

| p50 | p95 | p99 | max | mean | n |
|---|---|---|---|---|---|
| 197.93 ms | 4374.51 ms | 5094.89 ms | 5465.52 ms | 961.97 ms | 500 |

## Tail attribution (OBI-344)

- Samples at or over the 50 ms SLA: **0** of 19127
- overlapping a server world-loop stall window: **0** (0% of the tail), 0 of them by a window the server measured rather than bracketed
- overlapping a loadtest-process timer-starvation window: 0
- inside the login ramp (t+ <= 0.0 s): 0
- unexplained by any of the above: **0**
- p99 as measured: 1152.99 ms; p99 with server-stall-attributed slices removed: 0.00 ms. Informational only -- the gate stays the former.
- Window placement: no server stall window could be placed for this run, so nothing here attributes the tail to the world thread. Scraped every 0 ms.

## Notes

- R3 server-side metrics (loom-http /metrics) are not scraped by this run: loom-http/loom-obs are not yet on main (OBI-28); this report is bot-side latency only.
- re-rendered by `loom-loadtest --rerender` from results/2026-09-27-500-players-stretch.json: stall windows rebuilt from the report's own scrape series (no server stall window could be placed for this run, so nothing here attributes the tail to the world thread), tail re-attributed against them, timeline re-marked. `p99_excluding_server_stall_ms` is inherited from the archived report -- re-ranking it needs every sample, which a report does not carry. p99 and the E1.1 gate are the archived run's measurements, unchanged. The archived run scraped no instrumented server, so no windows were rebuilt: the timeline keeps the stall marks the run wrote, and the bucket-level figures are not this re-render's claim.

