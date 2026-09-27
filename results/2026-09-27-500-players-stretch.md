# Load-test run: 500 players

- Requested duration: 90s (actual: 92.0s)
- Slow-reader cohort: 10%
- Login failures: 0
- Disconnects (incl. slow-reader backpressure drops): 0
- Commands sent (normal cohort): 19127

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

## Notes

- R3 server-side metrics (loom-http /metrics) are not scraped by this run: loom-http/loom-obs are not yet on main (OBI-28); this report is bot-side latency only.
