# Load-test run: 500 players

- Requested duration: 90s (actual: 92.2s)
- Slow-reader cohort: 10%
- Login failures: 0
- Disconnects (incl. slow-reader backpressure drops): 0
- Commands sent (normal cohort): 23340

## Command latency (normal cohort, send -> prompt)

| p50 | p95 | p99 | max | mean | n |
|---|---|---|---|---|---|
| 430.47 ms | 588.77 ms | 697.77 ms | 764.68 ms | 382.62 ms | 23340 |

**E1.1 (p99 < 50 ms): FAIL**

## Command latency (slow-reader cohort, informational only)

| p50 | p95 | p99 | max | mean | n |
|---|---|---|---|---|---|
| 802.82 ms | 2006.56 ms | 2407.70 ms | 3207.18 ms | 1087.36 ms | 1830 |

## Login latency (name -> first prompt, Argon2id included)

| p50 | p95 | p99 | max | mean | n |
|---|---|---|---|---|---|
| 72.60 ms | 395.89 ms | 644.22 ms | 1158.69 ms | 113.92 ms | 500 |

## Notes

- R3 server-side metrics (loom-http /metrics) are not scraped by this run: loom-http/loom-obs are not yet on main (OBI-28); this report is bot-side latency only.
