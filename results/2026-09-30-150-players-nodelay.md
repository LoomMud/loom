# Load-test run: 150 players

- Requested duration: 90s (actual: 90.9s)
- Slow-reader cohort: 10%
- Login failures: 0
- Disconnects (incl. slow-reader backpressure drops): 0
- Commands sent (normal cohort): 10108

## Command latency (normal cohort, send -> prompt)

| p50 | p95 | p99 | max | mean | n |
|---|---|---|---|---|---|
| 0.69 ms | 4.85 ms | 8.50 ms | 36.97 ms | 1.66 ms | 10108 |

**E1.1 (p99 < 50 ms): PASS**

## Command latency (slow-reader cohort, informational only)

| p50 | p95 | p99 | max | mean | n |
|---|---|---|---|---|---|
| 401.32 ms | 802.66 ms | 803.18 ms | 1203.82 ms | 488.63 ms | 775 |

## Login latency (name -> first prompt, Argon2id included)

| p50 | p95 | p99 | max | mean | n |
|---|---|---|---|---|---|
| 71.59 ms | 140.11 ms | 141.38 ms | 142.36 ms | 82.79 ms | 150 |

## Notes

- R3 server-side metrics (loom-http /metrics) are not scraped by this run: loom-http/loom-obs are not yet on main (OBI-28); this report is bot-side latency only.
