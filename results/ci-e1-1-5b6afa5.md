# Load-test run: 150 players

- Requested duration: 90s (actual: 90.7s)
- Slow-reader cohort: 10%
- Login failures: 0
- Disconnects (incl. slow-reader backpressure drops): 0
- Commands sent (normal cohort): 10057
- Prompt timeouts, excluded from the distribution: 0

## Command latency (normal cohort, send -> prompt)

| p50 | p95 | p99 | max | mean | n |
|---|---|---|---|---|---|
| 1.26 ms | 9.27 ms | 16.41 ms | 92.31 ms | 2.95 ms | 10057 |

**E1.1 (p99 < 50 ms): PASS**

## Command latency (slow-reader cohort, informational only)

| p50 | p95 | p99 | max | mean | n |
|---|---|---|---|---|---|
| 401.26 ms | 802.54 ms | 803.54 ms | 1204.27 ms | 471.27 ms | 824 |

## Login latency (name -> first prompt, Argon2id included)

| p50 | p95 | p99 | max | mean | n |
|---|---|---|---|---|---|
| 64.73 ms | 137.34 ms | 140.16 ms | 143.76 ms | 67.19 ms | 150 |

Login split, account-service half only (Argon2id + `login_start`, off the world thread): p50 8.00 ms, p99 68.00 ms, max 69.00 ms. Whatever is left of the login p50 above happens on the world thread.

## Latency timeline (normal cohort)

| t+ (s) | n | p50 | p95 | p99 | max | > SLA | server stall in slice |
|---|---|---|---|---|---|---|---|
| 0.0 | 202 | 0.68 | 3.46 | 6.44 | 7.82 | 0 | no |
| 5.0 | 480 | 1.14 | 6.14 | 7.95 | 11.96 | 0 | no |
| 10.0 | 618 | 1.04 | 7.65 | 14.49 | 23.01 | 0 | no |
| 15.0 | 591 | 1.08 | 7.74 | 11.23 | 12.93 | 0 | no |
| 20.0 | 576 | 0.96 | 5.66 | 7.60 | 9.25 | 0 | no |
| 25.0 | 593 | 1.08 | 6.52 | 10.75 | 15.15 | 0 | no |
| 30.0 | 570 | 1.25 | 6.85 | 10.26 | 12.95 | 0 | no |
| 35.0 | 604 | 2.54 | 14.94 | 28.13 | 55.74 | 3 | no |
| 40.0 | 596 | 2.88 | 18.21 | 57.71 | 92.31 | 6 | yes |
| 45.0 | 574 | 2.30 | 11.80 | 15.89 | 21.78 | 0 | no |
| 50.0 | 568 | 2.19 | 12.38 | 18.16 | 23.47 | 0 | no |
| 55.0 | 610 | 1.48 | 10.78 | 18.76 | 23.74 | 0 | no |
| 60.0 | 594 | 2.15 | 8.42 | 16.13 | 26.36 | 0 | no |
| 65.0 | 573 | 1.64 | 10.11 | 18.43 | 24.22 | 0 | no |
| 70.0 | 564 | 1.02 | 7.55 | 11.71 | 28.40 | 0 | no |
| 75.0 | 593 | 0.95 | 5.91 | 8.94 | 14.74 | 0 | no |
| 80.0 | 579 | 1.00 | 7.50 | 11.25 | 18.49 | 0 | no |
| 85.0 | 572 | 1.15 | 9.28 | 15.28 | 28.36 | 0 | no |

## Slowest samples (top 20, informational)

| sent at t+ (s) | latency (ms) |
|---|---|
| 40.080 | 92.31 |
| 40.080 | 83.92 |
| 40.075 | 79.28 |
| 40.106 | 66.62 |
| 40.108 | 64.17 |
| 40.115 | 57.71 |
| 35.816 | 55.74 |
| 35.814 | 55.31 |
| 35.833 | 52.26 |
| 35.827 | 47.00 |
| 40.059 | 46.99 |
| 35.813 | 39.62 |
| 42.737 | 32.22 |
| 40.144 | 31.25 |
| 39.585 | 29.31 |
| 42.741 | 28.94 |
| 72.534 | 28.40 |
| 42.749 | 28.39 |
| 89.351 | 28.36 |
| 39.588 | 28.13 |

## Tail attribution (OBI-344)

- Samples at or over the 50 ms SLA: **9** of 10057
- overlapping a server world-loop stall window: **6** (67% of the tail), 6 of them by a window the server measured rather than bracketed
- overlapping a loadtest-process timer-starvation window: 0
- inside the login ramp (t+ <= 10.2 s): 0
- unexplained by any of the above: **3** (read the window-placement note below before treating this as "the server was fine at those moments": 0 of the 6 stall-attributed samples were explained by a bracket, not a measurement)
- Every at-or-over-SLA sample is carried in this report's JSON as `tail_samples_over_sla` (9 here, 20 listed above), so the attribution can be re-rendered under new window logic without rerunning the run.
- p99 as measured: 16.41 ms; p99 with server-stall-attributed slices removed: 15.99 ms. Informational only -- the gate stays the former.
- Window placement: every server stall window below is the server's own measurement (`loom_world_loop_last_stall_*`), placed on the run's `t+` axis from the wall clock read at scrape time. Scraped every 1000 ms.

| server stall window (t+ s) | stalls | stall ms | placed |
|---|---|---|---|
| 40.1 - 40.2 | 1 | 51 | measured |

## Loadtest process timer lag (self-measured)

| p50 | p95 | p99 | max | n |
|---|---|---|---|---|
| 1.07 ms | 1.84 ms | 3.67 ms | 7.31 ms | 7499 |

How late a fixed-interval timer fired inside the loadtest process. Lag here inflates every latency number this run reports, including the gate's, which is why it is measured rather than assumed away.

## Server world-loop counters (scraped during the run)

| t+ (s) | tick id | iterations | stalls | stall ms | dur max | gap max | cmd blocked | runtime errors |
|---|---|---|---|---|---|---|---|---|
| 0.0 | 1 | 4 | - | - | 1 | 21 | - | - |
| 1.0 | 11 | 182 | - | - | 7 | 67 | - | - |
| 2.0 | 21 | 371 | - | - | 7 | 67 | - | - |
| 3.0 | 31 | 584 | - | - | 7 | 67 | - | - |
| 4.0 | 41 | 791 | - | - | 26 | 67 | - | - |
| 5.0 | 51 | 1013 | - | - | 26 | 67 | - | - |
| 6.0 | 61 | 1246 | - | - | 26 | 67 | - | - |
| 7.0 | 71 | 1504 | - | - | 26 | 67 | - | - |
| 8.0 | 81 | 1775 | - | - | 26 | 67 | - | - |
| 9.0 | 91 | 2033 | - | - | 26 | 67 | - | - |
| 10.0 | 101 | 2319 | - | - | 26 | 67 | - | - |
| 11.0 | 111 | 2486 | - | - | 26 | 67 | - | - |
| 12.0 | 121 | 2627 | - | - | 26 | 67 | - | - |
| 13.0 | 131 | 2761 | - | - | 26 | 67 | - | - |
| 14.0 | 141 | 2900 | - | - | 26 | 67 | - | - |
| 15.0 | 151 | 3059 | - | - | 26 | 67 | - | - |
| 16.0 | 161 | 3207 | - | - | 26 | 67 | - | - |
| 17.0 | 171 | 3338 | - | - | 26 | 67 | - | - |
| 18.0 | 181 | 3469 | - | - | 26 | 67 | - | - |
| 19.0 | 191 | 3601 | - | - | 26 | 67 | - | - |
| 20.0 | 201 | 3746 | - | - | 26 | 67 | - | - |
| 21.0 | 211 | 3876 | - | - | 26 | 67 | - | - |
| 22.0 | 221 | 4000 | - | - | 26 | 67 | - | - |
| 23.0 | 231 | 4144 | - | - | 26 | 67 | - | - |
| 24.0 | 241 | 4287 | - | - | 26 | 67 | - | - |
| 25.0 | 251 | 4418 | - | - | 26 | 67 | - | - |
| 26.0 | 261 | 4556 | - | - | 26 | 67 | - | - |
| 27.0 | 271 | 4703 | - | - | 26 | 67 | - | - |
| 28.0 | 281 | 4831 | - | - | 26 | 67 | - | - |
| 29.0 | 291 | 4955 | - | - | 26 | 67 | - | - |
| 30.0 | 301 | 5111 | - | - | 26 | 67 | - | - |
| 31.0 | 311 | 5221 | - | - | 26 | 67 | - | - |
| 32.0 | 321 | 5359 | - | - | 26 | 67 | - | - |
| 33.0 | 331 | 5487 | - | - | 26 | 67 | - | - |
| 34.0 | 341 | 5628 | - | - | 26 | 67 | - | - |
| 35.0 | 351 | 5776 | - | - | 26 | 67 | - | - |
| 36.0 | 361 | 5888 | - | - | 26 | 67 | - | - |
| 37.0 | 371 | 6045 | - | - | 26 | 67 | - | - |
| 38.0 | 381 | 6199 | - | - | 26 | 67 | - | - |
| 39.0 | 391 | 6333 | - | - | 26 | 67 | - | - |
| 40.0 | 401 | 6482 | - | - | 26 | 67 | - | - |
| 41.0 | 411 | 6613 | 1 | 51 | 51 | 67 | - | - |
| 42.0 | 421 | 6745 | 1 | 51 | 51 | 67 | - | - |
| 43.0 | 431 | 6898 | 1 | 51 | 51 | 67 | - | - |
| 44.0 | 441 | 7028 | 1 | 51 | 51 | 67 | - | - |
| 45.0 | 451 | 7173 | 1 | 51 | 51 | 67 | - | - |
| 46.0 | 461 | 7322 | 1 | 51 | 51 | 67 | - | - |
| 47.0 | 471 | 7456 | 1 | 51 | 51 | 67 | - | - |
| 48.0 | 481 | 7585 | 1 | 51 | 51 | 67 | - | - |
| 49.0 | 491 | 7724 | 1 | 51 | 51 | 67 | - | - |
| 50.0 | 501 | 7851 | 1 | 51 | 51 | 67 | - | - |
| 51.0 | 511 | 7988 | 1 | 51 | 51 | 67 | - | - |
| 52.0 | 521 | 8130 | 1 | 51 | 51 | 67 | - | - |
| 53.0 | 531 | 8252 | 1 | 51 | 51 | 67 | - | - |
| 54.0 | 541 | 8391 | 1 | 51 | 51 | 67 | - | - |
| 55.0 | 551 | 8526 | 1 | 51 | 51 | 67 | - | - |
| 56.0 | 561 | 8663 | 1 | 51 | 51 | 67 | - | - |
| 57.0 | 571 | 8794 | 1 | 51 | 51 | 67 | - | - |
| 58.0 | 581 | 8933 | 1 | 51 | 51 | 67 | - | - |
| 59.0 | 591 | 9084 | 1 | 51 | 51 | 67 | - | - |
| 60.0 | 601 | 9234 | 1 | 51 | 51 | 67 | - | - |
| 61.0 | 611 | 9364 | 1 | 51 | 51 | 67 | - | - |
| 62.0 | 621 | 9482 | 1 | 51 | 51 | 67 | - | - |
| 63.0 | 631 | 9637 | 1 | 51 | 51 | 67 | - | - |
| 64.0 | 641 | 9766 | 1 | 51 | 51 | 67 | - | - |
| 65.0 | 651 | 9924 | 1 | 51 | 51 | 67 | - | - |
| 66.0 | 661 | 10047 | 1 | 51 | 51 | 67 | - | - |
| 67.0 | 671 | 10181 | 1 | 51 | 51 | 67 | - | - |
| 68.0 | 681 | 10324 | 1 | 51 | 51 | 67 | - | - |
| 69.0 | 691 | 10452 | 1 | 51 | 51 | 67 | - | - |
| 70.0 | 701 | 10589 | 1 | 51 | 51 | 67 | - | - |
| 71.0 | 711 | 10717 | 1 | 51 | 51 | 67 | - | - |
| 72.0 | 721 | 10850 | 1 | 51 | 51 | 67 | - | - |
| 73.0 | 731 | 10981 | 1 | 51 | 51 | 67 | - | - |
| 74.0 | 741 | 11125 | 1 | 51 | 51 | 67 | - | - |
| 75.0 | 751 | 11250 | 1 | 51 | 51 | 67 | - | - |
| 76.0 | 761 | 11393 | 1 | 51 | 51 | 67 | - | - |
| 77.0 | 771 | 11528 | 1 | 51 | 51 | 92 | - | - |
| 78.0 | 781 | 11671 | 1 | 51 | 51 | 92 | - | - |
| 79.0 | 791 | 11802 | 1 | 51 | 51 | 92 | - | - |
| 80.0 | 801 | 11937 | 1 | 51 | 51 | 92 | - | - |
| 81.0 | 811 | 12056 | 1 | 51 | 51 | 92 | - | - |
| 82.0 | 821 | 12199 | 1 | 51 | 51 | 92 | - | - |
| 83.0 | 831 | 12350 | 1 | 51 | 51 | 92 | - | - |
| 84.0 | 841 | 12482 | 1 | 51 | 51 | 92 | - | - |
| 85.0 | 851 | 12614 | 1 | 51 | 51 | 92 | - | - |
| 86.0 | 861 | 12739 | 1 | 51 | 51 | 92 | - | - |
| 87.0 | 871 | 12880 | 1 | 51 | 51 | 92 | - | - |
| 88.0 | 881 | 13003 | 1 | 51 | 51 | 92 | - | - |
| 89.0 | 891 | 13161 | 1 | 51 | 51 | 92 | - | - |
| 90.0 | 901 | 13285 | 1 | 51 | 51 | 92 | - | - |

## Notes

- server counters at the last successful scrape (cumulative for this process): 1 world-loop stall(s) totalling 51 ms; slowest iteration 51 ms; longest between-iteration gap 92 ms

## Server-side metrics (`/metrics` scrape, OBI-177)

```
# TYPE loom_world_loop_stall_ms_total counter
loom_world_loop_stall_ms_total 51

# TYPE loom_world_loop_iterations_total counter
loom_world_loop_iterations_total 13585

# TYPE loom_world_loop_stalls_total counter
loom_world_loop_stalls_total{kind="input"} 1

# TYPE loom_world_loop_ticks_total counter
loom_world_loop_ticks_total 903

# TYPE loom_world_loop_gap_ms_max gauge
loom_world_loop_gap_ms_max 92

# TYPE loom_world_loop_last_stall_tick gauge
loom_world_loop_last_stall_tick 402

# TYPE loom_world_loop_last_stall_duration_ms gauge
loom_world_loop_last_stall_duration_ms 51

# TYPE loom_world_loop_last_stall_unix_ms gauge
loom_world_loop_last_stall_unix_ms 1791543116260

# TYPE loom_world_loop_duration_ms_max gauge
loom_world_loop_duration_ms_max 51


```
