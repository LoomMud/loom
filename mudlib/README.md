<!-- SPDX-FileCopyrightText: 2026 Oberfield -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

This is a placeholder mount point for local Docker development.

Populate this directory with a Warp/Weft mudlib before running:

```bash
docker compose up --build
```

Two things to know before you drop a checkout in here:

* `warp.lock` is **not** mudlib content and not a Python/pip lockfile. It is the
  commit the CI load lane serves and prints in its reports (OBI-326), read by
  `loadtest-e1-1` / `loadtest-smoke` and enforced by rule 9 of
  `scripts/check-ci-load-lane.py`. Keep it tracked; edit it to change the world
  the gate measures, never to point it at a branch.
* The engine only scans a mudlib root for `*.wf` files
  (`crates/loom-compiler/src/mudlib.rs`, `collect_wf`), so this directory
  tolerating non-source files is not an accident -- but if you clone `warp` in
  here as `warp/`, that is a *second* copy of the world and CI will not use it:
  the lane checks its own pinned copy out into `warp`, not into `mudlib/`.
