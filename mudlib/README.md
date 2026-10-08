<!-- SPDX-FileCopyrightText: 2026 Oberfield -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

This is a placeholder mount point for local Docker development.

Populate this directory with a Warp/Weft mudlib before running:

```bash
docker compose up --build
```

Two things to know before you drop a checkout in here:

* The world the CI load gate measures is **not** in this directory. It is
  `LoomMud/warp`, checked out into `warp/` inside the job at the commit pinned in
  [`/warp.ref`](../warp.ref) (OBI-326). Nothing that belongs to CI lives under
  `mudlib/`: this tree is only ever mounted read-only by `docker-compose.yml` and
  passed to `loom serve` by the local dev scripts.
* The engine only scans a mudlib root for `*.wf` files
  (`crates/loom-compiler/src/mudlib.rs`, `collect_wf`), so a populated `mudlib/`
  is a *second* copy of the world and CI will not use it -- if you clone `warp`
  in here for local play, say `mudlib/warp`, name it explicitly in your
  `loom serve --mudlib` argument and remember it is floating, not pinned.
