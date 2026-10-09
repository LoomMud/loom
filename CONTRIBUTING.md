# Contributing to Loom

## Status and licence

This repository is public and licensed under the **GNU Affero General Public License v3.0 only**
(`AGPL-3.0-only`). The full text is in [`LICENSE`](LICENSE) (REUSE copy: `LICENSES/AGPL-3.0-only.txt`).
Every file carries an SPDX header naming `AGPL-3.0-only` as its licence identifier.

**External pull requests are not accepted for now.** Please do not open pull requests from forks; they
will be closed unmerged. Issues, bug reports and feedback are welcome. We will revisit this (most likely
accepting contributions under AGPL-3.0-only with DCO sign-off) once the contribution governance is settled.

## Rules

Applied from the first commit (spec v2 §4.4):

- **DCO sign-off on every commit.** Use `git commit -s` (or `git config format.signOff true`).
  The trailer must match the commit author. CI (`scripts/check-dco.sh`) enforces it.
- **Dependencies must be AGPL-3.0-compatible and OSI-approved**, per the allow-list in `deny.toml`.
  `cargo deny check licenses` gates CI.
  Adding a licence to the allow-list requires CTO review.
- **SPDX headers** on every source file:
  `SPDX-FileCopyrightText: 2026 Oberfield` and
  an `SPDX-License-Identifier` tag with value `AGPL-3.0-only`. `reuse lint` gates CI.
- **No secrets, credentials or unlicensed third-party assets.** `gitleaks` gates CI.
- **`unsafe` is denied workspace-wide.** Any exception is local to `loom-vm`, justified in a comment, and CTO-reviewed.
- **A plain `cargo build` must never connect to a database.** `.cargo/config.toml`
  pins `SQLX_OFFLINE = { value = "true", force = false }` (OBI-321), so sqlx's
  compile-time `query!` macros compile from the committed `.sqlx/` cache. The live-DB
  build stays an explicit opt-in (`force = false` means your shell's value wins), and
  refreshing the cache is `scripts/sqlx-prepare.sh` -- which boots its own disposable
  Postgres. If a build says `SQLX_OFFLINE=true but there is no cached data for this
  query`, run that script; see `docs/persistence.md#sqlx-offline-metadata`.
- **Never point a local Postgres-backed test or `loom serve` run at the
  ambient `DATABASE_URL`** (OBI-151). Agent shells export `DATABASE_URL` for
  Paperclip's own control-plane Postgres (OBI-150); loom/warp's DB-backed
  integration tests read `LOOM_TEST_DATABASE_URL`/`LOOM_TEST_DB_MIGRATE_URL`
  instead (never `DATABASE_URL`/`LOOM_DB_MIGRATE_URL`), and `unset
  DATABASE_URL` before running anything DB-backed locally. Use
  `scripts/with-disposable-postgres.sh -- <command>` to get a throwaway,
  per-run Postgres instance instead -- see `docs/persistence.md#local-db-testing-obi-151`.
- Run `scripts/ci-local.sh` before pushing; it runs the same gates as CI.
- **No synthetic CPU/load or stress testing on the shared host without board consent**
  (OBI-306/OBI-307). Do not start busy-loop spinners (`while :; do :; done`), parallel builds whose
  only purpose is to add load, or stress loops unless the issue has a board-accepted confirmation
  for that test. Ordinary builds and tests are fine. So are sequential repeat runs with no added load.
  To prove a flake fix, use a deterministic reproduction plus a regression test, or N *sequential*
  runs with no added load. If you really need contention, say so in the plan and get board consent
  before you run it.
- Commits made by Paperclip agents end with `Co-Authored-By: Paperclip <noreply@paperclip.ing>`.

## GitHub flow

- Open PRs against `main` on `https://github.com/LoomMud/loom`.
- Keep the interim shared bare repo read-only as a migration mirror.
- For CLI operations, use the short-lived command env pattern without persisting credentials:
  `GH_TOKEN="$GITHUB_TOKEN" gh <command>`

### Getting merged: the required checks and the load lane

`main` requires five checks -- `rust`, `deny`, `dco`, `hygiene`,
`loadtest-e1-1` -- and branch protection runs with `strict: true` ("require
branches to be up to date before merging"), so a PR merges only when those are
green on a commit that already contains the current `main`.

`loadtest-e1-1` is the 150-player latency gate. It runs alone in one FIFO
`loom-ci-load-lane` shared by every open PR, so it spends most of its time
*waiting* rather than measuring (~90 s of measurement, tens of minutes of
queue). And because `strict: true` invalidates the gate every time `main`
moves, a rebase restarts that wait: PR #124 was rebased four times in five hours
and was still `BEHIND` when its gate finally went green (OBI-325). Two rules
follow:

- **Do not rebase or force-push while `loadtest-e1-1` is queued or running.**
  It discards the place in line and takes a new one at the back. Rebase once,
  immediately before you merge, and let the gate run on that commit.
  (`scripts/check-ci-load-lane.py` keeps a stale SHA from *holding* a lane place
  for somebody else; that protects the lane, it does not speed up your merge.)
- **A diff that cannot change what the gate measures does not wait for it at
  all.** A cheap `classify` job decides, from `scripts/load-lane-classify.py`,
  whether your changed paths can reach the binaries E1.1 builds or the bench
  workloads `bench` measures in the same lane. Docs, tests, CI config, scripts,
  `ops/`, the web client and committed reports get green in seconds and never
  enter the group. Anything under `crates/*/src/**`, any `Cargo.toml` or
  `Cargo.lock`, `rust-toolchain.toml`, `.cargo/`, `build.rs`, `mudlib/`, the
  `tests/fixtures/**` mirror of the mix the gate replays, or a bench
  workload/harness file takes the lane and is measured. Unknown paths take the
  lane too: the list is an *irrelevance allow-list*, and being unsure costs a
  lane run rather than hiding a regression. A rename is read as **both** its old
  and its new path (`git diff --name-only --no-renames`), because git's default
  reports a detected rename as its destination only -- so a file moving *out* of
  `mudlib/` or the mix mirror under `tests/fixtures/**` into an allow-listed path
  would otherwise look like a docs change. `load-lane-classify.py --self-test`
  builds a throwaway repo and asserts both halves, including the counterfactual
  that `-M` alone would have skipped it.
  Two over-measures are deliberate: a `Cargo.lock` delta counts even when it only
  touches dev-dependencies a release build never links (the alternative is a rule
  that reads the resolver's output and can fail open), and `tests/fixtures/**`
  counts as the *mirror* of the mix E1.1 replays from `warp/loadbot/mix.tsv` --
  not because it is compiled in (`src/mix.rs`'s `include_str!` is `#[cfg(test)]`
  only, corrected in review).
- **CI does not get to pick its own compiler.** `.github/**` counts as
  irrelevant, so `scripts/check-ci-load-lane.py` (rule 9, run by `hygiene`) also
  requires every `toolchain:` the workflow installs to equal the channel in
  `rust-toolchain.toml`. Bump the compiler there, where the change is measured;
  a bump in `ci.yml` alone fails a required check.

So `loadtest-e1-1` can be green in two different ways, and the job says which
one you got in its step summary: **measured** (p99 against the 50 ms budget) or
**not applicable** (nothing was built, no players were connected, and the rule
that decided it is named). The check is never made optional, and it is never
`if:`-ed away by anything except `!cancelled()` -- a detail that matters, because
GitHub counts a *skipped* required check as **passing**. `needs: classify` alone
would therefore be a fail-open: a classifier that dies (lost runner, failed
checkout, timeout) would skip the gate and hand the PR a green that never
measured. `if: ${{ !cancelled() }}` is the closing half, rule 4 requires the two
lines as a pair, and rule 4 rejects `always()` too -- it would run 150 players on
a host GitHub is already tearing down.

If you think a diff was wrongly called irrelevant -- a change that should have
been measured -- say so on the PR and fix the *rule* in
`scripts/load-lane-classify.py` (its `--self-test` table is the test), not the
threshold, the population, or the check itself: `hygiene` fails those.

Two things this does **not** change:

- **A skip is not a cure for a contended measurement.** The lane has never
  shielded a gate from its own run's `rust` and `fuzz-smoke*` jobs, and the
  board's root cause for the PR #124 miss was exactly that. If a measured gate
  misses while `rust` is still running in the same run, that is OBI-311 (a quiet
  runner via `CI_LOAD_RUNS_ON`), not a driver regression -- do not chase it as
  one, and do not re-run it into a quiet window by hand.
- **A `${{ ... }}` in a `run:` script is evaluated before the shell sees it --
  including in shell comments.** `cancelled()`, `always()`, `failure()`, `success()`
  and `no_status()` exist only in `if:` conditions, so one of them inside a `run:`
  block is not a bad step, it is a workflow file GitHub cannot compile: no job runs,
  and on a `pull_request` not even a check run appears. The symptom is a `push`
  placeholder run named after the file path with 0 jobs and no logs, plus
  `gh pr checks` reporting "no checks reported" -- which looks like Actions being
  stuck and is not (PR #144 lost its suite that way for a whole evening, 2026-10-09).
  Rule 10 of `scripts/check-ci-load-lane.py` fails it in `hygiene`; write the
  expression bare in a script (`if: !cancelled()`) and keep `${{ }}` for YAML
  comments and real `if:` conditions. `actionlint` finds this class too.
- **`ci.yml` and `scripts/check-ci-load-lane.py` are shared real estate.** OBI-311
  (PR #131) and OBI-325 (PR #144) both edit them plus `results/README.md`, so
  expect a textual rebase for whoever lands second; the shapes do not conflict
  (a configurable `runs-on:` versus a new job and rules 7-8).
