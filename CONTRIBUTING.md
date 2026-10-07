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
