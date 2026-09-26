# Contributing to Loom

## Status and licence

This repository is public and licensed under the **GNU Affero General Public License v3.0 only**
(`AGPL-3.0-only`). The full text is in [`LICENSE`](LICENSE) (REUSE copy: `LICENSES/AGPL-3.0-only.txt`).
Every file carries `SPDX-License-Identifier: AGPL-3.0-only`.

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
  `SPDX-License-Identifier: AGPL-3.0-only`. `reuse lint` gates CI.
- **No secrets, credentials or unlicensed third-party assets.** `gitleaks` gates CI.
- **`unsafe` is denied workspace-wide.** Any exception is local to `loom-vm`, justified in a comment, and CTO-reviewed.
- Run `scripts/ci-local.sh` before pushing; it runs the same gates as CI.
- Commits made by Paperclip agents end with `Co-Authored-By: Paperclip <noreply@paperclip.ing>`.

## GitHub flow

- Open PRs against `main` on `https://github.com/LoomMud/loom`.
- Keep the interim shared bare repo read-only as a migration mirror.
- For CLI operations, use the short-lived command env pattern without persisting credentials:
  `GH_TOKEN="$GITHUB_TOKEN" gh <command>`
