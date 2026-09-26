# Contributing to Loom

## Status and licence

This repository is **public but not open source (yet)**. The project licence is still being decided, so
every file is `LicenseRef-Oberfield-Proprietary` (all rights reserved). **External contributions are not
accepted** until a licence is chosen; please do not open pull requests from forks. Issues and feedback
are welcome.

## Rules

Applied from the first commit (spec v2 §4.4):

- **DCO sign-off on every commit.** Use `git commit -s` (or `git config format.signOff true`).
  The trailer must match the commit author. CI (`scripts/check-dco.sh`) enforces it.
- **Dependencies are OSI-licensed only**, per the allow-list in `deny.toml`. `cargo deny` gates CI.
  Adding a licence to the allow-list requires CTO review.
- **SPDX headers** on every source file:
  `SPDX-FileCopyrightText: 2026 Oberfield` and the proprietary license identifier
  `LicenseRef-Oberfield-Proprietary`. `reuse lint` gates CI.
- **No secrets, credentials or unlicensed third-party assets.** `gitleaks` gates CI.
- **`unsafe` is denied workspace-wide.** Any exception is local to `loom-vm`, justified in a comment, and CTO-reviewed.
- Run `scripts/ci-local.sh` before pushing; it runs the same gates as CI.
- Commits made by Paperclip agents end with `Co-Authored-By: Paperclip <noreply@paperclip.ing>`.

## GitHub flow

- Open PRs against `main` on `https://github.com/LoomMud/loom`.
- Keep the interim shared bare repo read-only as a migration mirror.
- For CLI operations, use the short-lived command env pattern without persisting credentials:
  `GH_TOKEN="$GITHUB_TOKEN" gh <command>`
