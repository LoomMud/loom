# Contributing to Loom

Private repository while in development (spec v2 §4.4). Rules from the first commit:

- **DCO sign-off on every commit.** Use `git commit -s` (or `git config format.signOff true`).
  The trailer must match the commit author. CI (`scripts/check-dco.sh`) enforces it.
- **Dependencies are OSI-licensed only**, per the allow-list in `deny.toml`. `cargo deny` gates CI.
  Adding a licence to the allow-list requires CTO review.
- **SPDX headers** on every source file:
  `SPDX-FileCopyrightText: 2026 Oberfield` and
  `SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary`. `reuse lint` gates CI.
- **No secrets, credentials or unlicensed third-party assets.** `gitleaks` gates CI.
- **`unsafe` is denied workspace-wide.** Any exception is local to `loom-vm`, justified in a comment, and CTO-reviewed.
- Run `scripts/ci-local.sh` before pushing; it runs the same gates as CI.
- Commits made by Paperclip agents end with `Co-Authored-By: Paperclip <noreply@paperclip.ing>`.

## GitHub flow

- Open PRs against `main` on `https://github.com/LoomMud/loom`.
- Keep the interim shared bare repo read-only as a migration mirror.
- For CLI operations, use the short-lived command env pattern without persisting credentials:
  `GH_TOKEN="$GITHUB_TOKEN" gh <command>`
