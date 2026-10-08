#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
#
# Run the same gates as .github/workflows/ci.yml locally (until GitHub exists).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check licenses bans sources advisories
scripts/check-dco.sh
# The web client's own gate, in CI's order: install from the lockfile
# (`npm ci`, so a missing devDependency fails the same way here as in CI --
# `npm install` would let a stale lockfile pass), vendor + type-check, lint
# the HTML-sink and static-CSP audits, run the unit tests, then the licence
# and vulnerability gates (OBI-180 M-IDE-1/2/3).
if [ -d web-client ]; then
  (cd web-client && npm ci --include=dev && npm run build && npm run lint \
    && npm test && npm run check-licenses && npm audit --audit-level=high)
  node --test scripts/check-static-csp.test.mjs
fi
echo "ci-local: all gates green"
