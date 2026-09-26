#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
#
# Fails if any non-merge commit in RANGE lacks a Signed-off-by trailer that
# matches its author (spec §4.4). Usage: scripts/check-dco.sh [RANGE]
# Default RANGE: all commits reachable from HEAD.
set -euo pipefail
range="${1:-HEAD}"
fail=0
while read -r sha; do
  author="$(git log -1 --format='%an <%ae>' "$sha")"
  if ! git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$sha" | grep -qF "$author"; then
    echo "DCO: commit $sha by $author has no matching Signed-off-by" >&2
    fail=1
  fi
done < <(git rev-list --no-merges "$range")
[ "$fail" -eq 0 ] && echo "DCO: all commits signed off"
exit "$fail"
