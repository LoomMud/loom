#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <cyclonedx-sbom.json>" >&2
  exit 2
fi

sbom_path=$1
if [[ ! -f "$sbom_path" ]]; then
  echo "sbom not found: $sbom_path" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 2
fi

missing_count=$(jq '[.components[]? | select(((.licenses // []) | length) == 0)] | length' "$sbom_path")

if [[ "$missing_count" -gt 0 ]]; then
  echo "found ${missing_count} SBOM components with no declared license:" >&2
  jq -r '.components[]? | select(((.licenses // []) | length) == 0) | "- \(.name)@\(.version // "unknown")"' "$sbom_path" | head -n 50 >&2
  exit 1
fi

echo "sbom license check passed"
