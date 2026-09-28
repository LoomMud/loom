#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
#
# VM benchmark regression gate (OBI-25 / OBI-118). Method:
# crates/loom-vm/benches/BASELINE.md.
#
# There is no criterion bench harness in this tree; the suite is the plain
# `Instant`-timed `cargo run --release -p loom-vm --example vm_bench` binary
# (OBI-72), which prints one Markdown table row per workload with a median,
# p95 and min duration. This script builds that example for a base commit
# (in a git worktree) and for the working tree ("head"), runs both several
# times interleaved on the same runner, and hands the per-round tables to
# scripts/bench_compare.py to take the min-of-medians per workload and fail
# on a >THRESHOLD regression.
#
# Usage: scripts/bench-gate.sh [BASE_REF]
#   BASE_REF  commit to compare against (default: merge-base of HEAD and origin/main).
# The working tree (including uncommitted changes) is the "head" side.
#
# Env:
#   BENCH_THRESHOLD  allowed slowdown as a fraction (default 0.15 = 15%)
#   BENCH_ROUNDS     A/B rounds per pass (default 3); a failing pass gets one
#                    confirmation pass of the same size before the gate fails
#   BENCH_ITERS      iterations passed to vm_bench each round (default 15)
#   BENCH_WORK       scratch dir (default target/bench-gate)
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"

threshold="${BENCH_THRESHOLD:-0.15}"
rounds="${BENCH_ROUNDS:-3}"
iters="${BENCH_ITERS:-15}"
work="${BENCH_WORK:-$root/target/bench-gate}"
base_ref="${1:-$(git merge-base HEAD origin/main)}"
base_sha="$(git rev-parse --verify "$base_ref^{commit}")"

echo "bench-gate: base $base_sha vs working tree, threshold ${threshold}, ${rounds} rounds, ${iters} iters/round"

rm -rf "$work/logs"
mkdir -p "$work/logs"
base_dir="$work/base"
if [ -e "$base_dir" ]; then
  git worktree remove --force "$base_dir" 2>/dev/null || rm -rf "$base_dir"
fi
git worktree prune
git worktree add --detach --quiet "$base_dir" "$base_sha"
trap 'git -C "$root" worktree remove --force "$base_dir" >/dev/null 2>&1 || true' EXIT

if [ ! -f "$base_dir/crates/loom-vm/examples/vm_bench.rs" ]; then
  echo "bench-gate: base $base_sha has no vm_bench example; nothing to compare (pass)"
  exit 0
fi

base_target="$work/target-base"
head_target="$root/target"

build() { # dir target
  (cd "$1" && CARGO_TARGET_DIR="$2" cargo build --release --quiet -p loom-vm --example vm_bench)
}
run() { # dir target save-name
  local log="$work/logs/$3.log"
  if ! (cd "$1" && "$2/release/examples/vm_bench" "$iters") >"$log" 2>&1; then
    cat "$log" >&2
    echo "bench-gate: bench run $3 failed" >&2
    exit 1
  fi
}

build "$base_dir" "$base_target"
build "$root" "$head_target"

# Interleave A/B/B/A so slow drift on the runner hits both sides equally.
pass() { # first-round last-round
  for ((r = $1; r <= $2; r++)); do
    if ((r % 2)); then
      run "$base_dir" "$base_target" "base$r"
      run "$root" "$head_target" "head$r"
    else
      run "$root" "$head_target" "head$r"
      run "$base_dir" "$base_target" "base$r"
    fi
  done
}

pass 1 "$rounds"
if python3 scripts/bench_compare.py "$work/logs" "$threshold"; then
  echo "bench-gate: pass"
  exit 0
fi
echo "bench-gate: regression on first pass; running a confirmation pass" >&2
pass $((rounds + 1)) $((rounds * 2))
if python3 scripts/bench_compare.py "$work/logs" "$threshold"; then
  echo "bench-gate: pass (first-pass regression was noise)"
  exit 0
fi
echo "bench-gate: FAIL" >&2
exit 1
