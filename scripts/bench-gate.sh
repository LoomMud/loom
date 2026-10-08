#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
#
# VM benchmark regression gate (OBI-25 / OBI-118 / OBI-312). Method:
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
# ## Why there is now a control arm (OBI-312)
#
# `bench` failed on PR #131 (run 37689038963) with `priv_control` at ratio
# 1.177 -- on a diff with no `.rs` and no `Cargo.toml`, so both arms compiled
# the *same Rust source*. The first hypothesis was code layout: base is built
# from a git worktree at `$work/base` into `$work/target-base` while head is
# built from `$root` into `$root/target`, so embedded `file!()`/debug strings
# differ in length and could shift the hot code. That hypothesis is now
# **measured and rejected**: the two `vm_bench` binaries from exactly that
# pair of paths are byte-identical (same sha256, different inodes), because
# cargo compiles path dependencies with paths relative to the workspace root.
# So the harness has no build-side asymmetry to blame, and whatever made head
# read 17.7% slower is a *runtime* asymmetry of the runner -- which the old
# two-arm gate could not see, because it had no way to check that it could
# measure 1.00.
#
# The gate therefore measures its own null distribution instead of assuming
# one. Three arms run per round:
#
#   base  the base commit, built in a worktree           (the `A` of `A/B`)
#   head  the working tree, built in the workspace       (the `B`)
#   ctrl  a *byte-identical copy of the head binary*, at its own path and
#         inode -- so `ctrl` vs `head` is the same bytes measured twice and
#         `head/ctrl` is the harness's own error bar.
#
# scripts/bench_compare.py requires `head/ctrl` to stay within the *same*
# tolerance as `head/base`. If it does not, the run is reported as
# `INVALID (harness)` and exits 3 -- loud, non-zero, and labelled as a
# measurement failure rather than a code regression. That is deliberate:
# "the harness cannot demonstrate it measures 1.00" must never be laundered
# into a pass, and must never be reported as the PR's fault. When `base` and
# `head` hash the same, there is no code difference to time at all, so a
# `head/base` miss is *definitionally* a harness artifact and is also
# reported as `INVALID (harness)`.
#
# Remaining per-arm asymmetries are removed rather than merely measured: the
# three binaries are staged into one directory with equal-length paths and
# always run from the same cwd, so argv[0] length and cwd cannot differ
# between arms, and the run order is rotated every round so each arm gets
# each slot once per three rounds.
#
# Usage: scripts/bench-gate.sh [BASE_REF]
#   BASE_REF  commit to compare against (default: merge-base of HEAD and origin/main).
# The working tree (including uncommitted changes) is the "head" side.
#
# Env:
#   BENCH_THRESHOLD  allowed slowdown as a fraction (default 0.15 = 15%)
#                    applied to BOTH head/base and the head/ctrl control
#   BENCH_ROUNDS     A/B rounds per pass (default 3); a failing pass gets one
#                    confirmation pass of the same size before the gate fails
#   BENCH_ITERS      iterations passed to vm_bench each round (default 15)
#   BENCH_WORK       scratch dir (default target/bench-gate)
# Exit: 0 pass, 1 regression, 2 usage/setup error, 3 harness invalid.
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"

threshold="${BENCH_THRESHOLD:-0.15}"
rounds="${BENCH_ROUNDS:-3}"
iters="${BENCH_ITERS:-15}"
work="${BENCH_WORK:-$root/target/bench-gate}"
base_ref="${1:-$(git merge-base HEAD origin/main)}"
base_sha="$(git rev-parse --verify "$base_ref^{commit}")"
head_sha="$(git rev-parse --verify 'HEAD^{commit}')"

echo "bench-gate: base $base_sha vs working tree, threshold ${threshold}, ${rounds} rounds, ${iters} iters/round"

rm -rf "$work/logs" "$work/bin"
mkdir -p "$work/logs" "$work/bin"
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
build "$base_dir" "$base_target"
build "$root" "$head_target"

# Stage the three measurement arms. Equal-length paths (`a1`/`a2`/`a3`) in one
# directory, one file per arm, so the only intended difference between arms is
# the bytes of the binary itself.
bin_dir="$work/bin"
mkdir -p "$bin_dir/a1" "$bin_dir/a2" "$bin_dir/a3"
cp "$base_target/release/examples/vm_bench" "$bin_dir/a1/vm_bench"
cp "$head_target/release/examples/vm_bench" "$bin_dir/a2/vm_bench"
cp "$head_target/release/examples/vm_bench" "$bin_dir/a3/vm_bench"
chmod +x "$bin_dir"/a*/vm_bench

sha_of() { sha256sum "$1" | cut -d' ' -f1; }
sha_base="$(sha_of "$bin_dir/a1/vm_bench")"
sha_head="$(sha_of "$bin_dir/a2/vm_bench")"
sha_ctrl="$(sha_of "$bin_dir/a3/vm_bench")"

# Everything the next incident post-mortem will need, next to the round logs.
{
  echo "base_sha=$base_sha"
  echo "head_sha=$head_sha"
  echo "sha_base=$sha_base"
  echo "sha_head=$sha_head"
  echo "sha_ctrl=$sha_ctrl"
  echo "identical_binaries=$([ "$sha_base" = "$sha_head" ] && echo true || echo false)"
  echo "threshold=$threshold"
  echo "rounds=$rounds"
  echo "iters=$iters"
  echo "uname=$(uname -srm)"
  echo "nproc=$(nproc)"
  echo "loadavg=$(cut -d' ' -f1-3 /proc/loadavg)"
  echo "cpu=$(sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -1)"
  echo "governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
  echo "cgroup_cpu_max=$(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo unknown)"
  echo "date=$(date -u +%FT%TZ)"
} > "$work/logs/meta.env"

if [ "$sha_base" = "$sha_head" ]; then
  echo "bench-gate: base and head vm_bench are byte-identical (sha256 $sha_base);"
  echo "bench-gate:   this diff changes no compiled code, so any ratio != 1.00 is harness noise."
fi

run() { # arm-round save-name  (arm = base|head|ctrl)
  local arm="$1" r="$2" slot log
  case "$arm" in
    base) slot=a1 ;;
    head) slot=a2 ;;
    ctrl) slot=a3 ;;
    *) echo "bench-gate: unknown arm $arm" >&2; exit 2 ;;
  esac
  log="$work/logs/${arm}${r}.log"
  # A header line per round (not a table row, so the comparator ignores it)
  # so a slow round can be correlated with what the host was doing -- the
  # missing data in the OBI-312 post-mortem.
  echo "# arm=$arm round=$r slot=$slot iters=$iters loadavg=$(cut -d' ' -f1-3 /proc/loadavg | tr ' ' '/') ts=$(date -u +%FT%TZ)" > "$log"
  # Same cwd for every arm: the working directory is not part of the measurement.
  if ! (cd "$bin_dir" && "./$slot/vm_bench" "$iters") >>"$log" 2>&1; then
    cat "$log" >&2
    echo "bench-gate: bench run $arm$r failed" >&2
    # A `base` that never printed a table is a setup error: there is nothing to
    # compare against, and calling that a regression would blame the PR for the
    # baseline build (OBI-312 review, N1). `head` or `ctrl` failing stays 1 --
    # the change under test broke its own benchmark.
    if [ "$arm" = base ]; then exit 2; fi
    exit 1
  fi
}

# Rotate the order, not just the pair. With three arms, cyclic rotation covers 3
# of the 6 orders, so each arm holds each *slot position* exactly once per three
# rounds: no arm can systematically get the warm slot. What it does *not* do is
# equalise every predecessor (head always follows ctrl or runs first), so
# "what ran immediately before" -- frequency ramp, page-cache state, a
# neighbour's burst -- is controlled for by the byte-identical `ctrl` arm, not
# by the schedule.
pass() { # first-round last-round
  local r
  for ((r = $1; r <= $2; r++)); do
    case $((r % 3)) in
      0) run head "$r"; run ctrl "$r"; run base "$r" ;;
      1) run ctrl "$r"; run base "$r"; run head "$r" ;;
      *) run base "$r"; run head "$r"; run ctrl "$r" ;;
    esac
  done
}

# `set -e` would abort on a non-zero comparison, so capture the exit status
# explicitly; 1 = regression, 3 = the harness failed its own control arm.
compare() { python3 scripts/bench_compare.py "$work/logs" "$threshold"; }

pass 1 "$rounds"
rc=0; compare || rc=$?
if [ $rc -eq 0 ]; then
  echo "bench-gate: pass"
  exit 0
elif [ $rc -ne 1 ] && [ $rc -ne 3 ]; then
  echo "bench-gate: setup/comparison error (exit $rc)" >&2
  exit 2
fi
if [ $rc -eq 3 ]; then
  echo "bench-gate: control arm missed on first pass; running a confirmation pass" >&2
else
  echo "bench-gate: regression on first pass; running a confirmation pass" >&2
fi

pass $((rounds + 1)) $((rounds * 2))
rc=0; compare || rc=$?
if [ $rc -eq 0 ]; then
  echo "bench-gate: pass (first-pass miss was noise)"
  exit 0
fi
case $rc in
  1) echo "bench-gate: FAIL (regression)" >&2 ;;
  3) echo "bench-gate: FAIL (INVALID: the harness could not measure 1.00 against its own byte-identical control arm, so no head/base number in this run -- including any that looked like a regression -- can be trusted). No workload was classified REGRESSION in the confirmation pass. See the 'ctrl/head' column and $work/logs/meta.env." >&2 ;;
  *) echo "bench-gate: setup/comparison error (exit $rc)" >&2; exit 2 ;;
esac
exit $rc
