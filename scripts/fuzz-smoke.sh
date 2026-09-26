#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary
#
# CI smoke run of a `cargo fuzz` target: seeds the corpus from golden/seed
# files and fuzzes for FUZZ_SECONDS (default 45, hard cap 60).
# FUZZ_SANITIZER defaults to `none` (see below); set FUZZ_SANITIZER=address
# for a sanitized run.  Needs a nightly toolchain and cargo-fuzz:
#   rustup toolchain install nightly --profile minimal
#   cargo install cargo-fuzz --locked
#
# Usage: scripts/fuzz-smoke.sh [parse|bytecode]  (default: parse)
set -euo pipefail
target_name="${1:-parse}"
root="$(cd "$(dirname "$0")/.." && pwd)"
secs="${FUZZ_SECONDS:-45}"
if (( secs > 60 )); then secs=60; fi
san="${FUZZ_SANITIZER:-none}"

case "$target_name" in
  parse)
    # loom-syntax has no `unsafe`, so ASAN adds little beyond cost.
    cd "$root/crates/loom-syntax"
    corpus=fuzz/corpus/parse
    mkdir -p "$corpus"
    cp tests/golden/*.wf "$corpus"/
    cargo +nightly fuzz build -s "$san" parse
    cargo +nightly fuzz run -s "$san" parse "$corpus" -- \
      -max_total_time="$secs" -max_len=4096 -timeout=5 -rss_limit_mb=2048 \
      -dict=fuzz/weft.dict
    ;;
  bytecode)
    cd "$root/crates/loom-compiler"
    corpus=fuzz/corpus/decode_verify
    mkdir -p "$corpus"
    cargo +nightly fuzz build -s "$san" decode_verify
    cargo +nightly fuzz run -s "$san" decode_verify "$corpus" -- \
      -max_total_time="$secs" -max_len=8192 -timeout=5 -rss_limit_mb=2048
    ;;
  *)
    echo "unknown fuzz target: $target_name" >&2
    exit 1
    ;;
esac
echo "fuzz-smoke: $target_name target clean for ${secs}s"
