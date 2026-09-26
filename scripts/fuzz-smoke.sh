#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary
#
# CI smoke run of the Weft parser fuzz target: seeds the corpus from the
# golden files and fuzzes for FUZZ_SECONDS (default 45, hard cap 60).
# FUZZ_SANITIZER defaults to `none`: loom-syntax has no `unsafe`, so ASAN adds
# little beyond cost; set FUZZ_SANITIZER=address for a sanitized run.
# Needs a nightly toolchain and cargo-fuzz:
#   rustup toolchain install nightly --profile minimal
#   cargo install cargo-fuzz --locked
set -euo pipefail
cd "$(dirname "$0")/../crates/loom-syntax"
secs="${FUZZ_SECONDS:-45}"
if (( secs > 60 )); then secs=60; fi
corpus=fuzz/corpus/parse
mkdir -p "$corpus"
cp tests/golden/*.wf "$corpus"/
san="${FUZZ_SANITIZER:-none}"
cargo +nightly fuzz build -s "$san" parse
cargo +nightly fuzz run -s "$san" parse "$corpus" -- \
  -max_total_time="$secs" -max_len=4096 -timeout=5 -rss_limit_mb=2048 \
  -dict=fuzz/weft.dict
echo "fuzz-smoke: parse target clean for ${secs}s"
