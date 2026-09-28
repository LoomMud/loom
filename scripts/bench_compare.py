#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
#
# Compare vm_bench round logs saved by scripts/bench-gate.sh (OBI-25 / OBI-118).
#
# Usage: bench_compare.py LOGS_DIR THRESHOLD
#
# LOGS_DIR holds base<N>.log / head<N>.log, each the Markdown table printed
# by `cargo run --release -p loom-vm --example vm_bench` (one row per
# workload: `| workload | result | median | p95 | min |`). For every
# workload that appears on both sides, take the minimum over rounds of the
# median column and report head/base. Exits 1 if any ratio exceeds
# 1 + THRESHOLD, 0 otherwise. Stdlib only; prints a Markdown table (also
# appended to $GITHUB_STEP_SUMMARY).

import os
import re
import sys
from pathlib import Path

ROW = re.compile(
    r"^\|\s*(?P<workload>\S+)\s*\|\s*(?P<result>\S+)\s*\|\s*"
    r"(?P<median>[\d.]+)\s*(?P<unit>ms|µs|s)\s*\|"
)
FILE = re.compile(r"^(base|head)(\d+)\.log$")

UNIT_TO_MS = {"s": 1e3, "ms": 1.0, "µs": 1e-3}


def parse_table(path: Path) -> dict:
    """{workload: median_ms}"""
    out: dict = {}
    for line in path.read_text().splitlines():
        m = ROW.match(line)
        if not m or m.group("workload") in ("workload", "---"):
            continue
        ms = float(m.group("median")) * UNIT_TO_MS[m.group("unit")]
        out[m.group("workload")] = ms
    return out


def collect(logs_dir: Path) -> dict:
    """{workload: {"base": [ms...], "head": [ms...]}}"""
    out: dict = {}
    for log in sorted(logs_dir.glob("*.log")):
        m = FILE.match(log.name)
        if not m:
            continue
        side = m.group(1)
        for workload, ms in parse_table(log).items():
            out.setdefault(workload, {"base": [], "head": []})[side].append(ms)
    return out


def fmt(ms: float) -> str:
    if ms >= 1e3:
        return f"{ms / 1e3:.3f} s"
    if ms >= 1.0:
        return f"{ms:.3f} ms"
    return f"{ms * 1e3:.1f} µs"


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: bench_compare.py LOGS_DIR THRESHOLD", file=sys.stderr)
        return 2
    logs_dir, threshold = Path(sys.argv[1]), float(sys.argv[2])
    data = collect(logs_dir)
    if not data:
        print("bench-gate: no saved rounds found", file=sys.stderr)
        return 2
    lines = [
        "| workload | base (min median) | head (min median) | head/base | rounds | verdict |",
        "|---|---:|---:|---:|---:|---|",
    ]
    failed = []
    for workload in sorted(data):
        base, head = data[workload]["base"], data[workload]["head"]
        if not base or not head:
            lines.append(
                f"| `{workload}` | | | | | only in {'base' if base else 'head'} (skipped) |"
            )
            continue
        b, h = min(base), min(head)
        ratio = h / b
        verdict = "ok"
        if ratio > 1 + threshold:
            verdict = f"**REGRESSION** (> +{threshold:.0%})"
            failed.append(workload)
        elif ratio < 1 - threshold:
            verdict = "faster"
        lines.append(
            f"| `{workload}` | {fmt(b)} | {fmt(h)} | {ratio:.3f} | {min(len(base), len(head))} | {verdict} |"
        )
    report = "\n".join(lines)
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write("### VM bench gate\n\n" + report + "\n")
    if failed:
        print(f"\nbench-gate: {len(failed)} regression(s): {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
