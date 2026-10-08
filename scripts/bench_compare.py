#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
"""
Compare `vm_bench` round logs saved by scripts/bench-gate.sh
(OBI-25 / OBI-118 / OBI-312).

Usage: bench_compare.py LOGS_DIR THRESHOLD
       bench_compare.py --self-test [LOGS_DIR_UNUSED]

LOGS_DIR holds `base<N>.log`, `head<N>.log` and `ctrl<N>.log`, each the
Markdown table printed by `cargo run --release -p loom-vm --example
vm_bench` (one row per workload: `| workload | result | median | p95 | min |`).
For every workload present on all three arms it takes the minimum over rounds
of the median column and reports:

  head/base   the number the gate exists for; > 1 + THRESHOLD is a regression
  ctrl/head   the **control**: `ctrl` is a byte-identical copy of the head
              binary (scripts/bench-gate.sh), so this arm pair measures the
              harness's own error bar. Deviating by more than the same
              THRESHOLD in either direction means the harness cannot
              demonstrate it measures 1.00, and no `head/base` number from
              that run means anything.

If LOGS_DIR/meta.env (written by bench-gate.sh) says the two builds produced
byte-identical `vm_bench` binaries, then a `head/base` miss is *definitionally*
not a code regression -- that diff changed no compiled code -- and it is
reported the same way as a control miss.

Exit codes:
  0  within tolerance
  1  regression: head/base exceeds 1 + THRESHOLD on a workload, control OK
  2  usage / no comparable data / a required arm is missing entirely
  3  INVALID harness: the control arm (or an identical-binary `head/base`
     pair) exceeded tolerance, or a workload both `base` and `head` timed has
     no control sample -- so the measurement, not the PR, is broken

Stdlib only. Prints a Markdown table and appends it to $GITHUB_STEP_SUMMARY
when that is set, plus a `bench-rounds.csv` of every raw round next to the
logs so a post-mortem can see per-round values instead of only the minima.
"""

import csv
import os
import re
import sys
import tempfile
from pathlib import Path

ROW = re.compile(
    r"^\|\s*(?P<workload>\S+)\s*\|\s*(?P<result>\S+)\s*\|\s*"
    r"(?P<median>[\d.]+)\s*(?P<unit>ms|µs|s)\s*\|"
)
FILE = re.compile(r"^(base|head|ctrl)(\d+)\.log$")

UNIT_TO_MS = {"s": 1e3, "ms": 1.0, "µs": 1e-3}

ARMS = ("base", "head", "ctrl")


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
    """{workload: {"base": {round: ms}, "head": {...}, "ctrl": {...}}}"""
    out: dict = {}
    for log in sorted(logs_dir.glob("*.log")):
        m = FILE.match(log.name)
        if not m:
            continue
        side, rnd = m.group(1), int(m.group(2))
        for workload, ms in parse_table(log).items():
            out.setdefault(workload, {a: {} for a in ARMS})[side][rnd] = ms
    return out


def read_meta(logs_dir: Path) -> dict:
    meta_path = logs_dir / "meta.env"
    if not meta_path.is_file():
        return {}
    meta = {}
    for line in meta_path.read_text().splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            meta[k.strip()] = v.strip()
    return meta


def fmt(ms: float) -> str:
    if ms >= 1e3:
        return f"{ms / 1e3:.3f} s"
    if ms >= 1.0:
        return f"{ms:.3f} ms"
    return f"{ms * 1e3:.1f} µs"


def ratio_str(x: float) -> str:
    return f"{x:.3f}"


def evaluate(logs_dir: Path, threshold: float) -> tuple:
    """Return (stdout_report: str, exit_code: int)."""
    data = collect(logs_dir)
    if not data:
        return "bench-gate: no saved rounds found", 2
    meta = read_meta(logs_dir)
    identical = meta.get("identical_binaries", "unknown")
    n_ctrl = sum(len(v["ctrl"]) for v in data.values())
    if n_ctrl == 0:
        return (
            "bench-gate: no `ctrl*` rounds found -- the gate must run the "
            "byte-identical control arm (scripts/bench-gate.sh), otherwise "
            "nothing can show the harness measures 1.00",
            2,
        )

    tol = 1.0 + threshold
    lines = [
        "| workload | base | head | head/base | ctrl | ctrl/head | rounds | verdict |",
        "|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    regressions, invalid, detail, ctrl_gaps = [], [], [], []
    worst_ctrl = 1.0
    for workload in sorted(data):
        base, head, ctrl = (data[workload][a] for a in ARMS)
        if not (base and head and ctrl):
            missing = [a for a, v in zip(ARMS, (base, head, ctrl)) if not v]
            if base and head and not ctrl:
                # `ctrl` is a copy of the head binary, so a workload both
                # other arms timed must appear there; if it does not, a
                # control round died and this gate cannot validate itself.
                ctrl_gaps.append(workload)
                missing = [f"{m} sample -- cannot trust this row" for m in missing]
            lines.append(
                f"| `{workload}` | | | | | | | missing {', '.join(missing)} (skipped) |"
            )
            continue
        b, h, c = min(base.values()), min(head.values()), min(ctrl.values())
        if b <= 0.0 or h <= 0.0 or c <= 0.0:
            # A zero/negative median means a broken print or a truncated table,
            # not a speedup: the row is evidence about nothing. Without this
            # guard a `0.000 ms` row raised ZeroDivisionError, which the shell
            # reported as a regression (OBI-312 review, N1).
            invalid.append(f"{workload} (non-positive median)")
            lines.append(
                f"| `{workload}` | {fmt(b)} | {fmt(h)} | | {fmt(c)} | | "
                f"{min(len(base), len(head), len(ctrl))} | **INVALID (non-positive median)** |"
            )
            continue
        ratio = h / b
        ctrl_ratio = c / h
        # A control deviation in either direction is equally fatal to trust:
        # the same bytes must measure the same time.
        ctrl_dev = max(ctrl_ratio, 1.0 / ctrl_ratio)
        worst_ctrl = max(worst_ctrl, ctrl_dev)
        control_missed = ctrl_dev > tol
        too_slow = ratio > tol
        too_fast = ratio < 1.0 - threshold
        if control_missed:
            verdict = "**INVALID (control)**"
            invalid.append(workload)
        elif too_slow and identical == "true":
            verdict = "**INVALID (identical binaries)**"
            invalid.append(workload)
        elif too_slow:
            verdict = f"**REGRESSION** (> +{threshold:.0%})"
            regressions.append(workload)
        elif too_fast and identical == "true":
            verdict = f"**INVALID (identical binaries, {ratio:.3f})**"
            invalid.append(workload)
        elif too_fast:
            verdict = "faster"
        else:
            verdict = "ok"
        lines.append(
            f"| `{workload}` | {fmt(b)} | {fmt(h)} | {ratio_str(ratio)} | "
            f"{fmt(c)} | {ratio_str(ctrl_ratio)} | "
            f"{min(len(base), len(head), len(ctrl))} | {verdict} |"
        )
        if verdict != "ok" or ratio > 1.05 or ctrl_dev > 1.05:
            detail.append((workload, base, head, ctrl))

    report = "\n".join(lines)
    if identical == "true":
        report += (
            "\n\n`base` and `head` `vm_bench` binaries are byte-identical "
            f"(sha256 `{meta.get('sha_base', '?')}`): this diff compiles to the "
            "same code, so a ratio off 1.00 is a measurement artifact, not a "
            "change in the VM."
        )
    report += (
        f"\n\nControl (byte-identical head copy) worst deviation across all "
        f"workloads: **{worst_ctrl:.3f}** (tolerance {tol:.3f})."
    )

    if detail:
        rounds = sorted({r for _, b, h, c in detail for d in (b, h, c) for r in d})
        det = [
            "",
            "<details><summary>Per-round medians for the workloads that moved"
            " (raw data; also in bench-rounds.csv)</summary>",
            "",
            "| workload | arm | " + " | ".join(f"r{r}" for r in rounds) + " |",
            "|---|---|" + "---:|" * len(rounds),
        ]
        for workload, base, head, ctrl in detail:
            for arm, values in zip(ARMS, (base, head, ctrl)):
                det.append(
                    f"| `{workload}` | {arm} | "
                    + " | ".join(
                        f"{values[r]:.3f}" if r in values else "" for r in rounds
                    )
                    + " |"
                )
        det.append("</details>")
        report += "\n" + "\n".join(det)

    # Precedence (OBI-312 review, B1): a `REGRESSION` row whose *own* control
    # sat inside the tolerance is evidence about this PR's code, and must not
    # be relabelled "harness invalid" because some other workload's control
    # arm misbehaved. That would re-run the original mistake in reverse: one
    # flaky short workload exonerating a genuine slowdown everywhere else.
    # So regressions win the exit code; untrustworthy rows are still listed.
    if regressions:
        report += (
            f"\n\nbench-gate: {len(regressions)} regression(s): "
            f"{', '.join(regressions)}"
        )
        if invalid or ctrl_gaps:
            report += (
                "\n\nThis run additionally could not trust "
                f"{len(invalid) + len(ctrl_gaps)} workload(s) "
                f"({', '.join(invalid + ctrl_gaps)}): their control arm moved or "
                "produced no sample. Those rows do not change the verdict -- the "
                "regressions above each carry a control that measured 1.00 -- but "
                "they mean the run is worth repeating once the host is quieter."
            )
        return report, 1
    if ctrl_gaps:
        report += (
            "\n\nbench-gate: INVALID harness -- no control sample for "
            f"{', '.join(ctrl_gaps)} while both `base` and `head` produced one: "
            "a `ctrl` round died or printed a truncated table, so this run "
            "cannot demonstrate that it measures 1.00. Re-run on a host that "
            "can complete all three arms."
        )
        return report, 3
    if invalid:
        report += (
            f"\n\nbench-gate: INVALID harness -- {len(invalid)} workload(s) could not "
            "be trusted: {names}. The control arm compares two byte-identical "
            "binaries, so a miss there is the runner, not this PR: give the gate a "
            "quiet host (OBI-311) and re-run. Do not raise BENCH_THRESHOLD."
        ).format(names=", ".join(invalid))
        return report, 3
    return report, 0


def write_csv(logs_dir: Path, data: dict) -> Path:
    out = logs_dir / "bench-rounds.csv"
    with out.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["workload", "arm", "round", "median_ms"])
        for workload in sorted(data):
            for arm in ARMS:
                for rnd, ms in sorted(data[workload][arm].items()):
                    w.writerow([workload, arm, rnd, ms])
    return out


def main(argv) -> int:
    if len(argv) >= 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) != 3:
        print("usage: bench_compare.py LOGS_DIR THRESHOLD", file=sys.stderr)
        return 2
    logs_dir, threshold = Path(argv[1]), float(argv[2])
    data = collect(logs_dir)
    if data:
        path = write_csv(logs_dir, data)
        print(f"bench-gate: wrote raw per-round medians to {path}", file=sys.stderr)
    report, code = evaluate(logs_dir, threshold)
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            heading = (
                "### VM bench gate: INVALID harness"
                if code == 3
                else "### VM bench gate"
            )
            f.write(heading + "\n\n" + report + "\n")
    return code


# ---------------------------------------------------------------------------
# Self-test: synthetic round logs, run in a temp dir. Covers each verdict the
# gate can produce, so the control logic is testable without a release build.
# ---------------------------------------------------------------------------


def _table(rows) -> str:
    """rows: [(workload, value, unit)] -> the Markdown vm_bench prints."""
    out = ["| workload | result | median | p95 | min |", "|---|---|---|---|---|"]
    for workload, value, unit in rows:
        out.append(
            f"| {workload} | ok | {value:.3f} {unit} | {value:.3f} {unit} | "
            f"{value:.3f} {unit} |"
        )
    return "\n".join(out) + "\n"


def _ms(rows):
    """Shorthand for a fixture row given in ms."""
    return [(w, v, "ms") for w, v in rows]


def _write(dirpath: Path, rounds: int, base, head, ctrl=None, meta=None) -> Path:
    for r in range(1, rounds + 1):
        (dirpath / f"base{r}.log").write_text(_table(base))
        (dirpath / f"head{r}.log").write_text(_table(head))
        if ctrl is not None:
            (dirpath / f"ctrl{r}.log").write_text(_table(ctrl))
    if meta is not None:
        (dirpath / "meta.env").write_text(meta)
    return dirpath


def self_test() -> int:
    wl = "priv_control"

    def arm(value):
        return _ms([(wl, value)])

    # The control arm is a copy of the *head* binary, so a healthy control
    # sits within tolerance of `head`, not of `base`.
    base_v, head_v = 2.0, 2.5  # head/base = 1.25 -> regression
    ctrl_ok = arm(head_v * 0.98)  # ctrl/head = 0.98 -> dev 1.020, within
    ctrl_bad = arm(head_v * 1.30)  # ctrl/head = 1.30 -> dev 1.300, invalid
    b, h_slow = arm(base_v), arm(head_v)
    cases = [
        ("within tolerance", dict(base=b, head=b, ctrl=b, meta="identical_binaries=true\n"), 0),
        ("real regression, control ok", dict(base=b, head=h_slow, ctrl=ctrl_ok, meta="identical_binaries=false\n"), 1),
        ("regression on identical binaries", dict(base=b, head=h_slow, ctrl=ctrl_ok, meta="identical_binaries=true\n"), 3),
        ("regression, control also missed", dict(base=b, head=h_slow, ctrl=ctrl_bad, meta="identical_binaries=false\n"), 3),
        ("no regression but control missed", dict(base=b, head=b, ctrl=arm(base_v * 1.30), meta="identical_binaries=false\n"), 3),
        ("control faster than head", dict(base=b, head=b, ctrl=arm(base_v * 0.70), meta="identical_binaries=false\n"), 3),
        # B1: a real regression with a healthy control must not be buried by a
        # different workload whose control arm moved.
        (
            "mixed: real regression + another workload's control invalid",
            dict(
                base=_ms([("other", 1.0), (wl, base_v)]),
                head=_ms([("other", 1.0), (wl, head_v)]),
                ctrl=_ms([("other", 1.0 * 1.30), (wl, head_v * 0.98)]),
                meta="identical_binaries=false\n",
            ),
            1,
        ),
        ("genuine speedup passes", dict(base=arm(head_v), head=b, ctrl=arm(base_v * 0.98), meta="identical_binaries=false\n"), 0),
    ]
    failures = 0
    with tempfile.TemporaryDirectory() as td:
        for i, (name, kwargs, want) in enumerate(cases):
            d = Path(td) / f"case{i}"
            d.mkdir()
            _write(d, rounds=3, **kwargs)
            report, got = evaluate(d, 0.15)
            if got != want:
                print(f"FAIL {name}: exit {got}, want {want}\n{report}", file=sys.stderr)
                failures += 1
            else:
                print(f"ok   {name}: exit {got}")

        # Unit handling: vm_bench prints µs for sub-ms workloads and s above
        # 1000 ms; a control comparison that mixed up the units would be
        # nonsense, so pin the conversion.
        # Same quantities, different units per arm: if a factor were wrong the
        # ratio would move, so this fixture can actually fail. (All three arms
        # carrying identical rows would cancel any constant factor.)
        d = Path(td) / "units"
        d.mkdir()
        _write(
            d,
            rounds=2,
            base=[("tiny", 512.0, "µs"), ("huge", 1.5, "s"), (wl, 2.0, "ms")],
            head=[("tiny", 0.512, "ms"), ("huge", 1500.0, "ms"), (wl, 2.0, "ms")],
            ctrl=[("tiny", 0.512, "ms"), ("huge", 1500.0, "ms"), (wl, 2.0, "ms")],
            meta="identical_binaries=true\n",
        )
        got = evaluate(d, 0.15)[1]
        if got != 0:
            print(f"FAIL unit conversion: exit {got}, want 0", file=sys.stderr)
            failures += 1
        else:
            print("ok   unit conversion: exit 0")

        # A workload both other arms timed must also appear in the control.
        d = Path(td) / "ctrlgap"
        d.mkdir()
        for r in (1, 2):
            (d / f"base{r}.log").write_text(_table(b + _ms([("other", 1.0)])))
            (d / f"head{r}.log").write_text(_table(h_slow + _ms([("other", 1.0)])))
            (d / f"ctrl{r}.log").write_text(_table(_ms([("other", 1.0)])))
        (d / "meta.env").write_text("identical_binaries=false\n")
        got = evaluate(d, 0.15)[1]
        if got != 3:
            print(f"FAIL workload missing from the control arm: exit {got}, want 3", file=sys.stderr)
            failures += 1
        else:
            print("ok   workload missing from the control arm is an error: exit 3")

        # A missing control arm must be an error, not a silent pass.
        d = Path(td) / "noctrl"
        d.mkdir()
        _write(d, rounds=2, base=b, head=h_slow, ctrl=None)
        got = evaluate(d, 0.15)[1]
        if got != 2:
            print(f"FAIL missing control arm: exit {got}, want 2", file=sys.stderr)
            failures += 1
        else:
            print("ok   missing control arm is an error: exit 2")

        # The table keeps the columns reviewers read, plus the raw rounds.
        d = Path(td) / "header"
        d.mkdir()
        _write(d, rounds=2, base=b, head=h_slow, ctrl=ctrl_ok, meta="identical_binaries=false\n")
        report, got = evaluate(d, 0.15)
        for token in ("head/base", "ctrl/head", "REGRESSION", "Per-round medians", "priv_control"):
            if token not in report:
                print(f"FAIL report missing {token!r}", file=sys.stderr)
                failures += 1
        case_bad = 0
        for token in ("head/base", "ctrl/head", "REGRESSION", "Per-round medians", "priv_control"):
            if token not in report:
                print(f"FAIL report missing {token!r}", file=sys.stderr)
                failures += 1
                case_bad += 1
        if got != 1:
            print(f"FAIL report case: exit {got}, want 1", file=sys.stderr)
            failures += 1
            case_bad += 1
        if case_bad == 0:
            print("ok   report carries the columns reviewers read, and exits 1")
        write_csv(d, collect(d))
        if not (d / "bench-rounds.csv").is_file():
            print("FAIL bench-rounds.csv not written", file=sys.stderr)
            failures += 1
        else:
            rows = (d / "bench-rounds.csv").read_text().splitlines()
            if rows[0] != "workload,arm,round,median_ms" or len(rows) != 1 + 2 * 3:
                print(f"FAIL bench-rounds.csv shape: {rows}", file=sys.stderr)
                failures += 1
            else:
                print("ok   raw per-round CSV written (2 rounds x 3 arms)")

        # B1: when a run carries both, the report has to name the regression
        # *and* the rows it could not trust, so nobody reads exit 1 as "the
        # whole run is garbage" or exit 3 as "nothing regressed".
        d = Path(td) / "mixedreport"
        d.mkdir()
        _write(
            d,
            rounds=2,
            base=_ms([("other", 1.0), (wl, base_v)]),
            head=_ms([("other", 1.0), (wl, head_v)]),
            ctrl=_ms([("other", 1.0 * 1.30), (wl, head_v * 0.98)]),
            meta="identical_binaries=false\n",
        )
        report, got = evaluate(d, 0.15)
        bad = 0
        for phrase in ("1 regression(s): priv_control", "could not trust 1 workload(s) (other)"):
            if phrase not in report:
                print(f"FAIL mixed report missing {phrase!r}\n{report}", file=sys.stderr)
                failures += 1
                bad += 1
        if got != 1:
            print(f"FAIL mixed report exit: {got}, want 1", file=sys.stderr)
            failures += 1
            bad += 1
        if bad == 0:
            print("ok   a regression outranks another workload's invalid control")

        # N1: a `0.000 ms` row used to raise ZeroDivisionError, which the shell
        # reported as a regression. A broken print is an untrustworthy row.
        d = Path(td) / "zeromedian"
        d.mkdir()
        _write(
            d,
            rounds=2,
            base=_ms([(wl, 0.0)]),
            head=_ms([(wl, 2.0)]),
            ctrl=_ms([(wl, 2.0)]),
            meta="identical_binaries=false\n",
        )
        got = evaluate(d, 0.15)[1]
        if got != 3:
            print(f"FAIL zero median: exit {got}, want 3", file=sys.stderr)
            failures += 1
        else:
            print("ok   a zero median is an invalid row, not a crash or a regression")
    if failures:
        print(f"bench_compare self-test: {failures} failure(s)", file=sys.stderr)
        return 1
    print("bench_compare self-test: all cases pass")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - a broken run is never a regression
        # Documented contract: setup/comparison errors are 2, only a verdict
        # about the measured code is 1.
        print(f"bench-gate: comparator error: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(2)
