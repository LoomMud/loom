#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
"""
Prove that a latency gate's *post-verdict* step tail cannot fail a passing
run (OBI-354).

GitHub runs a `run:` block as `bash --noprofile --norc -e` (and `shell: bash`
adds `-e -o pipefail`). A step that writes `set -uo pipefail` does **not** turn
that `-e` off -- it only adds options. So every command that runs *after* the
gate has already decided pass/fail must be `-e`-safe, or a command whose
non-zero exit is perfectly normal can abort the step and turn a PASS into red.

That is exactly what happened to `loadtest-e1-1` in run 37877217457: E1.1
measured p99 22.91 ms against a 50 ms SLA -- the report prints PASS -- and the
job still went red with `exit 1`, on this line of the tail:

    kinds=$(grep -oE 'kind="[a-z_]+"' /tmp/loom-metrics-final.txt | sed ... | tr ...)

`grep` exits 1 when it matches nothing, `pipefail` makes that sticky, and zero
matches is the *healthy* case: the `kind="..."` labels only exist on world-loop
stall events, and a run with no stalls has none. The step died there, before
`exit $status` could report the verdict it had just passed. Runs that *did*
record a stall -- worse runs -- passed, which is why this read as a flake.

Method: the check does not lint the shell, it *runs* it. For every step that
captures the gate's status (`status=$?`) and then keeps going, the tail is
executed under `bash -e` + `set -uo pipefail` with the paths redirected into a
temp directory, against three scrape fixtures:

  clean    a non-empty metrics file with no `kind="..."` label -- a run with no
           world-thread stalls, which is the *healthy* case (and the one that
           turned run 37877217457 red)
  stalled  a metrics file that does carry stall labels
  empty    a zero-byte scrape: the server had already stopped, so `curl > file`
           left nothing behind (the `-s` branch of the tail)

A passing gate must survive all three and still print its own instrumentation
line. `--self-test` runs the same harness against the known-bad pre-fix tail
and requires that it is caught; `--verify` does that *and* the real-file check.

Scope: the SLA-gate steps (those running `loom-loadtest`), because there the
step's exit code *is* a measurement verdict. Steps that merely build or test
are not covered.

Usage: check-ci-step-shell-safety.py [--self-test|--verify] [.github/workflows/ci.yml]
"""

import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

# The unguarded tail as it stood before the OBI-354 fix. Kept here so
# --self-test can prove the harness detects the real bug, not a toy one.
KNOWN_BAD_TAIL = """          curl -s --max-time 2 http://127.0.0.1:4001/metrics > /tmp/loom-metrics-final.txt 2>/dev/null || true
          durmax=$(awk '/^loom_world_loop_duration_ms_max/ {print $2; exit}' /tmp/loom-metrics-final.txt)
          stalls=$(awk '/^loom_world_loop_stalls_total/ {s+=$2} END {printf "%d", s+0}' /tmp/loom-metrics-final.txt)
          kinds=$(grep -oE 'kind="[a-z_]+"' /tmp/loom-metrics-final.txt | sed 's/kind="//;s/"//' | sort -u | tr '\\n' ' ')
          echo "world_loop: worst_iteration_ms=${durmax:-unknown} stall_events=${stalls:-0} kinds=${kinds:-none}"
"""

FIXTURES = {
    # run 37877217457's actual scrape: counters present, no stall labels.
    "clean": (
        "# TYPE loom_world_loop_ticks_total counter\n"
        "loom_world_loop_ticks_total 907\n"
        "loom_world_loop_iterations_total 13549\n"
        "loom_world_loop_gap_ms_max 100\n"
        "loom_world_loop_duration_ms_max 26\n"
    ),
    "stalled": (
        'loom_world_loop_duration_ms_max{kind="world_tick"} 61\n'
        'loom_world_loop_stalls_total{kind="world_tick"} 3\n'
    ),
    "empty": "",
}


def step_tails(text: str):
    """Yield (step_name, tail) for SLA-gate steps that capture `$?` then continue.

    A `- name:` item's block runs to the next line at the same or lower indent,
    blank lines included (a regex over `[^\\n]+` would stop at the first one).
    """
    lines = text.splitlines(keepends=True)
    i = 0
    while i < len(lines):
        m = re.match(r"^(?P<indent>[ ]*)- (?P<key>name|uses): (?P<rest>.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group("indent"))
        j = i + 1
        body = []
        while j < len(lines):
            line = lines[j]
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            body.append(line)
            j += 1
        run_at = next(
            (k for k, l in enumerate(body) if re.match(r"^\s+run: \|\s*$", l)), None
        )
        src = "".join(body)
        if run_at is not None and "loom-loadtest" in src and "status=$?" in src:
            tail = "".join(body[run_at + 1 :]).split("status=$?", 1)[1]
            if "exit $status" in tail:
                name = (
                    m.group("rest").strip()
                    if m.group("key") == "name"
                    else "(unnamed step)"
                )
                yield name, tail
        i = j


def run_tail(tail: str) -> list[tuple[str, int, str]]:
    """Execute one tail under the runner's shell flags, once per fixture."""
    results = []
    for label, contents in FIXTURES.items():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "results").mkdir()
            (root / "saves").mkdir()
            metrics = root / "loom-metrics-final.txt"
            (root / "loom-serve.log").write_text("INFO loom_cli: loom server started\n")
            # A pid that was a real child of this process and has already been
            # reaped: `kill` is guaranteed ESRCH, so the tail's
            # `kill "$(cat <pidfile>)" || true` is a no-op here and can never
            # signal a live process.
            child = subprocess.Popen(["true"])
            child.wait()
            (root / "loom-serve.pid").write_text(f"{child.pid}\n")

            script = tail.replace("/tmp/loom-", str(root) + "/loom-").replace(
                "results/", str(root) + "/results/"
            )
            # The tail opens by scraping the server's /metrics into a file, and
            # everything after reads that file. There is no server here, so the
            # harness swaps that one line for the fixture under test -- which is
            # exactly the situation the tail has to survive: whatever the scrape
            # left behind, including nothing. If this substitution stops
            # matching, the check would quietly test nothing, so it fails loud.
            fixture_line = f"printf %s {shlex.quote(contents)} > {metrics}"
            script, n = re.subn(
                r"(?m)^[ ]*curl [^\n]*/metrics[^\n]*$",
                " " * 10 + fixture_line + " || true",
                script,
            )
            if n != 1:
                raise SystemExit(
                    "check-ci-step-shell-safety: FAIL -- could not find exactly one "
                    "`curl .../metrics > <file>` scrape line in the step tail, so the "
                    "fixtures cannot be fed to it. Update this check to match the step."
                )
            # The context the step gives the tail: the gate has already passed.
            prefix = f"set -uo pipefail\nstatus=0\nSAVES={root}/saves\ncd {root}\n"
            proc = subprocess.run(
                # `-e` is what the runner supplies; `-x` only traces, and on a
                # non-zero exit the last trace line names the command that
                # aborted the step -- the actionable part of the report.
                ["bash", "--noprofile", "--norc", "-e", "-x", "-c", prefix + script],
                capture_output=True,
                text=True,
            )
            results.append((label, proc.returncode, (proc.stdout + proc.stderr).strip()))
    return results


def main(argv: list[str]) -> int:
    self_test = "--self-test" in argv
    verify = "--verify" in argv
    args = [a for a in argv[1:] if a not in ("--self-test", "--verify")]
    path = Path(args[0]) if args else Path(".github/workflows/ci.yml")

    if self_test or verify:
        print("check-ci-step-shell-safety: self-test")
        outcomes = run_tail(KNOWN_BAD_TAIL)
        bad = [lbl for lbl, rc, _ in outcomes if rc != 0]
        if "clean" not in bad:
            print(
                "FAIL: the harness accepted the known-bad tail on the no-stall fixture "
                f"(exit codes: {[(l, r) for l, r, _ in outcomes]})"
            )
            return 1
        print(
            "  ok: the known-bad pre-fix tail is caught (non-zero on "
            + ", ".join(sorted(bad))
            + " fixture(s))"
        )
        if not verify:
            return 0
        print("check-ci-step-shell-safety: real-file check")

    if not path.exists():
        print(f"check-ci-step-shell-safety: no such workflow file: {path}")
        return 2

    failures = []
    checked = 0
    for name, tail in step_tails(path.read_text()):
        checked += 1
        for label, rc, output in run_tail(tail):
            if rc == 0:
                printed = [
                    l for l in output.splitlines()
                    if not l.startswith("+") and not l.startswith("bash:")
                ]
                reported = [l for l in printed if "world_loop:" in l] or printed
                last = reported[-1][:110] if reported else "(no output)"
                print(f"  {name} :: {label}: exit 0 | {last}")
            else:
                trace = [l for l in output.splitlines() if l.startswith("+ ")]
                culprit = trace[-1][:160] if trace else "(no trace)"
                print(f"  {name} :: {label}: exit {rc} -- aborted at: {culprit}")
                failures.append((name, label, rc, culprit))
    if checked == 0:
        print("FAIL: no status-capturing SLA-gate step tail found in the workflow")
        return 1
    if failures:
        print(
            "FAIL: a post-verdict step tail aborted the step. Under the runner's "
            "default `bash -e` that turns a PASSING gate red -- guard every command "
            "after `status=$?` that may legitimately exit non-zero (`|| true`)."
        )
        for name, label, rc, culprit in failures:
            print(f"  {name} :: {label} -> exit {rc}, aborted at: {culprit}")
        return 1
    print(
        f"check-ci-step-shell-safety: {checked} step tail(s) survive all "
        f"{len(FIXTURES)} scrape fixtures"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
