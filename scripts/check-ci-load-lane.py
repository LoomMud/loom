#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
"""
Check the CI "load lane" invariants in a workflow file (OBI-308).

`bench`, `loadtest-smoke` and `loadtest-e1-1` measure wall-clock latency on
the self-hosted runner set. Their numbers are only meaningful on a quiet
host: two `cargo build --release` + 150-player runs sharing one ARC host
produced p99 593 ms against a 50 ms SLA with zero login failures and zero
disconnects (runs 37658696127 / 37658252388, 2026-10-07). So:

  1. each load job is in the `loom-ci-load-lane` job-level concurrency group,
     with `cancel-in-progress: false` (never kill a running measurement) and
     `queue: max` (a *cancelled* required check blocks a PR as hard as a
     failed one, so waiting runs must queue in FIFO, not replace each other);
  2. no other job may take that group -- unrelated work must not hold the
     lane that the latency gates are waiting on;
  3. the three load jobs are chained with `needs`
     (loadtest-e1-1 -> loadtest-smoke -> bench) so they never overlap inside
     one run either;
  4. the required checks (rust, deny, dco, hygiene, loadtest-e1-1) cannot be
     skipped or downgraded: no `needs`, no `if`, no `continue-on-error`, and
     `loadtest-e1-1` still runs `loom-loadtest` with `--players 150` and
     `--fail-on-sla-miss`.

Usage: check-ci-load-lane.py [.github/workflows/ci.yml]
"""

import re
import sys
from pathlib import Path

LANE_GROUP = "loom-ci-load-lane"
# In DAG order: the required gate goes first so nothing it depends on can
# delay or skip it, and the two non-required gates follow it in the lane.
LANE_JOBS = ["loadtest-e1-1", "loadtest-smoke", "bench"]
LANE_CHAIN = {"loadtest-smoke": "loadtest-e1-1", "bench": "loadtest-smoke"}
REQUIRED_JOBS = ["rust", "deny", "dco", "hygiene", "loadtest-e1-1"]
# The E1.1 exit criterion (spec v2 section 10): 150 players, p99 < 50 ms,
# and an SLA miss must fail the job.
SLA_FLAGS = ["--players 150", "--fail-on-sla-miss"]
DEFAULT = ".github/workflows/ci.yml"


def job_blocks(text):
    """job id -> list of its body lines, from the `jobs:` mapping.

    Reads the file as YAML-by-indentation: job keys are exactly 2 spaces
    under `jobs:` with nothing after the colon. That is the shape of every
    workflow in this repo, and it keeps the check dependency-free (no PyYAML
    on the minimal ARC runner image).
    """
    lines = text.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if re.fullmatch(r"jobs:\s*", l))
    except StopIteration:
        sys.exit(f"check-ci-load-lane: no top-level `jobs:` mapping found")
    jobs = {}
    current = None
    for i in range(start + 1, len(lines)):
        line = lines[i]
        key = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*(#.*)?", line)
        if key:
            current = key.group(1)
            jobs[current] = []
            continue
        if current is not None and re.fullmatch(r"[A-Za-z0-9_-]+:.*", line):
            break  # left the jobs: mapping (back to indent 0)
        if current is not None:
            jobs[current].append(line)
    return jobs


def child(block, key):
    """Lines directly under an indent-4 `key:` inside a job body."""
    out = []
    seen = False
    for line in block:
        if re.fullmatch(rf"    {re.escape(key)}:\s*", line):
            seen = True
            continue
        if seen:
            if re.fullmatch(r"    \S.*", line) or re.fullmatch(r"\S.*", line):
                break
            out.append(line)
    return out


def submapping(block, key):
    """Direct children of an indent-4 `key:` block, as {name: value}.

    Job properties sit at 2 spaces, their children at 6; the indent is read
    off the first child line instead of being hard-coded.
    """
    kids = child(block, key)
    if not kids:
        return {}
    indent = len(kids[0]) - len(kids[0].lstrip())
    out = {}
    for line in kids:
        m = re.fullmatch(r"{}([a-zA-Z_-]+):\s*(.*?)\s*".format(" " * indent), line)
        if m and m.group(2):
            out[m.group(1)] = m.group(2).strip("'\"")
    return out


def scalar(block, key):
    """The value of an indent-4 `key: value` line, or None."""
    for line in block:
        m = re.fullmatch(rf"    {re.escape(key)}:\s*(.+?)\s*", line)
        if m:
            return m.group(1)
    return None


def needs_of(block):
    raw = scalar(block, "needs")
    if raw is not None:
        if raw.startswith("["):
            return [n.strip().strip("'\"") for n in raw.strip("[]").split(",") if n.strip()]
        return [raw.strip().strip("'\"")]
    return [l.strip("- ").strip() for l in child(block, "needs") if l.strip()]


def check_text(text):
    jobs = job_blocks(text)
    errors = []

    for job in LANE_JOBS:
        if job not in jobs:
            errors.append(f"`{job}` job is missing from the workflow")
            continue
        block = jobs[job]
        code = "\n".join(l for l in block if not l.lstrip().startswith("#"))
        got = submapping(block, "concurrency")
        if not got and "concurrency" not in code:
            errors.append(f"`{job}` has no job-level `concurrency:` -- it can run "
                          "against a loaded host and its latency numbers are noise")
        if got.get("group") != LANE_GROUP:
            errors.append(f"`{job}` concurrency.group is {got.get('group')!r}, "
                          f"expected {LANE_GROUP!r}")
        if got.get("cancel-in-progress") != "false":
            errors.append(f"`{job}` concurrency.cancel-in-progress is "
                          f"{got.get('cancel-in-progress')!r}, expected 'false' "
                          "(never cancel a measurement mid-flight)")
        if got.get("queue") != "max":
            errors.append(f"`{job}` concurrency.queue is {got.get('queue')!r}, "
                          "expected 'max' (pending runs must queue, not be "
                          "cancelled and replaced)")

    for job, dep in LANE_CHAIN.items():
        if job in jobs:
            deps = needs_of(jobs[job])
            if dep not in deps:
                errors.append(f"`{job}` must `needs: {dep}` so the load gates do not "
                              "overlap each other inside a single run")
            cond = scalar(jobs[job], "if")
            if cond is not None and "success()" not in cond:
                errors.append(f"`{job}` sets `if:` without `success()`: an explicit `if` "
                              "overrides the default `needs` gate, so it would run next to "
                              "a failed or skipped lane job")

    holder_group = re.compile(rf"\bgroup:\s*{LANE_GROUP}\b")
    for job, block in jobs.items():
        if job in LANE_JOBS:
            continue
        code = "\n".join(l for l in block if not l.lstrip().startswith("#"))
        if holder_group.search(code):
            errors.append(f"`{job}` must not join {LANE_GROUP!r}: unrelated work would "
                          "hold up the latency gates")

    for job in REQUIRED_JOBS:
        if job not in jobs:
            errors.append(f"required check `{job}` is missing from the workflow "
                          "(branch protection lists it)")
            continue
        block = jobs[job]
        if needs_of(block):
            errors.append(f"required check `{job}` has `needs:` -- an upstream failure "
                          "would skip it, which blocks the PR like a failure")
        if scalar(block, "if") is not None:
            errors.append(f"required check `{job}` has `if:` -- it can be skipped")
        if scalar(block, "continue-on-error") == "true":
            errors.append(f"required check `{job}` sets continue-on-error: true")

    e11 = [l for l in jobs.get("loadtest-e1-1", []) if not l.lstrip().startswith("#")]
    body = "\n".join(e11)  # comments excluded: the flags must be in the command
    for flag in SLA_FLAGS:
        if flag not in body:
            errors.append(f"`loadtest-e1-1` no longer passes `{flag}`: the E1.1 gate "
                          "must keep measuring 150 players and failing on an SLA miss")

    return errors


# --- self-test ---------------------------------------------------------------
# The lane is a property of the workflow *text*; nothing else proves the check
# notices when it rots. `--self-test` mutates the real ci.yml and asserts each
# invariant bites. Runs in the `hygiene` job next to the real check.

def _sub(text, needle, repl, nth=0):
    """Replace the nth non-comment line containing `needle` (None = drop it)."""
    out, hits = [], 0
    for line in text.splitlines(keepends=True):
        if needle in line and not line.lstrip().startswith("#"):
            if hits == nth:
                if repl is not None:
                    out.append(repl)
            else:
                out.append(line)
            hits += 1
        else:
            out.append(line)
    assert hits > nth, f"self-test needle not found: {needle!r}"
    return "".join(out)


def _drop_concurrency(text, job):
    lines = text.splitlines(keepends=True)
    i = next(k for k, l in enumerate(lines) if l == f"  {job}:\n")
    j = next(k for k in range(i, len(lines)) if lines[k] == "    concurrency:\n")
    return "".join(lines[:j] + lines[j + 4:])


def _prepend(text, job, prop):
    return text.replace(f"  {job}:\n", f"  {job}:\n{prop}", 1)


MUTANTS = [
    ("cancel-in-progress: true", lambda t: _sub(t, "cancel-in-progress: false",
                                                "      cancel-in-progress: true\n")),
    ("cancel-in-progress as an expression",
     lambda t: _sub(t, "cancel-in-progress: false",
                    "      cancel-in-progress: ${{ github.event_name != 'pull_request' }}\n")),
    ("queue: max dropped", lambda t: _sub(t, "queue: max", None)),
    ("group made per-ref", lambda t: _sub(t, "group: loom-ci-load-lane",
                                          "      group: ci-${{ github.ref }}\n")),
    ("e1-1 concurrency dropped", lambda t: _drop_concurrency(t, "loadtest-e1-1")),
    ("smoke unchained", lambda t: _sub(t, "needs: loadtest-e1-1", None)),
    ("bench unchained", lambda t: _sub(t, "needs: loadtest-smoke", None)),
    ("bench loses success()", lambda t: _sub(t, "if: github.event_name == 'pull_request' && success()",
                                             "    if: github.event_name == 'pull_request'\n")),
    ("required gate gains needs", lambda t: _prepend(t, "loadtest-e1-1", "    needs: rust\n")),
    ("required gate made optional",
     lambda t: _prepend(t, "loadtest-e1-1", "    continue-on-error: true\n")),
    ("SLA flag dropped", lambda t: _sub(t, "--fail-on-sla-miss", None)),
    ("population lowered", lambda t: _sub(t, "--players 150", "            --players 20 \\\n")),
    ("unrelated job joins the lane",
     lambda t: t.replace("jobs:\n", "jobs:\n  noise:\n    concurrency:\n"
                                    "      group: loom-ci-load-lane\n"
                                    "      cancel-in-progress: false\n"
                                    "      queue: max\n"
                                    "    runs-on: ubuntu-latest\n"
                                    "    steps:\n      - run: echo hi\n", 1)),
    ("required check renamed away", lambda t: t.replace("  deny:\n", "  deny-optional:\n", 1)),
]


def self_test(path):
    text = Path(path).read_text()
    failed = 0
    if check_text(text):
        print(f"FAIL baseline: {path} does not satisfy its own lane invariants")
        failed += 1
    for name, mutate in MUTANTS:
        errors = check_text(mutate(text))
        if errors:
            print(f"ok   {name}: caught ({errors[0][:90]})")
        else:
            print(f"FAIL {name}: the check does not notice this change")
            failed += 1
    print(f"check-ci-load-lane self-test: {len(MUTANTS) + 1} cases, "
          f"{failed} failure(s)")
    return 1 if failed else 0


def main(argv):
    if "--self-test" in argv:
        return self_test(argv[-1] if argv[-1].endswith(".yml") else DEFAULT)
    path = argv[1] if len(argv) > 1 else DEFAULT
    errors = check_text(Path(path).read_text())
    if errors:
        print(f"check-ci-load-lane: {len(errors)} problem(s) in {path}")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"check-ci-load-lane: {path} keeps the {LANE_GROUP} lane and "
          f"{'/'.join(LANE_JOBS)} in DAG order")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
