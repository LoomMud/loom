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
     or is in an OBI-325 escape group, which rule 8 pins to exactly the shape
     that still puts every runtime-relevant run in the lane;
  2. no other job may take that group -- unrelated work must not hold the
     lane that the latency gates are waiting on;
  3. the three load jobs are chained with `needs`
     (loadtest-e1-1 -> loadtest-smoke -> bench) so they never overlap inside
     one run either;
  4. the required checks (rust, deny, dco, hygiene, loadtest-e1-1) cannot be
     skipped or downgraded: no `needs`, no `if`, no `continue-on-error` -- except
     that `loadtest-e1-1` may `needs: classify` *only* beside the exact
     `if: ${{ !cancelled() }}`, because GitHub counts a *skipped* required check
     as passing and a gate that an upstream job can skip is a gate that can be
     green without measuring. `loadtest-e1-1` still runs `loom-loadtest` with
     `--players 150` and `--fail-on-sla-miss`, with enough `timeout-minutes` that
     host load can only make the measurement slow, never get the job cancelled.
  5. if the workflow has a *workflow-level* `concurrency` block (OBI-313), it
     cancels superseded `pull_request` runs and nothing else. The rule the CTO
     accepted (2026-10-08) is that no required check on a *mergeable candidate*
     may be cancelled; a superseded PR SHA is not a mergeable candidate under
     `strict: true`, which is what makes the cancel legal. `group` must be
     PR-scoped and carry `github.run_id` as the non-PR fallback, and
     `cancel-in-progress` must be an expression that is true only for
     `pull_request`. Rule 5 exists because a workflow-level cancel reaches into
     jobs whose own `cancel-in-progress: false` forbids being cancelled -- rule
     1 is only as strong as what the block above it is allowed to kill; and
  6. if that block cancels `pull_request` runs, `on.pull_request.types` is
     narrowed to the activities that change the commit (`opened`, `synchronize`,
     `reopened`) -- with `types:` omitted GitHub fires on *every* activity, so
     labeling a PR would cancel its own running gate -- and the narrowing may
     not drop `opened` or `synchronize`, which is how a required check gets
     skipped under cover of "narrowing the trigger"; and
  7. in `loadtest-e1-1`, the p99 verdict is the only thing that fails the job:
     the step saves the loadtest exit status, runs its post-run evidence tail
     with errexit disabled, and re-asserts the saved status at the end. The
     runner's default `bash --noprofile --norc -e -o pipefail` means one
     non-zero command in that tail aborts the step *after* the verdict was
     computed -- which is how main run 37862921160 (sha eaf9ceb) went red on a
     p99 PASS of 21.47 ms: the world thread recorded zero stalls, so the scrape
     had no `kind="..."` label, `grep -oE` exited 1, pipefail carried it through
     the pipeline, and the command substitution failed the step. A gate that
     goes red exactly when the world thread behaves is worse than no gate; and
  8. the OBI-325 lane escape (`needs: classify` + a conditional
     `concurrency.group`) is only allowed in the shape that keeps the gate
     fail-closed: the `classify` job has nothing upstream of it, can never be
     skipped, and writes a verdict on every path (a job that dies mid-decision
     must still leave `runtime=true` behind, because rule 4's `if:` then makes
     the gate queue and measure rather than be skipped-and-counted-as-passing),
     and can never report "irrelevant" on a diff it could not read
     (`runtime != 'false'` everywhere, never `== 'true'`), the escape group is
     run-scoped (`github.run_id`) so skipped runs do not serialise behind each
     other, each lane job reads the verdict from its own place in the `needs`
     chain, and every step that could touch the measurement host is guarded by
     that same test -- an escaped group with unguarded steps is precisely the
     contention OBI-308 was written to stop; and
  9. every `toolchain:` a job installs equals the channel `rust-toolchain.toml`
     declares. Rule 9 is what makes `.github/**` safe to put on the skip list:
     the compiler is one of the inputs the lane measures, so the workflow may
     not be a second, unsynced place to change it; and
 10. no `${{ ... }}` that calls a status function (`cancelled()`, `always()`,
     `failure()`, `success()`) may appear inside a `run:` block -- including
     inside a shell comment there, because Actions expands expressions before
     the shell sees them. One is a workflow file GitHub cannot compile: no job
     runs, and on `pull_request` not even a check run appears, so required
     checks do not go red, they vanish. PR #144 lost its CI to exactly this; and
 11. the mudlib the lane serves is a *pinned input* (OBI-326). `warp.ref` names
     the world being measured -- one line, a full 40-character commit SHA, never
     a branch name, which can move underneath a run -- the classifier counts it
     runtime-relevant so a bump takes a lane place, and every job that serves a
     mudlib reads the rev from that file, refuses an external checkout whose rev
     comes from anywhere else, re-reads the file to verify what landed on disk,
     and stamps the rev into the report with `--note`. The repository name is the
     one half that may stay a workflow literal (`LoomMud/warp`), and rule 11
     asserts that literal, so a fork swap fails `hygiene` even though `.github/**`
     is on the skip list. Rule 11 is what keeps the OBI-325 skip honest for the one
     input that lives in a second repository: without it a warp-side change moves
     p99 while every loom PR skips, and the next source PR is blamed for a
     regression it did not cause; and
 12. the workflow keeps a *drift backstop* (OBI-326): `on.schedule` and
     `on.workflow_dispatch` are both still triggers. Neither carries a commit
     range, so the classifier falls closed to "take the lane", which means the
     nightly run measures `main` every day however quiet the diffs are, and a
     release SHA can be measured on demand instead of forced through the lane by
     an empty commit. Rule 12 exists for the same reason as rule 8: the trigger
     list lives in `.github/**`, which the lane counts irrelevant, so a backstop
     that can be deleted without a required check noticing is a comment; and
 13. a job that audits commit sign-off gives an answer for an event with no
     commit range, and the answer is a bounded range, never a bare rev. A schedule
     or dispatch run that audits "every commit reachable from HEAD" is red on the
     first night and stays red, because merged history contains commits whose
     sign-off names the agent who wrote them rather than the author (run
     37752599276). A permanently red backstop is not a backstop; it is a
     notification nobody reads; and
 14. the stage-two identity proof (OBI-397) must predict `loadtest-e1-1`, not
     merely resemble a build. The classifier's path table decides which diffs are
     *worth asking*; the answer to "did the measured program move" comes from
     building both ends of the range and hashing the artifacts. That is only
     evidence about E1.1 if the proof runs the gate's own build under the gate's
     own toolchain, cache action, host and timeouts -- so this rule reads
     `BUILD_CMD`, `ARTIFACTS` and the action pins out of `scripts/load-lane-identity.py`
     and compares them, string for string, against the steps of `loadtest-e1-1`.
     A proof built differently is a hash of some other program; and
 15. the proof may only ever *lower* a verdict, and only where it has standing.
     It runs on `pull_request` when the table said "relevant" and every relevant
     path is buildable Rust source (`steps.decide.outputs.identity`), never on a
     `main` push, where spec 8.12 requires a real p99 per release; the merge step
     re-reads the table's own output and can only write `runtime=false`, so a
     table skip stays a skip and no docs PR can buy itself a lane place by failing
     to build. Scope is asserted against the classifier as code (importing it and
     asking `identity_candidate`), including that every source file which
     `include!`s a build-generated path is named in `IDENTITY_NEVER` -- the one
     shape where "same bytes at both ends" would not mean "same program".

Usage: check-ci-load-lane.py [.github/workflows/ci.yml]
"""

import argparse
import ast
import importlib.util
import re
import sys
from pathlib import Path

LANE_GROUP = "loom-ci-load-lane"
# In DAG order: the required gate goes first so nothing it depends on can
# delay or skip it, and the two non-required gates follow it in the lane.
LANE_JOBS = ["loadtest-e1-1", "loadtest-smoke", "bench"]
LANE_CHAIN = {"loadtest-smoke": "loadtest-e1-1", "bench": "loadtest-smoke"}
REQUIRED_JOBS = ["rust", "deny", "dco", "hygiene", "loadtest-e1-1"]
# OBI-325 review: the one job-level `if:` the required gate may carry. GitHub
# counts a *skipped* required check as passing, so `needs: classify` without this
# expression is a fail-open: a dead classifier buys a green with no measurement.
# `${{ !cancelled() }}` makes the gate run whenever the run itself was not
# cancelled, so an unreadable verdict costs a lane run instead of a fake green.
# `always()` is deliberately not allowed -- it would start a 150-player
# measurement on a host GitHub is already tearing down after a cancel.
GATE_IF = "!cancelled()"
# OBI-325: which job's output each lane job is allowed to read its lane verdict
# from. `loadtest-e1-1` asks the classifier; the other two inherit the verdict
# the gate already acted on, so one run cannot half-occupy the lane.
CLASSIFIER = "classify"
ESCAPE_SOURCE = {"loadtest-e1-1": CLASSIFIER,
                 "loadtest-smoke": "loadtest-e1-1",
                 "bench": "loadtest-smoke"}
# The verdict test, spelled exactly once per guarded step and per group.
ESCAPE_TEST = "{src}.outputs.runtime != 'false'"
# A step that can put load on the lane host. If the group escapes and one of
# these is unguarded, the run measures *outside* the lane: worst case, not best.
MEASURING_NEEDLES = ["cargo build --release", "--fail-on-sla-miss", "--players",
                     "scripts/bench-gate.sh", "loom-cli serve"]
# The E1.1 exit criterion (spec v2 section 10): 150 players, p99 < 50 ms,
# and an SLA miss must fail the job.
SLA_FLAGS = ["--players 150", "--fail-on-sla-miss"]
# Wall-clock headroom per gate. The lane removes the *gate* competing with
# itself; it does not remove the same run's `rust` job, or another PR's
# builds, from the host. A starved release build must therefore not be able
# to end the job: run 37663331238 (2026-10-07) hit the old 15-minute budget
# mid-build and the required check was `cancelled`, which blocks a PR exactly
# like a miss while saying nothing at all about p99.
MIN_TIMEOUT = {"loadtest-e1-1": 30, "loadtest-smoke": 20}
# The `pull_request` activity types that change the commit under test, and the
# two that a required check cannot afford to lose (OBI-313).
COMMIT_TYPES = {"opened", "synchronize", "reopened"}
MUST_RUN_ON = {"opened", "synchronize"}
DEFAULT = ".github/workflows/ci.yml"
# Workflow-level concurrency (OBI-313). A constant group name would be a
# repo-wide mutex -- one PR's push cancelling another PR's in-flight
# 150-player gate -- and a group without the `github.run_id` fallback puts a
# `push` to `main` in a shared group, where the next main push (or a re-run of
# the gate, which is how OBI-311 measures "5 sequential un-retried runs")
# could cancel it.
WF_GROUP_PREFIX = "github.workflow"
WF_RUNID_FALLBACK = "github.run_id"
WF_PR_SCOPED = ("github.ref", "github.head_ref", "github.event.pull_request.number")
WF_PR_TEST = re.compile(r"github\.event_name\s*==\s*['\"]pull_request['\"]")
# Rule 7: the E1.1 step's contract with the shell. The verdict is captured in
# `status=$?` and re-asserted with `exit $status`; the evidence in between must
# not be able to end the step, so it runs under `set +e`.
E11_STATUS_CAPTURE = "status=$?"
E11_VERDICT_EXIT = re.compile(r"^\s*exit \$status\s*$")
E11_ERREXIT_OFF = re.compile(r"^\s*set \+e\s*$")
WF_OTHER_EVENTS = ("push", "pull_request_target", "workflow_dispatch", "workflow_call",
                   "schedule", "repository_dispatch", "merge_request_event")

# Rule 11 (OBI-326): the mudlib is a second repository, and it is an input to the
# number the gate prints, so it is pinned in this one -- the same way `Cargo.lock`
# pins dependencies. `warp.ref` holds exactly one thing: the commit SHA. The
# repository name is the one half that may stay a workflow literal, because it
# never moves and because `hygiene` runs rule 11 on every PR whatever `classify`
# decides -- a fork swap there fails a required check even though `.github/**` is
# on the skip list. The rev is the half that moves underneath a run, so it may
# only ever come from the pin file.
MUDLIB_PIN = "warp.ref"
MUDLIB_REPO = "LoomMud/warp"
PIN_STEP_ID = "warp-pin"
PIN_REV_REF = "ref: ${{ %s.outputs.rev }}" % ("steps." + PIN_STEP_ID)
PIN_REPO_LINE = "repository: %s" % MUDLIB_REPO
# A step reads the pin only if it names the file as its own path token. The regex
# is the point: `ci/warp.ref` contains every character of `warp.ref` and is a
# different file, and a pin read from the wrong place pins nothing.
PIN_FILE_TOKEN = re.compile(r"(?:^|[\s:=])%s(?=$|[\s:|])" % re.escape(MUDLIB_PIN), re.M)
# A job that measures against a mudlib: `--mudlib` names the world under test and
# `repository:` is the external checkout that brings it in. Both only appear in
# the two load jobs -- `build`'s `-p loom-loadtest` must not be mistaken for one.
SERVING_NEEDLES = ("--mudlib", "repository:")
PIN_REV_SHA = re.compile(r"^[0-9a-f]{40}$")

# Rule 12 (OBI-326): the drift backstop. These two events carry no commit range,
# so `classify` falls closed to `runtime=true` and the run measures -- the only
# paths to a number when every diff in between was correctly skipped.
BACKSTOP_EVENTS = ("schedule", "workflow_dispatch")

# Rules 14 and 15 (OBI-397): the stage-two identity proof, which decides a lane
# place by building `loadtest-e1-1`'s own command at both ends of the range and
# comparing the bytes. It is worth as much as its agreement with the gate, so
# every constant below is *compared against the gate's steps* rather than
# restated: a proof that drifts to a different rustc, a different `-p` set or a
# different feature env is a proof about some other program.
IDENTITY_SCRIPT = "scripts/load-lane-identity.py"
PROOF_STEP_ID = "prove"
VERDICT_STEP_ID = "verdict"
E1_BUILD_MARK = "cargo build --release -p loom-cli -p loom-loadtest"
E1_ARTIFACTS = ("loom-cli", "loom-loadtest")
E1_PARITY_ACTIONS = ("dtolnay/rust-toolchain@", "Swatinem/rust-cache@")
E1_TOOLS_MARK = "scripts/ci-ensure-tools.sh"
# The candidate guard, spelled once per stage-two step. Two halves, each stopping
# a different failure: `identity` keeps the proof off diffs the table cannot
# settle by path alone, and `pull_request` keeps a `main` push -- where the
# Phase 1 exit criterion wants a real p99 (rule 8) -- unskippable.
CANDIDATE_GUARD = ("steps.decide.outputs.identity", "github.event_name == 'pull_request'")
# Paths that are gate inputs the hash of two binaries cannot speak for. Each is a
# different way the lane can move without touching `loom-cli` or `loom-loadtest`:
# what gets compiled (manifests, lockfile, `.cargo/`, the toolchain, a build
# script), what the *driver reads* (the pinned mudlib rev, `mudlib/**`, the mix
# mirror), and the criterion gate that shares this lane. Rule 15 asserts each one
# makes a source diff ineligible, which is the mechanical version of "the proof
# may only judge what the proof can judge".
UNHASHABLE_WITNESSES = (
    "Cargo.lock", "crates/loom-cli/Cargo.toml", ".cargo/config.toml",
    "rust-toolchain.toml", "crates/loom-vm/build.rs",
    MUDLIB_PIN, "mudlib/room/lobby.c",
    "crates/loom-loadtest/tests/fixtures/mix.tsv",
    "crates/loom-vm/benches/vm_bench.rs", "scripts/bench-gate.sh",
    "scripts/bench_compare.py",
)
SOURCE_WITNESS = "crates/loom-vm/src/world.rs"


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


def if_expression(value):
    """`"${{ !cancelled() }}"` -> `"!cancelled()"`; anything else as written.

    GitHub accepts an `if:` with or without the `${{ }}` wrapper, and this file
    uses both. The rule is about the *expression*, so compare expressions.
    """
    if value is None:
        return None
    m = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", value)
    return m.group(1) if m else value


def needs_of(block):
    raw = scalar(block, "needs")
    if raw is not None:
        if raw.startswith("["):
            return [n.strip().strip("'\"") for n in raw.strip("[]").split(",") if n.strip()]
        return [raw.strip().strip("'\"")]
    return [l.strip("- ").strip() for l in child(block, "needs") if l.strip()]


def steps_of(block):
    """The job's `steps:` entries, each as its list of lines.

    A step starts at an indent-6 `- ` and its own keys sit at indent 8, which is
    also how `step_if()` finds its guard. Block-scalar script bodies are deeper
    still, so they cannot be mistaken for a step key.
    """
    out, cur = [], None
    for line in block:
        if re.match(r"      - ", line):
            if cur is not None:
                out.append(cur)
            cur = [line]
            continue
        if cur is not None:
            cur.append(line)
    if cur is not None:
        out.append(cur)
    return out


def step_key(step, key):
    """A step's own scalar key (indent 8), or None.

    Quoting is removed only when the whole value is a quoted scalar: an `if:`
    expression ends in `'false'`, and stripping quote characters off both ends
    would mangle it.
    """
    for line in step:
        m = re.match(rf"        {key}:\s*(.*?)\s*$", line)
        if m:
            val = m.group(1)
            if len(val) >= 2 and val[0] in "'\"" and val[-1] == val[0]:
                val = val[1:-1]
            return val
    return None


def step_if(step):
    return step_key(step, "if")


def step_code(step):
    return "\n".join(l for l in step if not l.lstrip().startswith("#"))


def escape_test(job):
    return ESCAPE_TEST.format(src="needs." + ESCAPE_SOURCE[job])


def lane_group_error(job, group):
    """Rules 1 and 7a: the group is either the lane, or an escape *to* the lane.

    Both halves of the OBI-325 decision have to be pinned here. The group is the
    half that decides whether a run waits 40 minutes for a place it will not
    use; the step guards in `check_classifier()` are the half that decides
    whether a run that skipped the queue then measured on a loaded host.
    """
    if group == LANE_GROUP:
        return []
    test = escape_test(job)
    g = (group or "").strip()
    if not (g.startswith("${{") and g.endswith("}}")):
        return [f"`{job}` concurrency.group is {group!r}: expected {LANE_GROUP!r}, or an "
                f"OBI-325 escape keyed on `{test}`"]
    errs = []
    if test not in g:
        if "outputs.runtime" in g and "== 'true'" in g:
            errs.append(f"`{job}` concurrency.group keys the escape on `== 'true'`: a missing or "
                        "unreadable classifier verdict must mean 'take the lane and measure', so "
                        f"it has to be `{test}`")
        else:
            errs.append(f"`{job}` concurrency.group is not keyed on `{test}`: each lane job reads "
                        f"the verdict from its own place in the needs chain (`{ESCAPE_SOURCE[job]}`), "
                        "so one run cannot half-occupy the lane")
    if f"'{LANE_GROUP}'" not in g:
        errs.append(f"`{job}` concurrency.group can never resolve to {LANE_GROUP!r}: a "
                    "runtime-relevant run must take the lane")
    arms = g.split("||")
    if len(arms) < 2 or "github.run_id" not in arms[-1] or "format(" not in arms[-1]:
        errs.append(f"`{job}` concurrency.group's escape arm is not run-scoped: it must be "
                    "`format('...-{0}', github.run_id)`, or skipped runs serialise behind one "
                    "constant group and re-create the queue OBI-325 exists to remove")
    return errs


def check_classifier(jobs):
    """Rule 8. The escape hatch is only safe while the classifier can fail
    *toward the lane* and every step that could load the host is guarded."""
    errors = []
    if CLASSIFIER not in jobs:
        return [f"`{CLASSIFIER}` job is missing: the lane escape has nothing to read its "
                "verdict from"]
    block = jobs[CLASSIFIER]
    if needs_of(block):
        errors.append(f"`{CLASSIFIER}` has `needs:` -- a classifier that is itself skipped "
                      "has no verdict, and the gate's `if:` would still run it into the lane "
                      "on an empty answer; the decision must come from reading this run's diff")
    if scalar(block, "if") is not None:
        errors.append(f"`{CLASSIFIER}` has a job-level `if:` -- it can be skipped, same failure "
                      "as giving it `needs:`")
    if scalar(block, "continue-on-error") == "true":
        errors.append(f"`{CLASSIFIER}` sets continue-on-error: true -- its output would then be "
                      "empty on a real failure instead of failing loudly")
    # Comments excluded throughout: this rule asks whether the *code* writes a
    # verdict, and a prose mention of `runtime=true` or `exit 0` must not be able
    # to satisfy it. (It did: a comment explaining the fallback kept the mutant
    # "fallback deleted" passing.)
    text = "\n".join(l for l in block if not l.lstrip().startswith("#"))
    # The verdict must have exactly one source step, and that step must be either
    # the classifier or -- since OBI-397 -- the merge that can only *downgrade*
    # the classifier's answer toward "skip". Rule 14 pins the merge itself;
    # anything else reading a lane decision out of thin air is rejected here.
    src = re.search(r"runtime: \$\{\{ steps\.([a-z0-9-]+)\.outputs\.runtime \}\}", text)
    if not src:
        errors.append(f"`{CLASSIFIER}` does not publish `outputs.runtime` from a step in this "
                      "job: the lane verdict must have exactly one source")
    elif src.group(1) != "decide":
        merge = [s for s in steps_of(block)
                 if step_key(s, "id") == src.group(1)]
        if not merge:
            errors.append(f"`{CLASSIFIER}` publishes outputs.runtime from step "
                          f"`{src.group(1)}`, which does not exist")
        elif "steps.decide.outputs.runtime" not in step_code(merge[0]):
            errors.append(f"`{CLASSIFIER}`'s verdict comes from `{src.group(1)}`, which never "
                          "reads the classifier's own `runtime=`: a second decider must be "
                          "grounded in the table's verdict, not replace it")
    if "runtime=true" not in text:
        errors.append(f"`{CLASSIFIER}` has no fail-closed fallback value: without writing "
                      "`runtime=true` when the classifier cannot answer, an undecided diff "
                      "escapes the lane unmeasured")
    # The classifier call itself must be tolerated, whatever else in the job is
    # not: find the invocation and check its last continuation line.
    inv = [k for k, l in enumerate(block)
           if "load-lane-classify.py" in l and not l.lstrip().startswith("#")]
    if not inv:
        errors.append(f"`{CLASSIFIER}` never calls scripts/load-lane-classify.py: the lane "
                      "verdict has to come from the table, not from a hand-written condition")
    for k in inv:
        j = k
        while j + 1 < len(block) and block[j].rstrip().endswith("\\"):
            j += 1
        if "|| true" not in block[j]:
            errors.append(f"`{CLASSIFIER}` can fail on the classifier itself (line {k + 1}): the "
                          "gate would run with an empty verdict instead of the written "
                          "fail-closed one -- reading the diff has to fall back to "
                          "`runtime=true`, not to a missing output")
    # Every step of the decider, not just the one that calls the table: a step
    # that can fail the job leaves the *later* steps -- including the merge that
    # writes the published verdict -- unrun, which is the same missing-output
    # failure this rule has always been about, just one step further along.
    for step in steps_of(block):
        if step_key(step, "run") is None:
            continue          # an action step: `uses:` cannot fail on a shell status
        if step_key(step, "continue-on-error") == "true":
            continue
        if "exit 0" not in step_code(step).splitlines()[-1]:
            errors.append(f"`{CLASSIFIER}`'s step `"
                          + (step_key(step, "name") or "?")
                          + "` ends on whatever its last command returned: a non-zero step "
                            "leaves no verdict written for the gate to read; the decider has to "
                            "default the verdict and then `exit 0`")
    for step in steps_of(block):
        if "ci-ensure-tools.sh" in step_code(step) and step_key(step, "continue-on-error") != "true":
            errors.append(f"`{CLASSIFIER}`'s package step is fatal: a runner that cannot "
                          "apt-install python3 would fail the job before the fallback line "
                          "runs, and the gate would queue on an empty verdict instead of a "
                          "written one -- tolerate it and let the fallback take the lane")

    for job in LANE_JOBS:
        block = jobs.get(job) or []
        test = escape_test(job)
        escaped = (submapping(block, "concurrency").get("group") or "") != LANE_GROUP
        for step in steps_of(block):
            code = step_code(step)
            if not any(n in code for n in MEASURING_NEEDLES):
                continue
            guard = step_if(step)
            if guard is None or test not in guard:
                errors.append(f"`{job}` runs a step that can load the lane host (`"
                              + "`, `".join(n for n in MEASURING_NEEDLES if n in code)
                              + f"`) without the `if: {test}` guard"
                              + (" -- and its group escapes the lane, so this measures under "
                                 "contention instead of not measuring" if escaped else ""))

    e11 = jobs.get("loadtest-e1-1") or []
    reporting = [s for s in steps_of(e11) if "load-lane decision" in step_code(s)]
    if not reporting:
        errors.append("`loadtest-e1-1` has no `load-lane decision` step: a green check that "
                      "measured nothing must say so in the run, not in a comment later")
    else:
        guard = step_if(reporting[0])
        if guard is not None and "always()" not in guard:
            errors.append("`loadtest-e1-1`'s decision step is gated by an `if:` -- on the skip "
                          "path the run would then say nothing about why nothing was measured")
    return errors


def workflow_concurrency(text):
    """The top-level `concurrency:` mapping as {key: value}; {} when absent.

    Column 0 for the key, indent 2 for its children -- the same indentation
    reading used for the job blocks, so the check stays dependency-free.
    """
    out, seen = {}, False
    for line in text.splitlines():
        if not seen:
            if re.fullmatch(r"concurrency:\s*", line):
                seen = True
            continue
        if re.fullmatch(r"\s*", line) or re.fullmatch(r"\s*#.*", line):
            continue
        if re.fullmatch(r"[A-Za-z0-9_-]+:.*", line):
            break  # next top-level key: the block ended
        m = re.fullmatch(r"  ([a-zA-Z_-]+):\s*(.+?)\s*", line)
        if m:
            out[m.group(1)] = m.group(2).strip("'\"")
    return out


def check_workflow_concurrency(wc):
    """Rule 5. An absent block is allowed -- that is the pre-OBI-313 state,
    where nothing can be cancelled at workflow level. Safe, if it leaves stale
    runs holding lane places. A present block has to be exact."""
    errors = []
    if not wc:
        return errors
    group = wc.get("group")
    if group is None:
        return errors + ["workflow-level `concurrency` block has no `group:`"]
    g = group.strip()
    if "${{" not in g or WF_GROUP_PREFIX not in g:
        errors.append(f"workflow-level concurrency.group is {g!r}: it must be an "
                      "expression containing `github.workflow`. A constant or shared "
                      "group name is a repo-wide mutex -- one PR's push would cancel "
                      "another PR's in-flight 150-player gate.")
        return errors
    arms = g.rsplit("||", 1)
    if len(arms) != 2 or WF_RUNID_FALLBACK not in arms[1]:
        errors.append(f"workflow-level concurrency.group {g!r} must fall back to "
                      "`github.run_id` for non-`pull_request` events (`... || "
                      "github.run_id`): without it a `push` to `main` shares a group "
                      "with the next main push, and a gate measured on `main` becomes "
                      "cancellable.")
    elif not any(tok in arms[0] for tok in WF_PR_SCOPED):
        errors.append(f"workflow-level concurrency.group {g!r} is not PR-scoped: the "
                      f"`pull_request` arm must contain one of {list(WF_PR_SCOPED)}, "
                      "or every PR shares one group and cancels across PRs.")

    cip = wc.get("cancel-in-progress")
    if cip is None:
        return errors  # GitHub's default is false: nothing gets cancelled
    v = cip.strip()
    if not (v.startswith("${{") and v.endswith("}}")):
        return errors + [f"workflow-level concurrency.cancel-in-progress is {v!r}: it "
                         "must be an expression keyed on `github.event_name == "
                         "'pull_request'`. A literal `true` cancels `push` runs to "
                         "`main` and any re-run of a gate."]
    body = v[3:-2].strip()
    if not WF_PR_TEST.search(body):
        errors.append(f"workflow-level concurrency.cancel-in-progress {v!r} does not "
                      "test `github.event_name == 'pull_request'`, so it cannot be "
                      "shown false for `push` and `workflow_dispatch`.")
    if "!=" in body:
        errors.append(f"workflow-level concurrency.cancel-in-progress {v!r} uses `!=`: a "
                      "negated test is true for at least one non-`pull_request` event, "
                      "which is exactly the run OBI-313 must never cancel.")
    if "||" in body:
        errors.append(f"workflow-level concurrency.cancel-in-progress {v!r} uses `||`, "
                      "which can only widen cancellation beyond `pull_request`.")
    stray = sorted({q for q in re.findall(r"['\"]([^'\"]*)['\"]", body)} - {"pull_request"})
    if stray:
        errors.append(f"workflow-level concurrency.cancel-in-progress {v!r} mentions "
                      f"{stray}: only `'pull_request'` may appear, so nothing that is "
                      "true for `push`/`workflow_dispatch` can be smuggled in.")
    for ev in WF_OTHER_EVENTS:
        if re.search(rf"event_name\s*==\s*['\"]{ev}['\"]", body):
            errors.append(f"workflow-level concurrency.cancel-in-progress {v!r} is true "
                          f"for `{ev}`: only a superseded `pull_request` run may be "
                          "cancelled.")
    return errors


def on_block(text):
    """The child lines of the top-level `on:` mapping, in order."""
    lines = text.splitlines()
    starts = [i for i, l in enumerate(lines) if re.fullmatch(r"(?:^on:|^true:)\s*", l)]
    if not starts:
        return []
    block = []
    for line in lines[starts[0] + 1:]:
        if re.fullmatch(r"[A-Za-z0-9_-]+:.*", line):
            break  # next top-level key
        block.append(line)
    return block


def on_trigger_keys(text):
    """Event names this workflow fires on, from the `on:` block.

    Only the block's own children count (two-space keys), so a `types:` list or a
    `- cron:` entry is never mistaken for an event.
    """
    keys = []
    for line in on_block(text):
        m = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*.*", line)
        if m:
            keys.append(m.group(1))
    return keys


def on_pull_request_types(text):
    """`on.pull_request.types` as a set.

    Empty set = no `types:` key = GitHub fires on *every* activity type;
    None = `pull_request` is not a trigger of this workflow at all.
    """
    block = on_block(text)
    idx = [i for i, l in enumerate(block)
           if re.fullmatch(r"  (?:pull_request|pull_request_target):\s*", l)]
    if not idx:
        return None
    children = []
    for line in block[idx[0] + 1:]:
        if re.fullmatch(r"  [A-Za-z0-9_-]+:\s*", line):
            break  # next event key
        children.append(line)
    for line in children:
        m = re.fullmatch(r"    types:\s*\[?([^\]]*)\]?", line)
        if m and m.group(1).strip():
            return {x.strip().strip("'\"") for x in m.group(1).split(",") if x.strip()}
    return set()


def check_supersede_scope(text, wc):
    """Rule 6. A PR-only workflow-level cancel is only safe on a commit-only
    trigger: with `types:` omitted GitHub fires `pull_request` for *every*
    activity, so `labeled` / `assigned` / `edited` / `review_requested` would
    cancel that PR's own in-flight 150-player gate and take a fresh lane place
    for a diff that had not changed. A label is not a superseded commit."""
    cip = (wc.get("cancel-in-progress") or "").strip()
    if "pull_request" not in cip or cip.lower() == "false":
        return []  # nothing is cancelled per PR -> nothing to narrow
    types = on_pull_request_types(text)
    if types is None:
        return []  # no PR trigger at all; the cancel arm is inert
    if not types:
        return ["the workflow-level block cancels superseded `pull_request` runs, but "
                "`on.pull_request` has no `types:` -- GitHub then fires on *every* "
                "activity type, so labeling or re-reviewing a PR would cancel its own "
                "in-flight `loadtest-e1-1`. Restrict it to "
                f"{sorted(COMMIT_TYPES)}."]
    errs = []
    missing = sorted(MUST_RUN_ON - types)
    if missing:
        errs.append(f"`on.pull_request.types` dropped {missing}: a required check has to "
                    "run on the first commit and on every commit after it, so narrowing "
                    "the trigger cannot be used to skip the gate")
    extra = sorted(types - COMMIT_TYPES)
    if extra:
        errs.append(f"`on.pull_request.types` still fires on {extra}: those activities "
                    "change nothing about the commit, and with the workflow-level cancel "
                    "each one would kill that PR's running gate and take a fresh lane "
                    f"place. Only {sorted(COMMIT_TYPES)} may appear.")
    return errs


def repo_root(workflow_path):
    """Repo root as seen from `.github/workflows/<file>`; falls back to cwd."""
    p = Path(workflow_path).resolve()
    try:
        return p.parents[2]
    except IndexError:
        return Path.cwd()


def declared_toolchain(root):
    """The channel `rust-toolchain.toml` pins, or None if the repo declares none."""
    for name in ("rust-toolchain.toml", "rust-toolchain"):
        cand = Path(root) / name
        if cand.is_file():
            m = re.search(r'^\s*channel\s*=\s*"([^"]+)"', cand.read_text(), re.M)
            if m:
                return m.group(1)
    return None


def check_toolchain_pins(text, root):
    """Rule 9: a job may not install a compiler the repo does not declare.

    The toolchain is an input to what the lane measures, and OBI-325 put
    `.github/**` on the runtime-irrelevant list. Both are only true together if
    the workflow is not a *second*, unsynced place to change the compiler: with
    this rule a toolchain bump has to touch `rust-toolchain.toml`, which the
    classifier counts as runtime-relevant, so the bump is measured.
    """
    pins = {}
    for job, block in job_blocks(text).items():
        for line in block:
            if line.lstrip().startswith("#"):
                continue
            m = re.search(r'^\s*toolchain:\s*"?([0-9][^"\s]+)"?\s*$', line)
            if m:
                pins.setdefault(m.group(1), []).append(job)
    errors = []
    want = declared_toolchain(root)
    for got, where in sorted(pins.items()):
        where = ", ".join(f"`{j}`" for j in sorted(set(where)))
        if want is None:
            errors.append(f"{where} install toolchain {got!r} but rust-toolchain.toml "
                          "declares no channel: the measured compiler is pinned only in CI")
        elif got != want:
            errors.append(f"{where} install toolchain {got!r} while rust-toolchain.toml "
                          f"declares {want!r}: CI would measure a compiler nothing in the "
                          "repo pins, and `.github/**` is on the skip list (OBI-325) so the "
                          "bump would never be measured -- change rust-toolchain.toml instead")
    return errors


# Expressions inside a `run:` block are substituted *before the shell sees the
# script* -- including inside shell comments, which the shell never reads but
# Actions already has. `cancelled()`, `always()`, `failure()`, `success()` and
# `no_status()` are only available in `if:` conditions, so writing one in a
# `run:` block is not a wrong step, it is a workflow file that does not compile:
# no job in it runs, and on a `pull_request` event no check run appears at all,
# which is indistinguishable from "CI is stuck". Observed 2026-10-09 on PR #144:
# heads 18fc7ab/c114681 got only `push`-placeholder runs (0 jobs, named after the
# file path, no logs) and `gh pr checks` reported nothing. A comment mentioning
# `if: ${{ !cancelled() }}` inside the classifier's `run:` block was the whole
# cause. Write the expression bare (`if: !cancelled()`) in a script instead --
# rule 4 accepts both forms because GitHub itself does. This is rule 10.
STATUS_FUNCS = ("cancelled(", "always(", "failure(", "success(", "no_status(")


def run_block_lines(text):
    """Line numbers (1-based) that sit inside a `run:` block scalar."""
    lines = text.splitlines()
    inside, indent, out = False, 0, []
    for i, line in enumerate(lines, 1):
        head = re.match(r"^(\s*)(?:-\s+)?\w[^:\n]*:\s*[|>][-+]?\s*$", line)
        if head and re.search(r"\brun:", line):
            inside, indent = True, len(head.group(1))
            continue
        if not inside:
            continue
        if not line.strip():
            out.append(i)
            continue
        if len(line) - len(line.lstrip()) <= indent:
            inside = False
            continue
        out.append(i)
    return out


def check_run_block_expressions(text):
    errors = []
    for lineno in run_block_lines(text):
        line = text.splitlines()[lineno - 1]
        for expr in re.findall(r"\$\{\{(.+?)\}\}", line):
            hit = next((f[:-1] for f in STATUS_FUNCS if f in expr), None)
            if hit:
                errors.append(
                    f"line {lineno}: a `run:` block contains `${{{{ {expr.strip()} }}}}`. "
                    f"`{hit}()` is only available in an `if:` condition, so this is not a "
                    "comment -- it is a workflow file GitHub cannot compile: no job runs, and "
                    "on a pull_request no check run is created at all. Write the expression "
                    "bare in scripts (`if: !cancelled()`) instead of wrapping it.")
    return errors


def read_mudlib_pin(root):
    """(rev, error) from the file that names the world under test.

    `warp.ref` is one payload line -- comments and blanks stripped -- holding a
    full commit SHA. A missing or malformed pin is an error rather than a default.
    The load jobs have no branch to fall back to, and "fall back to warp's main"
    is the exact behaviour OBI-326 removes.
    """
    path = Path(root) / MUDLIB_PIN
    if not path.is_file():
        return None, (f"{MUDLIB_PIN} is missing: the load lane serves its mudlib from a "
                      "second repository, which is an input to the number it prints, so the "
                      "commit has to be named here (rule 11)")
    lines = [l.strip() for l in path.read_text().splitlines()
             if l.strip() and not l.lstrip().startswith("#")]
    if not lines:
        return None, (f"{MUDLIB_PIN} carries only comments: the gate refuses to guess which "
                      "mudlib to serve")
    if len(lines) > 1:
        return None, (f"{MUDLIB_PIN} must hold exactly one line -- the commit SHA -- but carries "
                      f"{len(lines)}: a second rev is a second world the gate could serve")
    rev = lines[0]
    if not PIN_REV_SHA.match(rev):
        return rev, (f"{MUDLIB_PIN} rev={rev!r} is not a full 40-character lowercase commit SHA: "
                     "a branch or tag name can move underneath a run, which is what the pin "
                     "exists to prevent")
    return rev, None


def classifier_module(root):
    """Import the real classifier so a rule can ask it, not paraphrase it.

    None when it cannot be imported: these checks then report the gap instead of
    passing silently (the same reasoning the classifier itself applies to a diff
    it cannot read).
    """
    script = Path(root) / "scripts" / "load-lane-classify.py"
    if not script.is_file():
        return None
    # The guard runs in CI's `hygiene` job and in developers' checkouts; importing
    # a module must not litter a `__pycache__` next to the tree it is checking.
    dont_write = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec = importlib.util.spec_from_file_location("load_lane_classify", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None
    finally:
        sys.dont_write_bytecode = dont_write


def classifier_relevance(root, path):
    """Ask the real classifier whether `path` takes a lane place (None = cannot tell)."""
    module = classifier_module(root)
    if module is None:
        return None
    try:
        return bool(module.classify([path])[0])
    except Exception:
        return None


def check_mudlib_pin(text, root):
    """Rule 11: the mudlib under measurement is pinned, read from one file, stamped.

    Three failures are prevented here and each needs its own check, because
    fixing one is how you create another:

      * the pin file names a commit, not a branch (else "pinned" is a comment);
      * the workflow's external checkout takes its rev from that file, so there is
        no second place to change what gets served, and its repository is the one
        this repo means to measure against;
      * the job verifies what landed and stamps it onto the report, so a
        committed number can be read against the world that produced it.
    """
    errors = []
    _rev, pin_err = read_mudlib_pin(root)
    if pin_err:
        errors.append(pin_err)
    relevant = classifier_relevance(root, MUDLIB_PIN)
    if relevant is None:
        errors.append("cannot ask scripts/load-lane-classify.py whether "
                      f"`{MUDLIB_PIN}` is runtime-relevant: rule 11 needs to know, because a pin "
                      "the classifier cannot see is a mudlib bump that skips the lane")
    elif not relevant:
        errors.append(f"{MUDLIB_PIN} is not runtime-relevant in scripts/load-lane-classify.py: "
                      "bumping the mudlib the lane serves changes what is measured, so it must "
                      "take a lane place like a `Cargo.lock` bump does")

    for job, block in job_blocks(text).items():
        code = "\n".join(l for l in block if not l.lstrip().startswith("#"))
        if not any(needle in code for needle in SERVING_NEEDLES):
            continue
        steps = steps_of(block)
        pin_steps = [s for s in steps if step_key(s, "id") == PIN_STEP_ID]
        if not pin_steps:
            errors.append(f"`{job}` serves a mudlib without reading `{MUDLIB_PIN}`: no step with "
                          f"`id: {PIN_STEP_ID}`, so nothing pins the checkout")
        else:
            pin = pin_steps[0]
            if job in ESCAPE_SOURCE and step_if(pin) != escape_test(job):
                errors.append(f"`{job}`: the `{PIN_STEP_ID}` step is not guarded by "
                              f"`{escape_test(job)}` -- an unguarded step also runs on the skip "
                              "path, so a docs-only PR would fail a gate that never measured "
                              "anything")
            if not PIN_FILE_TOKEN.search(step_code(pin)):
                errors.append(f"`{job}`: the `{PIN_STEP_ID}` step does not read `{MUDLIB_PIN}` -- "
                              "hard-coding a rev in a step, or reading some other file, is a "
                              "comment rather than a pin")
            if "0-9a-f" not in step_code(pin):
                errors.append(f"`{job}`: the `{PIN_STEP_ID}` step does not validate the rev as a "
                              "commit SHA, so a branch name in the pin file would be served "
                              "quietly -- the thing rule 11 exists to stop")
        for step in steps:
            body = step_code(step)
            if not re.search(r"^\s+repository:", body, re.M):
                continue
            if PIN_REPO_LINE not in body:
                errors.append(f"`{job}` checks out an external repository that is not "
                              f"`{MUDLIB_REPO}` (expected the line `{PIN_REPO_LINE}`): the world "
                              "the gate measures is a named input, not a matter of opportunity")
            if PIN_REV_REF not in body:
                errors.append(f"`{job}` checks out `{MUDLIB_REPO}` without pinning its rev from "
                              f"`{MUDLIB_PIN}` (expected `{PIN_REV_REF}`): a floating mudlib "
                              "checkout moves p99 underneath a queue of PRs that skipped the lane "
                              "(OBI-325's blind spot, closed by OBI-326)")
        if not any("rev-parse" in step_code(s) and PIN_FILE_TOKEN.search(step_code(s))
                   for s in steps):
            errors.append(f"`{job}` never re-reads `{MUDLIB_PIN}` to verify the commit it checked "
                          "out: the gate must serve the world the repository names, not the world "
                          "a step output claims")
        for step in steps:
            body = step_code(step)
            if "loom-loadtest" not in body or "--out" not in body:
                continue
            if "--note" not in body or f"{PIN_STEP_ID}.outputs.rev" not in body:
                errors.append(f"`{job}` writes a report without stamping the mudlib rev into it "
                              "(`--note`): a committed p99 that cannot name its inputs cannot be "
                              "compared or bisected (see results/README.md)")
    return errors


def check_drift_backstop(text):
    """Rule 12: the workflow keeps a path to a measurement that no diff can skip.

    OBI-325 made the lane conditional, which is right, and left a consequence: a
    run of irrelevant diffs means `main` can go unmeasured for as long as that run
    lasts, and `warp.ref` bumps -- which change the world under test -- arrive on
    their own schedule. `on.schedule` gives every day a number, and
    `on.workflow_dispatch` gives a release SHA one without faking a commit. Both
    are asserted because both live in `.github/**`, which the classifier counts
    irrelevant: without rule 12 the backstop could be removed by a PR that never
    entered the lane.

    The trigger alone is not enough: a backstop that cannot go green measures
    nothing, so rule 13 also requires every job to answer for an event that carries
    no commit range -- see `check_rangeless_audit`.
    """
    keys = on_trigger_keys(text)
    errors = []
    if "schedule" not in keys:
        errors.append("`on.schedule` is gone: after the OBI-325 skip a run of "
                      "runtime-irrelevant diffs leaves `main` unmeasured, and a "
                      "warp-side drift then has no date to land on -- it lands on "
                      "whoever's PR happens to be measured next (rule 12)")
    if "workflow_dispatch" not in keys:
        errors.append("`on.workflow_dispatch` is gone: results/README.md requires a "
                      "measured green `loadtest-e1-1` for a release SHA, and that "
                      "candidate may legitimately have skipped the lane -- without a "
                      "dispatch the only way to get the number is an empty commit "
                      "that forces a lane run (rule 12)")
    return errors


def check_rangeless_audit(text):
    """Rule 13: a run with no commit range must not be asked to audit all history.

    `schedule` and `workflow_dispatch` carry no `base` and no `before`. The first
    dispatch of this workflow (run 37752599276) went red on `dco` for exactly that
    reason: its fallback was `scripts/check-dco.sh HEAD`, which lists every commit
    reachable from the tip, and two of them (`a1d3dc4`, `7f1b074`) are authored by
    the founder and signed off by the agent who wrote them -- the rule compares the
    trailer to the author, so that scan fails on the same pair every time it runs.
    Not merely strict: unsatisfiable. And an unsatisfiable check on a nightly is
    noise that trains everyone to skip the one run whose colour is supposed to mean
    "the world drifted". Whether an agent's sign-off satisfies DCO for a
    human-authored commit is a policy question for the CTO; a scheduled run must not
    answer it by re-auditing merged history.

    So: every `check-dco.sh` call must name a bounded set of commits. A range with
    `..` is bounded. A bare rev is bounded only where the step has just proved that
    rev has no parent (`git rev-parse -q --verify "$AFTER^"`), which is the
    first-commit/initial-push case where the whole history *is* one commit. `HEAD`
    is never acceptable: in a `fetch-depth: 0` checkout it is the whole repository.
    """
    errors = []
    for job, block in job_blocks(text).items():
        for step in steps_of(block):
            code = step_code(step)
            if "check-dco.sh" not in code:
                continue
            bounded_one = 'rev-parse -q --verify "$AFTER^"' in code
            for m in re.finditer(r'check-dco\.sh(?:\s+")([^"\n]*)"|check-dco\.sh\s+(\S+)', code):
                arg = (m.group(1) or m.group(2) or "").strip()
                if not arg or ".." in arg:
                    continue
                if arg == "$AFTER" and bounded_one:
                    continue
                errors.append(f"`{job}` audits sign-off over `{arg}`, which is every commit "
                              "reachable from one rev: scheduled and dispatched runs carry no "
                              "commit range, and the merged history contains commits whose "
                              "sign-off does not name their author, so the nightly could never "
                              "go green -- name the commits the run stands on as a range "
                              "(rule 13)")
    return errors


def _py_literal(root, name):
    """A module-level `NAME = <literal>` in the proof script, or None."""
    path = Path(root) / IDENTITY_SCRIPT
    if not path.is_file():
        return None
    m = re.search(rf"^{name}\s*=\s*(.+?)\s*$", path.read_text(), re.M)
    if not m:
        return None
    try:
        return ast.literal_eval(m.group(1))
    except (ValueError, SyntaxError):
        return None


def _uses_of(steps, prefix):
    """The first `uses:` value starting with `prefix` among these steps."""
    for step in steps:
        for line in step:
            m = re.search(rf"uses:\s*({re.escape(prefix)}[^\s]+)", line)
            if m and not line.lstrip().startswith("#"):
                return m.group(1)
    return None


def check_identity_stage(jobs, text, root):
    """Rules 14 and 15 (OBI-397): the identity proof must predict the gate, and
    may only be asked about what a content hash can settle.

    Two distinct failures are being prevented, and each needs its own half:

    14. *drift*. The proof is evidence about `loadtest-e1-1`, so it has to be the
        same build: same command string, same toolchain action and pin, same
        cache action, same artefacts. A proof that builds `-p loom-cli` alone, or
        under a different rustc, is silent about the load bot -- and the failure
        is invisible, because the verdict still reads `same=true`. The job must
        also outlive its own caps: `classify` has no `timeout-minutes` slack left
        by the two builds means Actions kills the *decider*, which writes no
        output, and the gate queues on an empty verdict -- correct direction, but
        paid for with 30 minutes of somebody's queue. And the merge may run in
        only one direction: a matching hash clears a "relevant", nothing turns a
        table "skip" into a measurement.
    15. *scope*. `crates/*/src/**` is where the table is blind, so it is also the
        only place a hash is allowed to answer -- and a hash answers only for the
        two binaries. Any of `UNHASHABLE_WITNESSES` beside a source file must make
        the whole diff ineligible. These are assertions about the *shipped*
        classifier module, imported and called, so a widening of its source glob
        that swallows `warp.ref` fails `hygiene` instead of quietly retiring the
        OBI-326 pin from the lane.
    """
    errors = []
    block = jobs.get(CLASSIFIER)
    if block is None:
        return [f"`{CLASSIFIER}` job is missing: rule 14 has no stage-two proof to check"]
    try:
        src = (root / IDENTITY_SCRIPT).read_text()
    except OSError as exc:
        src = ""
        errors.append(f"cannot read {IDENTITY_SCRIPT}: {exc}")
    steps = steps_of(block)
    code = "\n".join(l for l in block if not l.lstrip().startswith("#"))
    proof = [s for s in steps if IDENTITY_SCRIPT in step_code(s)]
    if not proof:
        return [f"`{CLASSIFIER}` never calls {IDENTITY_SCRIPT}: the workflow says the lane may "
                "be skipped on a build-identity proof, and no job runs that proof -- which is "
                "the same claim with no evidence behind it"]
    step = proof[0]
    pcode = step_code(step)
    if step_key(step, "id") != PROOF_STEP_ID:
        errors.append(f"the identity proof step is `{step_key(step, 'id')}`, expected "
                      f"`{PROOF_STEP_ID}`: the merge reads its answer from that id")
    # The proof must not be able to fail the decider: it is either tolerated or
    # ends by writing its own verdict. (`classify` failing = no output = the gate
    # queues blind, which is expensive and unexplained.)
    last = [l.strip() for l in pcode.splitlines() if l.strip()][-1:]
    if step_key(step, "continue-on-error") != "true" and last != ["exit 0"]:
        errors.append("the identity proof step can fail the `classify` job: a proof that cannot "
                      "run must leave `same` unset so the merge takes the lane, not kill the "
                      "job that writes the verdict")
    # Which steps belong to stage two: the proof itself, the toolchain and cache it
    # needs, and anything already gated on the scope flag. All of them must carry
    # both halves of the candidate guard, and the *table* step must carry neither
    # -- a push to `main` needs a verdict from stage one even though stage two is
    # not allowed to speak there.
    stage2 = [s for s in steps if s is step
              or "outputs.identity" in (step_if(s) or "")
              or any(_uses_of([s], a) for a in E1_PARITY_ACTIONS)]
    for s in stage2:
        guard = step_if(s) or ""
        for half in CANDIDATE_GUARD:
            if half not in guard:
                errors.append(f"a stage-two step in `{CLASSIFIER}` (`"
                              + (step_key(s, "name") or step_key(s, "uses") or "?")
                              + f"`) is not limited by `{half}`: the proof would run on a diff "
                                "it is not allowed to judge, or on a `main` push, where rule 8 "
                                "requires a real measured p99")
    table = [s for s in steps if "load-lane-classify.py" in step_code(s)]
    for s in table:
        if step_if(s) is not None:
            errors.append(f"`{CLASSIFIER}`'s table step is gated by `if: {step_if(s)}`: a run "
                          "that skips it publishes no verdict, and the gate would then queue on "
                          "an empty answer instead of a written one")
    if "--base" not in pcode or "--head" not in pcode:
        errors.append(f"the identity proof does not name both ends of the range: comparing the "
                      f"working tree to itself is not a proof")
    if "github.event.pull_request.base.sha" not in code or \
            "github.event.pull_request.head.sha" not in code:
        errors.append("the identity proof's range does not come from the event's base and head "
                      "SHA: a ref name can move underneath a run, and `base...head` computed "
                      "from `origin/main` is not this PR's merge base")

    e11 = jobs.get("loadtest-e1-1") or []
    e11_code = "\n".join(l for l in e11 if not l.lstrip().startswith("#"))
    build_cmd = _py_literal(root, "BUILD_CMD")
    if build_cmd is None:
        errors.append(f"cannot read `BUILD_CMD` from {IDENTITY_SCRIPT}: the proof's build is "
                      "unpinned, so it proves nothing about what was measured")
    elif build_cmd.strip() not in e11_code:
        errors.append(f"the identity proof builds `{build_cmd}`, which is not what "
                      "`loadtest-e1-1` builds: a hash over a different command says nothing "
                      "about the binary the lane runs")
    if E1_BUILD_MARK not in e11_code:
        errors.append(f"`loadtest-e1-1` no longer runs `{E1_BUILD_MARK}`: rule 14's parity check "
                      "is comparing the proof to a gate that changed")
    hashed_list = list(_py_literal(root, "ARTIFACTS") or ())
    hashed = {str(a).rsplit("/", 1)[-1] for a in hashed_list}
    for art in E1_ARTIFACTS:
        if art not in hashed:
            errors.append(f"the identity proof hashes {hashed_list}, which omits `{art}` "
                          "-- a program E1.1 runs and no job compared")
    for prefix in E1_PARITY_ACTIONS:
        want, got = _uses_of(steps_of(e11), prefix), _uses_of(steps, prefix)
        if got is None:
            errors.append(f"the identity proof runs without `{prefix}`: the same build command "
                          "under a different toolchain or no dependency cache is not the same "
                          "build the gate performed")
        elif want is not None and want != got:
            errors.append(f"the identity proof uses `{got}` but `loadtest-e1-1` uses `{want}`: "
                          "the proof must run the gate's own action pin, not a nearby one")
    # The runner image is not a build image. `loadtest-e1-1` installs its own C
    # toolchain before building; the proof must run the same invocation, or its
    # first `cc` call dies (`libc` build script, rc=101) and stage two returns
    # `same=false` forever -- safe, silent, and indistinguishable from "this repo
    # has no test-only diffs", which is the false conclusion the first live run
    # (PR #175, job 113823165936) would have led to.
    def tools_line(step):
        """The tool bootstrap a step runs, or None. Compared as the invocation
        rather than the YAML line: one job writes `- run: scripts/…`, the other
        `run: scripts/…`, and that difference is indentation, not tools."""
        m = re.search(E1_TOOLS_MARK + r".*", step_code(step) or "")
        return m.group(0).strip() if m else None

    gate_tools = [tools_line(s) for s in steps_of(e11) if tools_line(s)]
    if gate_tools:
        want = gate_tools[0]
        if want not in {tools_line(s) for s in stage2}:
            errors.append(f"the identity proof does not run the gate's own tool bootstrap "
                          f"(`{want}`): a build environment the gate had to install is not a "
                          "build environment the proof can assume")

    # A hash is only evidence about the binary *this build wrote*. Cargo decides
    # freshness from mtimes, so a shared or restored cache can leave a crate
    # unbuilt and the two ends compare as copies of one file -- a wrong `same=true`
    # that skips a required measurement. The proof must therefore clear the two
    # artefacts first and witness that each build re-created them. `--release` is
    # load-bearing: `cargo clean -p x` with no profile cleans the dev artifacts
    # and reports "Removed 0 files" on a release tree -- exit 0, nothing removed.
    clean_cmd = _py_literal(root, "CLEAN_CMD")
    if clean_cmd is None:
        errors.append(f"{IDENTITY_SCRIPT} has no `CLEAN_CMD`: it hashes whatever is already in "
                      "`target/` without proving this build wrote it, and a cached artefact "
                      "makes two ends of one file look like evidence")
    else:
        if "--release" not in clean_cmd and "--profile release" not in clean_cmd:
            errors.append(f"the proof's clean is `{clean_cmd}`: with no profile, cargo cleans "
                          "the dev artifacts, reports \"Removed 0 files\", exits 0, and leaves "
                          "both release artefacts stale -- and a stale file at both ends hashes "
                          "as `same=true`, which is a wrong pass")
        for art in hashed_list:
            name = str(art).rsplit("/", 1)[-1]
            if f"-p {name}" not in clean_cmd:
                errors.append(f"the proof hashes `{art}` but its clean (`{clean_cmd}`) never "
                              f"names `{name}`: that artefact can survive from an earlier build "
                              "and be reported as this end's output")
        body = re.search(r"def build_and_hash(?:.|\n)*?\n    (?:head_art|def |return )", src)
        seg = body.group(0) if body else ""
        if not seg:
            errors.append(f"cannot read `build_and_hash` from {IDENTITY_SCRIPT}: the check that "
                          "each artefact was rewritten by the build it is attributed to cannot "
                          "be verified, so the hash is unattributed")
        elif seg.find("clean_cmd") < 0 or seg.find("build_cmd") < 0 \
                or seg.find("clean_cmd") > seg.find("build_cmd") or seg.count("mtime") < 2:
            errors.append("the proof must clear the artefacts, assert they are absent, build, "
                          "and assert each was written (mtime witness before and after) -- in "
                          "that order; otherwise `same=true` can describe a binary nobody built")
    cap = _py_literal(root, "BUILD_TIMEOUT")
    job_to = scalar(block, "timeout-minutes")
    m = re.search(r"\btimeout\s+(?:-k\s+\d+\s+)?(\d+)\s+python3", pcode)
    if not cap or not m or not (job_to or "").isdigit():
        errors.append("the identity proof's timeouts cannot be verified: it needs a per-build "
                      "cap in the script and a `timeout` around it in the step, inside a "
                      "`timeout-minutes` budget that exceeds both")
    elif 2 * cap > int(m.group(1)):
        errors.append(f"the identity proof step is capped at {m.group(1)} s, which is less than "
                      f"2 x the script's own {cap} s per-build cap: the outer kill fires first "
                      "and the answer is 'not proven' for a diff that only needed patience")
    elif int(m.group(1)) + 300 > 60 * int(job_to):
        errors.append(f"`{CLASSIFIER}`'s timeout-minutes ({job_to}) does not exceed the proof's "
                      f"{m.group(1)} s cap plus setup: Actions would then kill the *decider*, "
                      "leaving no output and a gate queueing on an empty verdict")

    verdict = [s for s in steps if step_key(s, "id") == VERDICT_STEP_ID]
    if not verdict:
        errors.append(f"`{CLASSIFIER}` has no `{VERDICT_STEP_ID}` step: stage one and stage two "
                      "need one place where the lane verdict is decided, or the proof output is "
                      "a number nobody reads")
    else:
        vcode = step_code(verdict[0])
        if step_if(verdict[0]) is not None:
            errors.append(f"`{CLASSIFIER}`'s `{VERDICT_STEP_ID}` step carries an `if:`: when it "
                          "is skipped the job publishes no verdict at all, and an absent output "
                          "is a worse answer than a written 'not proven'")
        for needle in ('"$SAME" = true', '"$SCOPE" = true', '"$EVENT" = pull_request',
                       '"$runtime" != false'):
            if needle not in vcode:
                errors.append(f"the `{VERDICT_STEP_ID}` merge no longer requires `{needle}`: "
                              "the proof could then skip the lane on an answer it was not "
                              "entitled to give (a missing output, an out-of-scope diff, a "
                              "table skip, or a `main` push)")
        if "runtime=$runtime" not in vcode:
            errors.append(f"`{CLASSIFIER}`'s `{VERDICT_STEP_ID}` step does not write the merged "
                          "verdict to its outputs")
        if "runtime=true" in vcode:
            errors.append(f"`{CLASSIFIER}`'s `{VERDICT_STEP_ID}` step can write `runtime=true`: "
                          "stage two is allowed to *clear* a lane verdict a build cannot move, "
                          "never to force a measurement the table already waved through -- an "
                          "upgrade would make every docs PR pay for a build to earn a lane place "
                          "it does not need")

    module = classifier_module(root)
    if module is None:
        errors.append(f"cannot import scripts/load-lane-classify.py to verify stage-two scope "
                      f"(rule 15): the {IDENTITY_SCRIPT} proof's eligibility set is unchecked")
    else:
        try:
            if not module.identity_candidate([SOURCE_WITNESS]):
                errors.append("the classifier refuses to let a pure-source diff be proven: "
                              "stage two would never run, and the lane would still be paid for "
                              "by test-only changes")
        except AttributeError:
            errors.append("scripts/load-lane-classify.py has no `identity_candidate`: the "
                          "workflow gates on an eligibility rule the classifier does not have")
        for w in UNHASHABLE_WITNESSES:
            try:
                ask = module.identity_candidate([SOURCE_WITNESS, w])
            except AttributeError:
                break
            if ask:
                errors.append(f"`{w}` is hash-judgeable beside a source file: the proof would "
                              "clear the lane on two binaries while this path changes what the "
                              "gate measures")
            if not classifier_relevance(root, w):
                errors.append(f"`{w}` is on the irrelevance allow-list *and* excluded from "
                              "stage two: check which of the two is right")
        # The scope rule's `IDENTITY_NEVER` is the list of source files whose
        # bytes do not all come from the file itself. That list is only sound if
        # it is *complete*, and completeness is not a thing you can remember -- so
        # it is looked up: every `include!`/`include_str!` of something the build
        # generates (`OUT_DIR`) in any crate source must be named, or the proof
        # would hash two checkouts that differ in a file neither one contains.
        try:
            never = set(module.IDENTITY_NEVER)
        except AttributeError:
            errors.append(f"{CLASSIFIER} has no `IDENTITY_NEVER`: rule 15 cannot check the "
                          "generated-source exclusions")
            never = set()
        if never:
            for path in sorted(root.glob("crates/*/src/**/*.rs")):
                rel = path.relative_to(root).as_posix()
                try:
                    txt = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if re.search(r'include!\s*\(\s*concat!\s*\(\s*env!\s*\(\s*"OUT_DIR"', txt):
                    if rel not in never:
                        errors.append(f"`{rel}` `include!`s a build-generated file and is not "
                                      f"in `IDENTITY_NEVER`: the identity proof would compare "
                                      "two checkouts whose generated bytes come from outside "
                                      "the range it is hashing")
    return errors


def check_text(text, root="."):
    jobs = job_blocks(text)
    wc = workflow_concurrency(text)
    errors = check_workflow_concurrency(wc) + check_supersede_scope(text, wc)

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
        errors += lane_group_error(job, got.get("group"))
        if got.get("cancel-in-progress") != "false":
            errors.append(f"`{job}` concurrency.cancel-in-progress is "
                          f"{got.get('cancel-in-progress')!r}, expected 'false' "
                          "(never cancel a measurement mid-flight)")
        if got.get("queue") != "max":
            errors.append(f"`{job}` concurrency.queue is {got.get('queue')!r}, "
                          "expected 'max' (pending runs must queue, not be "
                          "cancelled and replaced)")
        want = MIN_TIMEOUT.get(job)
        if want is not None:
            raw = scalar(block, "timeout-minutes")
            ok = raw is not None and raw.isdigit() and int(raw) >= want
            if not ok:
                errors.append(f"`{job}` timeout-minutes is {raw!r}, expected >= {want}: "
                              "a host under load must end the gate with a measured "
                              "p99, not a cancellation")

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
        val = submapping(block, "concurrency").get("group") or ""
        if holder_group.search(code) or LANE_GROUP in val:
            errors.append(f"`{job}` must not join {LANE_GROUP!r}: unrelated work would "
                          "hold up the latency gates")

    for job in REQUIRED_JOBS:
        if job not in jobs:
            errors.append(f"required check `{job}` is missing from the workflow "
                          "(branch protection lists it)")
            continue
        block = jobs[job]
        allowed = [CLASSIFIER] if job == "loadtest-e1-1" else []
        deps = needs_of(block)
        if deps != allowed:
            errors.append(f"required check `{job}` has `needs: {deps}`, expected `{allowed or []}`: "
                          "an upstream failure would *skip* it, and GitHub counts a skipped "
                          "required check as passing -- a green that measured nothing. "
                          f"`{CLASSIFIER}` is the one exception, and only beside the "
                          f"`if: ${{ GATE_IF }}` below plus rule 8.")
        cond = if_expression(scalar(block, "if"))
        if job == "loadtest-e1-1":
            # The gate needs `needs: classify` and `if: !cancelled()` as a pair.
            # Either half alone is the fail-open: no `if:` means a dead classifier
            # skips it, any other expression can skip it too.
            if cond != GATE_IF:
                errors.append(f"required check `loadtest-e1-1` has `if: {cond}`, expected "
                              f"`{GATE_IF}`: anything else (including no `if:` at all, which "
                              "is GitHub's `success()`) lets an upstream job *skip* the gate, "
                              "and a skipped required check is counted as passing")
        elif cond is not None:
            errors.append(f"required check `{job}` has `if:` -- it can be skipped, and a "
                          "skipped required check counts as passing; only `loadtest-e1-1` may "
                          f"carry `{GATE_IF}`, and only because rule 8 keeps its `needs:` "
                          "unable to change the verdict")
        if scalar(block, "continue-on-error") == "true":
            errors.append(f"required check `{job}` sets continue-on-error: true")

    errors += check_classifier(jobs)
    errors += check_identity_stage(jobs, text, root)
    errors += check_toolchain_pins(text, root)
    errors += check_run_block_expressions(text)
    check_e11_verdict_isolation(jobs, errors)
    errors += check_mudlib_pin(text, root)
    errors += check_drift_backstop(text)
    errors += check_rangeless_audit(text)

    e11 = [l for l in jobs.get("loadtest-e1-1", []) if not l.lstrip().startswith("#")]
    body = "\n".join(e11)  # comments excluded: the flags must be in the command
    for flag in SLA_FLAGS:
        if flag not in body:
            errors.append(f"`loadtest-e1-1` no longer passes `{flag}`: the E1.1 gate "
                          "must keep measuring 150 players and failing on an SLA miss")

    return errors


def check_e11_verdict_isolation(jobs, errors):
    """Rule 7: nothing but the p99 verdict may fail `loadtest-e1-1`.

    Requires the three-beat shape in the gate's shell step: capture the
    loadtest exit status, disable errexit for everything that runs after the
    verdict, and re-assert the captured status as the step's last act. Reads
    shell lines with comments stripped, so prose about `exit $status` or
    `set +e` cannot satisfy it -- that is how the check notices the shape rot
    instead of being fooled by the comment that explains it.
    """
    block = jobs.get("loadtest-e1-1")
    if block is None:
        return  # rule 4 already reported the missing required check
    shell = [l for l in block if not l.lstrip().startswith("#")]
    capture = next((i for i, l in enumerate(shell) if E11_STATUS_CAPTURE in l), None)
    if capture is None:
        errors.append("`loadtest-e1-1` no longer captures the loadtest exit status "
                      "(`status=$?`): without it the gate cannot separate 'the world "
                      "missed its SLA' from 'some shell command in this step failed'")
        return
    exits = [i for i, l in enumerate(shell) if E11_VERDICT_EXIT.match(l)]
    if not exits:
        errors.append("`loadtest-e1-1` no longer ends its gate step with "
                      "`exit $status`: the captured p99 verdict is dropped, so the "
                      "step's exit code comes from whatever command ran last")
        return
    guards = [i for i, l in enumerate(shell) if E11_ERREXIT_OFF.match(l)]
    if not any(capture < g < exits[-1] for g in guards):
        errors.append("`loadtest-e1-1` runs its post-verdict evidence tail under "
                      "errexit: one non-zero grep/awk in the reporting section aborts "
                      "the step after the p99 verdict was already computed (main run "
                      "37862921160 went red on a PASS this way)")


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


def _replace(text, needle, repl, nth=0):
    """Replace `needle` *inside* the nth non-comment line that holds it.

    Unlike `_sub` this keeps the line's indentation, so a value mutation cannot
    pass the self-test merely by corrupting the document structure.
    """
    out, hits = [], 0
    for line in text.splitlines(keepends=True):
        if needle in line and not line.lstrip().startswith("#"):
            if hits == nth:
                line = line.replace(needle, repl)
            hits += 1
        out.append(line)
    assert hits > nth, f"self-test needle not found: {needle!r}"
    return "".join(out)


def _drop_concurrency(text, job):
    lines = text.splitlines(keepends=True)
    i = next(k for k, l in enumerate(lines) if l == f"  {job}:\n")
    j = next(k for k in range(i, len(lines)) if lines[k] == "    concurrency:\n")
    return "".join(lines[:j] + lines[j + 4:])


def _unguard(text, job, needle):
    """Delete the step-level `if:` guard of the first step of `job` naming `needle`.

    `needle` must be on the step's own first line (`- name:`/`- run:`), because
    the guard is a line of that same step, and step keys sit at indent 8.
    """
    lines = text.splitlines(keepends=True)
    i = next(k for k, l in enumerate(lines) if l == f"  {job}:\n")
    j = next((k for k in range(i + 1, len(lines))
              if re.match(r"  [A-Za-z0-9_-]+:$", lines[k])), len(lines))
    h = next((k for k in range(i, j)
              if needle in lines[k] and not lines[k].lstrip().startswith("#")), None)
    if h is None:
        raise AssertionError(f"_unguard: {needle!r} not found in {job}")
    for k in range(h + 1, min(h + 4, j)):
        if re.match(r"        if:\s*needs\.", lines[k]):
            return "".join(lines[:k] + lines[k + 1:])
    raise AssertionError(f"_unguard: no lane guard under {needle!r} in {job}")


def _prepend(text, job, prop):
    return text.replace(f"  {job}:\n", f"  {job}:\n{prop}", 1)


# The three lane groups, in file order (`bench`, `loadtest-smoke`,
# `loadtest-e1-1`), each keyed on the verdict of the job it depends on.
LANE_GROUPS = ["needs.loadtest-smoke.outputs.runtime != 'false'",
               "needs.loadtest-e1-1.outputs.runtime != 'false'",
               "needs.classify.outputs.runtime != 'false'"]


def _group_line(src):
    return ("      group: ${{ needs." + src + ".outputs.runtime != 'false' && "
            "'loom-ci-load-lane' || format('loom-ci-load-lane-not-required-{0}', "
            "github.run_id) }}\n")


MUTANTS = [
    ("cancel-in-progress: true", lambda t: _sub(t, "cancel-in-progress: false",
                                                "      cancel-in-progress: true\n")),
    ("cancel-in-progress as an expression",
     lambda t: _sub(t, "cancel-in-progress: false",
                    "      cancel-in-progress: ${{ github.event_name != 'pull_request' }}\n")),
    ("queue: max dropped", lambda t: _sub(t, "queue: max", None)),
    ("group made per-ref", lambda t: _sub(t, f"&& '{LANE_GROUP}' ||",
                                          "      group: ci-${{ github.ref }}\n")),
    ("e1-1 concurrency dropped", lambda t: _drop_concurrency(t, "loadtest-e1-1")),
    ("smoke unchained", lambda t: _sub(t, "needs: loadtest-e1-1", None)),
    ("bench unchained", lambda t: _sub(t, "needs: loadtest-smoke", None)),
    ("bench loses success()", lambda t: _sub(t, "if: github.event_name == 'pull_request' && success()",
                                             "    if: github.event_name == 'pull_request'\n")),
    ("required gate gains needs", lambda t: _sub(t, "needs: classify", "    needs: rust\n")),
    ("required gate made optional",
     lambda t: _prepend(t, "loadtest-e1-1", "    continue-on-error: true\n")),
    # The OBI-325 review's fail-open: `needs: classify` + GitHub's default
    # `success()` means a dead classifier *skips* the gate, and a skipped required
    # check is counted as passing. Only `${{ !cancelled() }}` is allowed.
    ("required gate loses its !cancelled()",
     lambda t: _sub(t, "if: ${{ !cancelled() }}", None)),
    ("required gate if: becomes always()",
     lambda t: _sub(t, "if: ${{ !cancelled() }}", "    if: ${{ always() }}\n")),
    ("required gate if: becomes a needs-condition",
     lambda t: _sub(t, "if: ${{ !cancelled() }}",
                    "    if: ${{ needs.classify.result == 'success' }}\n")),
    ("required gate if: written as success()",
     lambda t: _sub(t, "if: ${{ !cancelled() }}", "    if: success()\n")),
    ("required gate !cancelled() loses its braces",
     lambda t: _sub(t, "if: ${{ !cancelled() }}", "    if: !cancelled\n")),
    ("a non-lane required check gains !cancelled()",
     lambda t: _prepend(t, "rust", "    if: ${{ !cancelled() }}\n")),
    ("SLA flag dropped", lambda t: _sub(t, "--fail-on-sla-miss", None)),
    ("gate timeout cut back to 15",
     lambda t: _sub(t, "timeout-minutes: 30", "    timeout-minutes: 15\n")),
    ("population lowered", lambda t: _sub(t, "--players 150", "            --players 20 \\\n")),
    ("unrelated job joins the lane",
     lambda t: t.replace("jobs:\n", "jobs:\n  noise:\n    concurrency:\n"
                                    "      group: loom-ci-load-lane\n"
                                    "      cancel-in-progress: false\n"
                                    "      queue: max\n"
                                    "    runs-on: ubuntu-latest\n"
                                    "    steps:\n      - run: echo hi\n", 1)),
    ("required check renamed away", lambda t: t.replace("  deny:\n", "  deny-optional:\n", 1)),
    # Workflow-level concurrency (OBI-313). The first six are the shapes the
    # issue names; the last four re-test the lane *beside* the new block -- the
    # hazard this block creates is a job that forbids being killed, and the
    # trigger that could kill it for a label instead of a commit.
    ("workflow-level cancel-in-progress made literal true",
     lambda t: _sub(t, "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
                    "  cancel-in-progress: true\n")),
    ("workflow-level cancel-in-progress also true for push",
     lambda t: _sub(t, "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
                    "  cancel-in-progress: ${{ github.event_name == 'pull_request' || "
                    "github.event_name == 'push' }}\n")),
    ("workflow-level cancel-in-progress true for a ref instead of the event",
     lambda t: _sub(t, "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
                    "  cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}\n")),
    ("workflow-level group loses the run_id fallback",
     lambda t: _sub(t, "group: ${{ github.workflow }}",
                    "  group: ${{ github.workflow }}-${{ github.ref }}\n")),
    ("workflow-level group made a constant name",
     lambda t: _sub(t, "group: ${{ github.workflow }}", "  group: loom-ci-supersede\n")),
    ("workflow-level group not PR-scoped",
     lambda t: _sub(t, "group: ${{ github.workflow }}",
                    "  group: ${{ github.workflow }}-${{ github.event_name == "
                    "'pull_request' && 'all-prs-together' || github.run_id }}\n")),
    ("required gate's own cancel-in-progress flipped beside the workflow block",
     lambda t: _sub(t, "cancel-in-progress: false", "      cancel-in-progress: true\n", nth=2)),
    ("supersede block with the PR trigger left unrestricted",
     lambda t: _sub(t, "    types: [opened, synchronize, reopened]\n", None)),
    ("supersede block with label events back in the trigger",
     lambda t: _sub(t, "types: [opened, synchronize, reopened]",
                    "    types: [opened, synchronize, reopened, labeled]\n")),
    ("supersede trigger narrowed until `synchronize` is gone",
     lambda t: _sub(t, "types: [opened, synchronize, reopened]",
                    "    types: [opened, reopened]\n")),
    ("supersede trigger narrowed until `opened` is gone",
     lambda t: _sub(t, "types: [opened, synchronize, reopened]",
                    "    types: [synchronize, reopened]\n")),
    # Rule 7 (#154/OBI-344). The first two are the shape main run 37862921160
    # actually broke.
    ("E1.1 evidence tail put back under errexit",
     lambda t: _sub(t, "set +e", None)),
    ("E1.1 gate step that drops the captured p99 verdict",
     lambda t: _sub(t, "exit $status", "          exit 0\n")),
    ("E1.1 gate step that stops saving the loadtest exit status",
     lambda t: _sub(t, "status=$?", "          echo verdict-captured\n")),
    # Rule 8: the lane escape. Each of these turns "this run cannot change what
    # the gate measures" into either an unmeasured regression (fail open), a
    # queue that skipped runs still sit in, or -- the worst -- a run that
    # skipped the queue and then measured on a loaded host anyway.
    ("lane escape compares == 'true'",
     lambda t: _sub(t, LANE_GROUPS[2],
                    "      group: ${{ needs.classify.outputs.runtime == 'true' && "
                    "'loom-ci-load-lane' || format('loom-ci-load-lane-not-required-{0}', "
                    "github.run_id) }}\n")),
    ("lane escape arm is not run-scoped",
     lambda t: _sub(t, LANE_GROUPS[2],
                    "      group: ${{ needs.classify.outputs.runtime != 'false' && "
                    "'loom-ci-load-lane' || 'loom-ci-load-lane-skipped' }}\n")),
    ("lane escape never names the lane",
     lambda t: _sub(t, LANE_GROUPS[2],
                    "      group: ${{ needs.classify.outputs.runtime != 'false' && "
                    "'nope' || format('nope-{0}', github.run_id) }}\n")),
    ("lane escape reads a verdict it does not depend on",
     lambda t: _sub(t, LANE_GROUPS[1], _group_line(CLASSIFIER))),
    ("classifier gains needs", lambda t: _prepend(t, CLASSIFIER, "    needs: hygiene\n")),
    ("classifier gains a job-level if",
     lambda t: _prepend(t, CLASSIFIER, "    if: github.event_name == 'pull_request'\n")),
    ("classifier made advisory",
     lambda t: _prepend(t, CLASSIFIER, "    continue-on-error: true\n")),
    ("classifier verdict published from another step",
     lambda t: _sub(t, "runtime: ${{ steps.verdict.outputs.runtime }}",
                    "      runtime: ${{ steps.other.outputs.runtime }}\n")),
    ("classifier fail-closed fallback deleted",
     lambda t: _sub(t, "echo 'runtime=true' >>", "            true\n")),
    ("classifier allowed to fail the job",
     lambda t: _sub(t, "--output-file \"$verdict\" --summary || true", None)),
    ("classifier ends on its shell status",
     lambda t: _sub(t, "exit 0", None)),
    ("a lane job installs a toolchain the repo does not declare",
     lambda t: _replace(t, '"1.98.1"', '"1.97.0"', nth=2)),
    ("classifier's package step made fatal",
     lambda t: _sub(t, "continue-on-error: true", None, 0)),
    ("build step loses its lane guard",
     lambda t: _unguard(t, "loadtest-e1-1", "SQLX_OFFLINE=true cargo build")),
    ("bench gate step loses its lane guard",
     lambda t: _unguard(t, "bench", "run: scripts/bench-gate.sh")),
    ("smoke load step loses its lane guard",
     lambda t: _unguard(t, "loadtest-smoke", "run loom serve + loadtest smoke")),
    ("decision step gated away",
     lambda t: _sub(t, "- name: load-lane decision",
                    "      - name: load-lane decision\n"
                    "        if: needs.classify.outputs.runtime == 'false'\n")),
    ("unrelated job joins the lane through an expression",
     lambda t: _prepend(t, "web-client",
                        "    concurrency:\n      group: ${{ true && 'loom-ci-load-lane' "
                        "|| format('x-{0}', github.run_id) }}\n")),
    # Both of these are the 2026-10-09 shape: a *comment* inside a script, which
    # the shell never reads and Actions substitutes anyway. The second one is the
    # exact text that cost PR #144 its check suite.
    ("a status function called inside a run block",
     lambda t: _replace(t, "echo 'runtime=true' >> \"$verdict\"",
                        'echo \'runtime=true\' >> "$verdict"  # the gate uses ${{ !cancelled() }}')),
    ("always() written into a script line",
     lambda t: _replace(t, 'cat "$verdict" >> "$GITHUB_OUTPUT"',
                        'cat "$verdict" >> "$GITHUB_OUTPUT"  # and ${{ always() }} elsewhere')),
    # OBI-326 rule 11: the workflow may not become a second place to change the
    # *world* either. `warp` lives in another repository, so a floating checkout
    # moves p99 while every loom PR skips the lane -- and a pin that is only
    # documented, or only half-read, is that same hazard wearing a comment.
    ("mudlib checkout floats on a branch",
     lambda t: _replace(t, PIN_REV_REF, "ref: main")),
    ("mudlib rev taken from somewhere other than the pin",
     lambda t: _replace(t, PIN_REV_REF, "ref: ${{ github.sha }}")),
    ("mudlib repository swapped for someone else's",
     lambda t: _replace(t, PIN_REPO_LINE, "repository: someone-else/warp")),
    ("mudlib pin step removed",
     lambda t: _sub(t, f"id: {PIN_STEP_ID}", None)),
    ("mudlib pin step loses its lane guard",
     lambda t: _unguard(t, "loadtest-e1-1", "read the pinned mudlib rev")),
    ("mudlib pin step reads a different file",
     lambda t: _replace(t, "PIN_FILE: warp.ref", "PIN_FILE: ci/warp.ref")),
    ("mudlib rev accepted without SHA validation",
     lambda t: _sub(t, "-ne 40", None)),
    ("served mudlib no longer verified against the pin",
     lambda t: _sub(t, "rev-parse HEAD", None)),
    ("report no longer stamped with the mudlib rev",
     lambda t: _sub(t, '--note "mudlib', None)),
    # OBI-326 rule 12: the drift backstop is two triggers, and both are deletable
    # through `.github/**`, which the lane counts irrelevant. Same argument as
    # rule 8 for the toolchain: an invariant that lives on the skip list needs a
    # guard in `hygiene`, which runs on every PR.
    ("nightly drift backstop removed",
     lambda t: _sub(t, "  schedule:", None)),
    ("on-demand measurement path removed",
     lambda t: _sub(t, "  workflow_dispatch:", None)),
    # OBI-326 rule 13: the backstop has to be able to go green. Both mutants are
    # shapes the workflow actually held before the first dispatch run showed `dco`
    # failing on commits merged long before ci.yml existed.
    ("sign-off audit walks all history",
     lambda t: _sub(t, 'scripts/check-dco.sh "$AFTER^..$AFTER"',
                    'scripts/check-dco.sh HEAD')),
    ("range-less path has no bound at all",
     lambda t: _sub(t, 'elif git rev-parse -q --verify "$AFTER^" >/dev/null 2>&1; then',
                    'elif true; then')),

    # OBI-397 rules 14 and 15. Each mutant is a way the identity proof stops being
    # evidence about `loadtest-e1-1` while still printing `same=true` -- or a way it
    # speaks where it has no standing.
    ("identity proof deleted from the decider",
     lambda t: _sub(t, "timeout -k 30 1980 python3 scripts/load-lane-identity.py",
                    "          true \\\n")),
    ("stage two allowed to speak on a main push",
     lambda t: _sub(t, "&& steps.decide.outputs.identity == 'true' && github.event_name == 'pull_request' }}",
                    "&& steps.decide.outputs.identity == 'true' }}")),
    ("proof toolchain pin differs from the gate's",
     lambda t: _replace(t, "        uses: dtolnay/rust-toolchain@02cb101ec7c40f2c49e1d9714d64511d8e1b74de",
                        "        uses: dtolnay/rust-toolchain@0000000000000000000000000000000000000000")),
    ("gate build command changes under the proof",
     lambda t: _sub(t, "- run: SQLX_OFFLINE=true cargo build --release -p loom-cli -p loom-loadtest",
                    "      - run: SQLX_OFFLINE=true cargo build --release -p loom-cli\n", nth=1)),
    ("decider timeout below the proof's own cap",
     lambda t: _sub(t, "    timeout-minutes: 45", "    timeout-minutes: 10")),
    ("merge may raise the verdict instead of only clearing it",
     lambda t: _replace(t, "runtime=false", "runtime=true")),
    # The two shapes of the gap the first live run actually hit (PR #175: the
    # proof died on `libc`'s build script because the runner had no `cc`). Either
    # mutant leaves stage two *silently inert* -- every proof returns `same=false`
    # -- which reads as "this repo has no test-only diffs" and is the false
    # conclusion a reviewer would never see fail.
    ("proof loses the gate's tool bootstrap entirely",
     lambda t: _sub(t, "        run: scripts/ci-ensure-tools.sh", None)),
    ("proof's tool bootstrap drifts from the gate's",
     lambda t: _replace(t, "        run: scripts/ci-ensure-tools.sh cc:build-essential python3:python3-minimal",
                        "scripts/ci-ensure-tools.sh python3:python3-minimal")),
]


def self_test(path):
    text = Path(path).read_text()
    root = repo_root(path)
    failed = 0
    if check_text(text, root):
        print(f"FAIL baseline: {path} does not satisfy its own lane invariants")
        failed += 1
    for name, mutate in MUTANTS:
        errors = check_text(mutate(text), root)
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
    errors = check_text(Path(path).read_text(), repo_root(path))
    if errors:
        print(f"check-ci-load-lane: {len(errors)} problem(s) in {path}")
        for e in errors:
            print(f"  - {e}")
        return 1
    wc = workflow_concurrency(Path(path).read_text())
    supersede = (" and cancels superseded pull_request runs only"
                 if wc.get("cancel-in-progress") else ", no workflow-level cancel")
    print(f"check-ci-load-lane: {path} keeps the {LANE_GROUP} lane and "
          f"{'/'.join(LANE_JOBS)} in DAG order{supersede}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
