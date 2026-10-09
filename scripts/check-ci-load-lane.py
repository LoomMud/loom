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
     `--fail-on-sla-miss`, with enough `timeout-minutes` that host load can
     only make the measurement slow, never get the job cancelled; and
  5. if the workflow has a *workflow-level* `concurrency` block (OBI-313), it
     cancels superseded `pull_request` runs and nothing else. The rule the CTO
     accepted (2026-10-08) is that no required check on a *mergeable candidate*
     may be cancelled; a superseded PR SHA is not a mergeable candidate under
     `strict: true` + `required_linear_history: true`, which is what makes the
     cancel legal. `group` must be
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
  7. in `loadtest-e1-1`, the p99 verdict's `$status` is the *only* thing that
     decides the job: the step ends in `exit $status`, and no diagnostic between
     capturing it and exiting may be able to abort the step first. The step runs
     under Actions' `bash -e {0}` *and* its own `set -uo pipefail`, so a `grep`
     that finds nothing -- which for the stall kinds means "no world-thread
     stall", the best result a gate can produce -- returns 1 through the
     pipeline, `set -e` kills the step, and a passing measurement is reported as
     a failed required check. Run 37862921160 (main, `eaf9ceb`, 2026-10-09) did
     exactly that: `E1.1 (p99 < 50 ms): PASS`, job red. Rule 7 is why every
     `grep` in a command substitution there carries `|| true`.

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
# Rule 7 (OBI-329): the E1.1 verdict hand-off. `status=$?` captures the p99
# verdict, `exit $status` is the only legitimate way for the step to end, and an
# assignment whose command substitution runs `grep` must be `|| true` guarded --
# under `set -e` + `set -o pipefail` a no-match grep aborts the step before the
# verdict is honoured.
VERDICT_CAPTURE = "status=$?"
VERDICT_EXIT = re.compile(r"^\s*exit\s+\"?\$status\"?\s*$")
ASSIGN_SUB = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*=\$\(")
WF_OTHER_EVENTS = ("push", "pull_request_target", "workflow_dispatch", "workflow_call",
                   "schedule", "repository_dispatch", "merge_request_event")


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


def on_pull_request_types(text):
    """`on.pull_request.types` as a set.

    Empty set = no `types:` key = GitHub fires on *every* activity type;
    None = `pull_request` is not a trigger of this workflow at all.
    """
    lines = text.splitlines()
    starts = [i for i, l in enumerate(lines) if re.fullmatch(r"(?:^on:|^true:)\s*", l)]
    if not starts:
        return None
    block = []
    for line in lines[starts[0] + 1:]:
        if re.fullmatch(r"[A-Za-z0-9_-]+:.*", line):
            break  # next top-level key
        block.append(line)
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


def check_text(text):
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

    errors += check_verdict_is_the_only_decision(e11)
    return errors


def check_verdict_is_the_only_decision(e11):
    """Rule 7: nothing between the p99 verdict and `exit $status` may end the job.

    `loadtest-e1-1` is a required check whose *measured* verdict decides it. The
    step therefore captures `status=$?` immediately after `loom-loadtest` and
    closes with `exit $status`, and every diagnostic in between must be unable to
    fail: the shell is `bash -e {0}` with `set -uo pipefail` inside the script, so
    one unguarded `grep` in a command substitution turns "no stalls recorded" -- a
    pass -- into exit 1, and the verdict is never reported.
    """
    errors = []
    try:
        capture = next(i for i, l in enumerate(e11) if VERDICT_CAPTURE in l)
    except StopIteration:
        return ["`loadtest-e1-1` no longer captures the verdict as `status=$?` right "
                "after `loom-loadtest`, so nothing can honour it at the end"]
    tail = e11[capture + 1:]
    end = next((i for i, l in enumerate(tail) if VERDICT_EXIT.match(l)), None)
    if end is None:
        return ["`loadtest-e1-1`'s verdict step no longer ends with `exit $status`: "
                "the p99 verdict must be the only thing that decides this required "
                "check, so a diagnostic cannot replace it and neither can an "
                "accidental 0"]
    for line in tail[:end]:
        if not ASSIGN_SUB.match(line):
            continue
        if "grep" not in line:
            continue
        if "|| true" not in line:
            errors.append(
                f"`loadtest-e1-1` diagnostic can abort the verdict step: {line.strip()[:78]} "
                "-- under `bash -e` + `set -o pipefail` a `grep` that matches nothing "
                "returns 1 through the pipeline and ends the job before `exit $status`, "
                "so a clean (zero-stall, p99-passing) run reads as a failed required "
                "check. Guard the substitution with `|| true`.")
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


def _unguard_verdict_diagnostic(text):
    """Strip the `|| true` from the E1.1 stall-kind substitution -- the shipped
    bug, reproduced from the real line instead of rebuilt from memory."""
    out, hits = [], 0
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith("kinds=$(grep") and "|| true" in line:
            line = line.replace(" || true)", ")")
            hits += 1
        out.append(line)
    assert hits == 1, f"expected one guardable E1.1 diagnostic, saw {hits}"
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
    # Rule 7 (OBI-329): the false red that made main fail while *passing*. The
    # first mutant is the shipped bug itself, reproduced by removing the guard
    # the fix added rather than by trusting the prose.
    ("E1.1 stall-kind diagnostic loses its `|| true`",
     lambda t: _unguard_verdict_diagnostic(t)),
    ("E1.1 verdict no longer decides the job",
     lambda t: _sub(t, "exit $status", "          exit 0\n")),
    ("E1.1 verdict status is never captured",
     lambda t: _sub(t, "status=$?", "          status=0\n")),
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
    wc = workflow_concurrency(Path(path).read_text())
    supersede = (" and cancels superseded pull_request runs only"
                 if wc.get("cancel-in-progress") else ", no workflow-level cancel")
    print(f"check-ci-load-lane: {path} keeps the {LANE_GROUP} lane and "
          f"{'/'.join(LANE_JOBS)} in DAG order{supersede}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
