#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
"""
Prove that a diff cannot change the binaries the load lane measures (OBI-397).

`load-lane-classify.py` answers "could this diff matter?" from a *table* of
paths, and a table is hand-maintained: it can only ever say "driver or load-bot
source" about `crates/*/src/**`, which is true of the file and false of the
change. A PR that adds a `#[cfg(test)]` harness, a doc comment, or an unused
`pub fn` under `src/` was therefore made to wait for a 150-player measurement
of a binary it had not altered (PR #160: six files, 1289 added lines, all of
them test code or dead code -- `fe5ec31 -> 7c8545a` in ~8 h, six lane places).

This script replaces the guess with the compiler's own answer. E1.1 runs
exactly two programs, `target/release/loom-cli` and `target/release/loom-loadtest`,
built by exactly one command (`.github/workflows/ci.yml`, the `loadtest-e1-1`
job). So build that command at the merge base and at the PR head, and compare
the bytes:

  * identical bytes  -> the program under measurement is the same program. No
    path a 150-player run can take differs. The lane has nothing to measure;
  * different bytes  -> take the lane, measure, report p99.

Why this is the mechanical guard and not another heuristic: the claim being
tested is the one the gate actually cares about ("could this change move the
number?"), stated in terms of the artifact the gate runs. Nothing has to model
module graphs, `#[cfg(test)]` spans, macro expansion, generic instantiation or
dead-code elimination -- the optimiser decides, and it decides the same way it
will decide for `loadtest-e1-1`. A source-level rule can only *approximate*
that and is unsound wherever the approximation is wrong; a content hash is
exact up to a SHA-256 collision.

Direction of failure matters more than the mechanism. Every path in here that
cannot produce a proof emits `same=false` -- "not proven, so measure" -- and
exits 0, because the expensive answer is a lane place (minutes) and the
dangerous one is an unmeasured regression (a green `loadtest-e1-1` with no
p99). Concretely it fails closed when: the range is unreadable, the tree is
dirty or not where it was told to be, a checkout or a build fails, a build
hits `--build-timeout`, an artefact is missing, or this script raises. Each of
those writes a `::warning::` so the cost is visible in the run instead of
silent.

Scope is set by the caller (the `classify` job) and pinned by
`scripts/check-ci-load-lane.py`:

  * only `pull_request` runs, never a `main` push -- the Phase 1 exit criterion
    wants a real measurement per release (OBI-308 rule 8), and a merge to main
    is where a p99 regression must land;
  * only diffs whose *every* runtime-relevant path is Rust source under
    `crates/*/src/**`. `Cargo.lock`, `Cargo.toml`, `.cargo/*`, `warp.ref`,
    `mudlib/**`, `crates/*/build.rs`, benches and the `bench` gate's own inputs
    are excluded even though they would often hash the same: they can change
    what the gate feeds the program (the mudlib, the mix, the criterion
    workloads) without touching these two binaries, and a guard is not allowed
    to be cleverer than the thing it guards.

Usage:
  load-lane-identity.py --base SHA --head SHA [--output-file F] [--github-output]
                        [--summary]
  load-lane-identity.py --self-test     # decision logic, no cargo, no network

Exit status is 0 in every case except a usage error; the verdict is what
carries the failure, never the exit code (a non-zero exit would skip the gate
that `needs:` this job, and GitHub counts a skipped required check as passing).
"""

import argparse
import hashlib
import os
import re
import subprocess
import sys
import time

# The two programs E1.1 runs, and the one command that builds them. Both are
# compared verbatim against the `loadtest-e1-1` job by
# scripts/check-ci-load-lane.py: a proof over different artefacts, or built
# with different flags, proves nothing about what was measured.
ARTIFACTS = ("target/release/loom-cli", "target/release/loom-loadtest")
BUILD_CMD = "SQLX_OFFLINE=true cargo build --release -p loom-cli -p loom-loadtest"

# Per-build wall-clock cap. The `classify` job's `timeout-minutes` must exceed
# 2 * BUILD_TIMEOUT + setup (pinned by check-ci-load-lane.py rule 13) so the
# inner cap always fires first: an Actions timeout fails the job, which skips
# the gate, which reads as green. A capped build just says "not proven".
BUILD_TIMEOUT = 900

SHA = re.compile(r"^[0-9a-f]{7,40}$")


def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Tree(object):
    """The real world: a git checkout and a cargo build. Wrapped so the
    decision logic can be tested without either."""

    def __init__(self, cwd=None, log=lambda s: None):
        self.cwd = cwd
        self.log = log

    def rev(self, ref):
        p = self.run(["git", "rev-parse", "--verify", "%s^{commit}" % ref])
        return p.stdout.strip() if p.returncode == 0 else None

    def head(self):
        return self.rev("HEAD")

    def status(self):
        p = self.run(["git", "status", "--porcelain"])
        return p.returncode, (p.stdout or "").strip()

    def checkout(self, sha):
        p = self.run(["git", "-c", "advice.detachedHead=false", "checkout", "--force", sha])
        return p.returncode == 0 and self.head() == sha

    def build(self, cmd, timeout):
        p = self.run(["timeout", str(timeout), "sh", "-c", cmd])
        return p.returncode, ((p.stdout or "") + (p.stderr or ""))[-4000:]

    def hash(self, path):
        return hash_file(path)

    def run(self, argv):
        return subprocess.run(argv, cwd=self.cwd, capture_output=True, text=True)


def prove(base, head, tree, build_cmd=BUILD_CMD, artifacts=ARTIFACTS,
          build_timeout=BUILD_TIMEOUT):
    """(same, reason, evidence). `same=True` only on a completed proof that the
    artefacts are byte-identical; every other answer is False."""
    ev = {"base": base or "", "head": head or "", "base_sha256": "", "head_sha256": "",
          "seconds": 0, "build": build_cmd}
    t0 = time.time()

    def no(reason):
        ev["seconds"] = int(time.time() - t0)
        return False, reason, ev

    if not base or not head:
        return no("no base/head pair to compare (fail closed: take the lane)")
    if not (SHA.match(base) and SHA.match(head)):
        return no("base/head are not commit ids")
    if base == head:
        # An empty range is not evidence that a change is cheap; it is evidence
        # that the caller could not work out the range.
        return no("base == head: there is no merge base to compare against")
    bsha, hsha = tree.rev(base), tree.rev(head)
    if not bsha or not hsha:
        return no("git cannot resolve both ends of the range (shallow clone?)")
    if bsha == hsha:
        return no("base and head resolve to the same commit")

    rc, dirty = tree.status()
    if rc != 0:
        return no("`git status` failed (fail closed: take the lane)")
    if dirty:
        # Provenance matters: a dirty tree would build something neither end of
        # the range names, so both hashes would be a lie.
        return no("working tree is not clean; refusing to hash a tree that is "
                  "in no commit: %s" % dirty.splitlines()[0])
    # Provenance, not convenience: the caller says "hash the program at sha X",
    # and the tree in front of us has to *be* sha X. In CI that is exactly what
    # `actions/checkout` leaves behind -- `github.sha`, the merge commit the run
    # is measuring -- so this is a tripwire, not an obstacle. A mismatch means
    # someone re-pointed the step at a commit the runner does not have checked
    # out, and the hashes would then describe a tree no job is testing.
    if tree.head() != hsha:
        return no("HEAD is %s but the caller said head=%s; not building a tree "
                  "the caller did not describe" % (tree.head(), hsha))

    def build_and_hash(label, sha):
        if not tree.checkout(sha):
            return None, "%s: cannot check out %s" % (label, sha[:12])
        rc, tail = tree.build(build_cmd, build_timeout)
        if rc == 124 or rc == 137:
            return None, "%s build hit the %d s cap (fail closed: take the lane)" % (label, build_timeout)
        if rc != 0:
            return None, "%s build failed (rc=%d): %s" % (label, rc, tail.strip().splitlines()[-1] if tail.strip() else "no output")
        try:
            return {a: tree.hash(os.path.join(tree.cwd or ".", a)) for a in artifacts}, None
        except (OSError, KeyError) as e:
            return None, "%s: no artefact to hash (%s)" % (label, e)

    head_art, err = build_and_hash("head", hsha)
    if err:
        return no(err)
    base_art, err = build_and_hash("base", bsha)
    if err:
        # Restore head before giving up so nothing downstream reads a tree
        # parked on the merge base.
        tree.checkout(hsha)
        return no(err)
    restored = tree.checkout(hsha)
    ev["head_sha256"] = " ".join(head_art[a] for a in artifacts)
    ev["base_sha256"] = " ".join(base_art[a] for a in artifacts)
    ev["seconds"] = int(time.time() - t0)
    if not restored:
        return no("could not restore the checkout to head after building")
    diff = [a for a in artifacts if head_art[a] != base_art[a]]
    if diff:
        return False, "%s differ(s) between %s and %s: this change reaches the " \
                      "measured program" % (", ".join(diff), bsha[:12], hsha[:12]), ev
    return True, "release build byte-identical at both ends of the range (%s): " \
                 "E1.1 would measure the same program" % \
                 ", ".join(os.path.basename(a) for a in artifacts), ev


# ── self-test: the decision logic, with a fake world ────────────────────────
class FakeTree(object):
    def __init__(self, head="h" * 40, revs=None, status="", builds=None, artifacts=None,
                 cwd="."):
        self.head_sha = head
        self.revs = revs or {}
        self.status_str = status
        self.builds = builds or {}       # sha -> rc
        self.artifacts = artifacts or {}  # sha -> {path: digest}
        self.cwd = cwd
        self.checkouts = []

    def rev(self, ref):
        return self.revs.get(ref)

    def head(self):
        return self.head_sha

    def status(self):
        return 0, self.status_str

    def checkout(self, sha):
        self.checkouts.append(sha)
        self.head_sha = sha
        return True

    def build(self, cmd, timeout):
        rc = self.builds.get(self.head_sha, 0)
        return rc, "" if rc == 0 else "error: simulated build failure"

    def hash(self, path):
        # `prove` hands back a cwd-joined path; keys here are repo-relative.
        return self.artifacts[self.head_sha][os.path.normpath(path)]


def self_test():
    ok = True
    A = list(ARTIFACTS)
    H = "a" * 40  # hex, like a real object id
    B = "b" * 40
    same_art = {A[0]: "a" * 64, A[1]: "b" * 64}
    other_art = {A[0]: "c" * 64, A[1]: "b" * 64}
    revs = {B: B, H: H}
    cases = [
        ("identical artefacts -> same",
         FakeTree(head=H, revs=revs, artifacts={H: same_art, B: dict(same_art)}),
         B, H, True, "byte-identical"),
        ("one artefact differs -> measure",
         FakeTree(head=H, revs=revs, artifacts={H: same_art, B: other_art}),
         B, H, False, "differ"),
        ("head build fails -> measure",
         FakeTree(head=H, revs=revs, builds={H: 101}, artifacts={B: same_art}),
         B, H, False, "head build failed"),
        ("base build fails -> measure",
         FakeTree(head=H, revs=revs, builds={B: 2}, artifacts={H: same_art}),
         B, H, False, "base build failed"),
        ("build hits the cap -> measure",
         FakeTree(head=H, revs=revs, builds={H: 124}, artifacts={B: same_art}),
         B, H, False, "cap"),
        ("artefact missing -> measure",
         FakeTree(head=H, revs=revs, artifacts={H: {A[0]: "a" * 64}, B: same_art}),
         B, H, False, "no artefact"),
        ("dirty tree -> measure, nothing built",
         FakeTree(head=H, revs=revs, status=" M crates/loom-cli/src/main.rs",
                  artifacts={H: same_art, B: same_art}),
         B, H, False, "not clean"),
        ("HEAD not where the caller said -> measure",
         FakeTree(head="f" * 40, revs=dict(revs, **{"f" * 40: "f" * 40}),
                  artifacts={H: same_art, B: same_art}),
         B, H, False, "HEAD is"),
        ("unreadable range -> measure", FakeTree(head=H, revs={}), B, H, False, "cannot resolve"),
        ("empty range -> measure", FakeTree(head=H, revs=revs, artifacts={H: same_art, B: same_art}),
         H, H, False, "no merge base"),
        ("no pair -> measure", FakeTree(head=H, revs=revs), "", H, False, "no base/head"),
        ("not a commit id -> measure", FakeTree(head=H, revs=revs), "main", H, False, "not commit ids"),
    ]
    for name, tree, base, head, want, frag in cases:
        got, reason, ev = prove(base, head, tree)
        good = (got == want) and (frag in reason)
        ok = ok and good
        print("%-46s same=%-5s %s" % (name, got, "ok" if good else "FAIL -> " + reason))
    print()
    print("restores the checkout: ", end="")
    t = FakeTree(head=H, revs=revs, artifacts={H: same_art, B: same_art})
    prove(B, H, t)
    done = t.head_sha == H and t.checkouts.count(B) == 1 and t.checkouts[-1] == H
    print("ok" if done else "FAIL (%s, %s)" % (t.head_sha, t.checkouts))
    ok = ok and done
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__name__.split(".")[-1])
    ap.add_argument("--base")
    ap.add_argument("--head")
    ap.add_argument("--output-file")
    ap.add_argument("--github-output", action="store_true")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--build-cmd", default=BUILD_CMD)
    ap.add_argument("--build-timeout", type=int, default=BUILD_TIMEOUT)
    ap.add_argument("--cwd", default=None)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()

    tree = Tree(cwd=a.cwd)
    same, reason, ev = prove(a.base, a.head, tree, build_cmd=a.build_cmd,
                             build_timeout=a.build_timeout)
    lines = ["same=%s" % ("true" if same else "false"), "reason=%s" % reason,
             "head_sha256=%s" % ev["head_sha256"], "base_sha256=%s" % ev["base_sha256"],
             "seconds=%d" % ev["seconds"]]
    if not same and not reason.startswith("release build byte-identical"):
        # A proof that could not be made is a warning, not a verdict of
        # "irrelevant": the run now costs a lane place, and that is visible.
        print("::warning::load-lane identity proof did not clear the lane: %s" % reason)
    if not same and "differ" in reason:
        print("::notice::load-lane identity proof: the measured program changes; taking the lane")
    for line in lines:
        if a.github_output:
            print(line)
        if a.output_file:
            with open(a.output_file, "a") as f:
                f.write(line + "\n")
        if not (a.github_output or a.output_file):
            print(line)
    if a.summary:
        print("\n### Load-lane identity proof\n\n| | |\n|---|---|")
        for k in ("base", "head", "seconds"):
            print("| `%s` | `%s` |" % (k, ev.get(k, "")))
        print("| built by | `%s` |" % ev["build"])
        print("| `same` | `%s` |" % ("true" if same else "false"))
        print("| reason | %s |" % reason)
        print("| head artefacts | `%s` |" % (ev["head_sha256"] or "-"))
        print("| base artefacts | `%s` |" % (ev["base_sha256"] or "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
