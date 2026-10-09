#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
"""
Decide whether a diff can move the numbers the CI load lane measures (OBI-325).

The lane (`loom-ci-load-lane` in `.github/workflows/ci.yml`) is one FIFO
shared by every open PR, and `loadtest-e1-1` is a *required* check inside it.
With branch protection on `strict: true`, that made every merge a race: a
test-only PR waited 35-60 min for a measurement of a binary it did not change
(PR #124's one-file diff was `crates/loom-cli/tests/supervise_handoff.rs`).

So the gate asks a narrower question first: **could this diff change what E1.1
measures at all?** E1.1 builds `cargo build --release -p loom-cli
-p loom-loadtest` from this checkout and drives `loom serve --mudlib warp`
over telnet. Anything that can change those two binaries, the driver's runtime
content, or the toolchain that compiles them is *runtime-relevant* and takes
the lane. Everything else -- docs, tests, benches, CI config, scripts, the web
client, committed reports -- cannot, and is answered with a fast green check
that never enters the group.

The table is deliberately an *irrelevance allow-list with a fail-closed
default*: a path nobody has thought about is runtime-relevant. Being wrong in
that direction costs one lane run; the other direction costs an unmeasured
regression. Four overlaps are resolved that way rather than by file type:

  * `crates/*/tests/**` is dev-only, *except* `tests/fixtures/**` -- and not for
    the reason this docstring first gave. `loom-loadtest`'s `src/mix.rs` does
    `include_str!("../tests/fixtures/mix.tsv")`, but inside `#[cfg(test)]`: it is
    a unit test asserting the in-repo copy of the mix still parses, not an input
    to the binary the gate builds (the OBI-327 review caught that). The fixture
    stays runtime-relevant on the real grounds: it is the mirror of
    `warp/loadbot/mix.tsv`, which is what E1.1 replays at runtime
    (`--mix warp/loadbot/mix.tsv`), and the contract says the mirror moves in the
    same PR as the mix -- so an edit there is an argument about the measured mix,
    which deserves a lane run rather than a path-based exemption;
  * `crates/*/benches/*.rs` and the bench harness scripts are irrelevant to
    E1.1's p99 but are exactly what the `bench` gate measures -- and `bench`
    shares this lane, so "needs a lane place" is the union, not just E1.1;
  * `.github/workflows/ci.yml` is irrelevant to the binary, including when it
    edits the load command itself. That is not a hole: the flags that define
    the measurement are pinned by scripts/check-ci-load-lane.py, which runs in
    `hygiene` -- a required check with no `needs:` and no `if:` -- so weakening
    the gate fails CI instead of sailing past it unmeasured. The same script's
    rule 9 keeps the one input the flags do not cover, the `toolchain:` the
    workflow installs, equal to the channel `rust-toolchain.toml` declares --
    and that file *is* runtime-relevant, so a compiler bump is measured;
  * `Cargo.lock` is relevant even for a delta that only touches dev-dependencies,
    which `cargo build --release -p loom-cli -p loom-loadtest` never links. Asked
    on OBI-325 whether that is a wasted slot -- yes, deliberately. The
    alternative is a rule about "lockfile deltas whose resolved set reaches the
    release build graph", which means reading a resolver's behaviour off a text
    file, and a rule like that can fail *open*. One lane run is the cheaper
    mistake; recorded here so nobody optimises it into a hole.

The mudlib is a second repository, and it is an input too, so it is pinned in
this one: `warp.ref` names the warp commit the load jobs check out (OBI-326),
and is listed below as runtime-relevant, which means a warp bump takes a lane
place and is measured exactly like a `Cargo.lock` bump -- instead of moving p99
underneath a queue of PRs that skipped it. Rule 11 of
scripts/check-ci-load-lane.py is what keeps the workflow honest about reading
that file.

A module-graph rule ("does the change reach the loadbot's transitive
dependencies?") was rejected for the same reason a prose rule was: it can fail
open. A test module under `src/` pulls its crate's whole public surface through
`use super::*`, and `#[cfg(test)]` attributes sit on statements as well as items
-- parsing that correctly is a compiler problem, and getting it wrong in the
optimising direction costs a gate that silently stops measuring. (A prototype of
exactly that rule was written for OBI-397; on one real 39-file diff it predicted
17 files correctly. It is not shipped.)

What replaced it is *stage two*, and it is a second question rather than a second
table: when this classifier says "relevant" and every relevant path is a Rust
source file the load gate builds (`crates/*/src/*.rs`, none of them
`IDENTITY_NEVER`), `scripts/load-lane-identity.py` builds the release programs
the gate measures at both ends of the range and compares their bytes. The rule
stays a path predicate -- fail-closed, and never wider than the table -- but
"relevant" now means "relevant and unproven", and the answer to "does this reach
the loadbot" comes from rustc instead of from anyone's reading of a diff. A diff
that moves only `#[cfg(test)]` code, or dead code, or a comment inside `src/`,
produces byte-identical programs and does not occupy the lane.

Stage two can only *lower* a verdict, and only for `pull_request`: a push to
`main` still gets a measured p99 (spec 8.12 and the Phase 1 exit criterion), and
a table skip still never triggers a build.

Usage:
  load-lane-classify.py --range BASE...HEAD [--github-output] [--summary]
  load-lane-classify.py --path P [--path P2 ...] [--github-output] [--summary]
  load-lane-classify.py --self-test          # table + how the paths are read

With no `--range`/`--path` the diff is unknown, which is the same as an
unrecognised path: runtime-relevant.

Exit status is 0 in classify mode even when the tool cannot work out a diff --
that case is reported as `runtime=true`, and the caller must not have to
improvise a fail-open. `--self-test` exits 1 if any table row misclassifies, or
if the git half (`git_self_test`) cannot read a rename's source path.
"""

import argparse
import fnmatch
import os
import shutil
import subprocess
import sys
import tempfile

# (glob, verdict, rule label). First match wins, runtime-relevant rules first:
# `crates/loom-vm/src/README.md` is documentation *and* a file under `src/`, and
# the conservative answer to that overlap is "take the lane".
#
# Label is what the job summary and the check description say, so a reviewer
# reading a green `loadtest-e1-1` can see why nothing was measured.
#
# `fnmatch`'s `*` crosses `/` (it is not a shell glob), so a pattern that must
# match a *nested* file says so with `**/`, and one that must match only the
# repo root says so by carrying no wildcard at all.
RULES = [
    # ── runtime-relevant: these change the binary the gate measures ─────────
    ("Cargo.lock", True, "dependency versions"),
    ("**/Cargo.lock", True, "dependency versions"),
    ("Cargo.toml", True, "workspace build profile"),
    ("**/Cargo.toml", True, "crate manifest/features"),
    ("rust-toolchain.toml", True, "compiler version"),
    (".cargo/*", True, "cargo config (flags, targets, profiles)"),
    (".cargo/**", True, "cargo config (flags, targets, profiles)"),
    ("crates/*/src/**", True, "driver or load-bot source"),
    ("crates/*/build.rs", True, "build script output"),
    # OBI-326: the mudlib the load lane serves lives in another repository, and
    # this file is the single place that says which commit of it the gate measures
    # (`warp.ref`: one 40-character SHA), so bumping the world under test has to
    # take a lane place like a `Cargo.lock` bump does.
    #
    # An unlisted path already falls closed to relevant, and `warp.ref` is a root
    # path so nothing else claims it. The explicit rule is not what makes the pin
    # measured; it is what makes the *reason* exact and the property deliberate, so
    # a later widening (a root `*.ref` -> metadata rule, say) cannot quietly turn a
    # world bump into a skip. Rule 11 of scripts/check-ci-load-lane.py asserts the
    # classification either way.
    ("warp.ref", True, "pinned mudlib rev (the world the gate serves)"),
    ("mudlib/**", True, "runtime mudlib content"),
    # Normally dev-only, but this is the in-repo mirror of `warp/loadbot/mix.tsv`
    # -- the mix E1.1 actually replays (`--mix warp/loadbot/mix.tsv`), which the
    # contract keeps moving in the same PR. It is *not* compiled in:
    # `src/mix.rs`'s `include_str!` sits inside `#[cfg(test)]` (OBI-327 review
    # corrected this comment). Relevant anyway: an edit here is an argument about
    # the measured mix, and the unpinned warp checkout means OBI-326, not this
    # rule, is the real guard.
    ("crates/*/tests/fixtures/**", True, "mirror of the mix E1.1 replays (warp/loadbot/mix.tsv)"),
    # The `bench` gate measures these inside the same lane, so "can move what
    # the lane measures" has to include them: marking them irrelevant would
    # have skipped the only gate that catches a criterion workload regression.
    ("crates/*/benches/*.rs", True, "criterion workload source (measured by `bench`)"),
    ("scripts/bench-gate.sh", True, "the bench harness itself"),
    ("scripts/bench_compare.py", True, "the bench comparator itself"),

    # ── runtime-irrelevant: nothing here reaches `loom serve` or loom-loadtest
    #    as built and run by the E1.1 job ───────────────────────────────────
    ("crates/*/tests/**", False, "integration tests (dev-only, not in the release build)"),
    ("crates/*/benches/*.md", False, "bench baseline documentation"),
    ("crates/*/benches/**", False, "criterion bench assets"),
    ("crates/*/examples/**", False, "example binaries (dev-only)"),
    ("crates/*/fuzz/**", False, "fuzz targets (separate cargo workspace)"),
    ("crates/*/proptest-regressions/**", False, "proptest seeds"),
    (".github/**", False, "CI configuration"),
    ("scripts/**", False, "CI and dev scripts (not compiled into the driver)"),
    ("web-client/**", False, "web client (served from disk, never in the E1.1 path)"),
    ("results/**", False, "committed load-test reports"),
    ("docs/**", False, "documentation"),
    ("*.md", False, "documentation"),
    ("LICENSE", False, "licence text"),
    ("LICENSES/**", False, "licence text"),
    ("COPYING", False, "licence text"),
    ("REUSE.toml", False, "REUSE metadata"),
    ("deny.toml", False, "cargo-deny policy (advisory, not a build input)"),
    ("Dockerfile", False, "image build (release-image.yml, not the CI measurement)"),
    (".dockerignore", False, "image build context"),
    ("docker-compose.yml", False, "dev stack definition"),
    ("ops/**", False, "deployment and ops manifests"),
    ("secrets.env.example", False, "env template"),
    (".gitignore", False, "repo hygiene"),
    (".editorconfig", False, "editor settings"),
]

DEFAULT_VERDICT = True
DEFAULT_REASON = "not on the runtime-irrelevant list (fail closed)"

# ── stage two: which diffs are worth asking the compiler about ───────────────
# The table decides "this diff can move p99". It cannot decide the opposite
# question -- "this diff is *source*, but does it move the program?" -- because
# a `#[cfg(test)]` block inside `src/` is source and moves nothing. That second
# question goes to `scripts/load-lane-identity.py`, which builds the release
# programs and compares bytes. What is decided *here* is only whose diffs get
# asked, and the scope rule is a path predicate like the table itself: it may
# only ever be narrower than "the table said relevant".
#
# A file the gate's own build command does not compile cannot be part of that
# proof, so the scope is what `cargo build --release -p loom-cli -p
# loom-loadtest` reads: Rust sources under a crate's `src/`.
IDENTITY_SOURCE = ("crates/*/src/*.rs",)
IDENTITY_NEVER = (
    # `include!(concat!(env!("OUT_DIR"), "/generated.rs"))`. The *file* is
    # source, but the bytes it expands to come from a build script, and the
    # proof builds the base checkout's generated file and the head checkout's
    # own -- two different files can hash equal only by luck of the base being
    # rebuilt identically, which is the assumption the proof is supposed to
    # *test*. Excluded by name because one path in this tree is generated today;
    # the exception is written down rather than discovered by a false green.
    #
    # `scripts/check-ci-load-lane.py` rule 15 walks every `include!` of a
    # generated path in the workspace and fails if one is not listed here, so a
    # second generated file cannot appear without this list being edited.
    "crates/loom-vm/src/codegen.rs",
    # A template that becomes source at build time (`build.rs` writes the
    # expansion): same objection as `codegen.rs`, and it would be swept in by a
    # `*` that crosses `/`.
    "crates/*/src/*.rs.in",
    # A `build.rs` under `src/` compiles as an ordinary module, not as a build
    # script -- but the name is the warning, and the proof must not be asked to
    # adjudicate one.
    "crates/*/src/build.rs",
)


def identity_candidate(paths, source=None, never=None):
    """May stage two ask the compiler about this diff? True/False.

    False unless the table already said *relevant* -- stage two is a discount,
    never an upgrade: it cannot turn a skip into a measurement -- and false
    unless every relevant path is buildable source. The fail-closed part is what
    it enumerates as exclusions: anything not provably a `.rs` the gate compiles
    (a manifest, a lockfile, `build.rs`, a fixture, the mudlib pin, a workflow,
    an unknown path) keeps the lane. A mistake here costs one measurement nobody
    needed, exactly like a mistake in the table does.

    `source`/`never` are overridable for `never_net_test()` only; callers use the
    module constants.
    """
    source = IDENTITY_SOURCE if source is None else source
    never = IDENTITY_NEVER if never is None else never
    if not classify(paths)[0]:
        return False
    if not paths:
        return False          # "could not read the diff" is not "only src changed"
    for p in sorted(set(paths)):
        if classify([p])[0]:
            # Relevant on its own, so it has to be source the gate builds: a
            # proof that cannot see part of the change is not a proof.
            if not any(fnmatch.fnmatchcase(p, g) for g in source):
                return False
            if any(fnmatch.fnmatchcase(p, g) for g in never):
                return False
    return True


def classify(paths):
    """(runtime_relevant, reason, matched_rule) for a set of changed paths.

    An empty path list is runtime-relevant: "the diff could not be read" is not
    evidence that nothing changed.
    """
    if not paths:
        return DEFAULT_VERDICT, DEFAULT_REASON, "no paths"
    worst = None  # the single most conservative hit, if any rule matched at all
    matched = False
    for p in sorted(set(paths)):
        for glob, verdict, reason in RULES:
            if fnmatch.fnmatchcase(p, glob):
                matched = True
                if verdict:
                    return True, "%s: %s" % (glob, reason), glob
                if worst is None:
                    worst = (p, glob, reason)
                break
    if matched:
        return False, "%s: %s" % (worst[1], worst[2]), worst[1]
    return DEFAULT_VERDICT, DEFAULT_REASON, None


# ── classification table (also the unit test, via --self-test) ──────────────
# Each row: (name, changed paths, expected runtime-relevant?, substring expected
# in the reason). Rows marked `case study` are real diffs from the issue that
# motivated this script.
TABLE = [
    ("docs only", ["CONTRIBUTING.md", "docs/net.md"], False, "documentation"),
    ("docs under a dir", ["results/README.md"], False, "committed load-test reports"),
    ("case study: PR #124", ["crates/loom-cli/tests/supervise_handoff.rs"], False,
     "integration tests"),
    ("test + doc mix", ["crates/loom-cli/tests/net_tick.rs", "README.md"], False,
     "documentation"),
    ("benches docs only", ["crates/loom-vm/benches/BASELINE.md"], False,
     "bench baseline documentation"),
    ("bench source is measured", ["crates/loom-vm/benches/vm_bench.rs"], True,
     "criterion workload source"),
    ("bench harness", ["scripts/bench-gate.sh"], True, "the bench harness itself"),
    ("bench comparator", ["scripts/bench_compare.py"], True, "the bench comparator itself"),
    ("the mix mirror under tests/", ["crates/loom-loadtest/tests/fixtures/mix.tsv"], True,
     "mirror of the mix E1.1 replays"),
    ("fuzz targets only", ["crates/loom-syntax/fuzz/fuzz_targets/parse.rs"], False,
     "fuzz targets"),
    ("CI only", [".github/workflows/ci.yml", ".github/workflows/release-image.yml"],
     False, "CI configuration"),
    ("CI + guard script", [".github/workflows/ci.yml", "scripts/check-ci-load-lane.py"],
     False, "CI configuration"),
    ("web client only", ["web-client/src/client.ts", "web-client/package.json"], False,
     "web client"),
    ("ops only", ["ops/kustomize/staging/statefulset.yaml"], False, "deployment"),
    ("licence metadata only", ["REUSE.toml", "deny.toml", "LICENSES/AGPL-3.0-only.txt"],
     False, "licence text"),
    ("driver source", ["crates/loom-vm/src/vm.rs"], True, "driver or load-bot source"),
    ("load bot source", ["crates/loom-loadtest/src/main.rs"], True,
     "driver or load-bot source"),
    ("crate manifest", ["crates/loom-cli/Cargo.toml"], True, "crate manifest"),
    ("workspace manifest", ["Cargo.toml"], True, "workspace build profile"),
    ("lockfile", ["Cargo.lock"], True, "dependency versions"),
    ("toolchain", ["rust-toolchain.toml"], True, "compiler version"),
    ("cargo config", [".cargo/config.toml"], True, "cargo config"),
    ("mudlib content", ["mudlib/room/lobby.c"], True, "runtime mudlib content"),
    ("pinned mudlib rev", ["warp.ref"], True, "pinned mudlib rev"),
    ("pin bump is a lane run", ["warp.ref", "results/README.md"], True,
     "pinned mudlib rev"),
    # The pin lives at the repo root, beside `Cargo.lock`, and not under
    # `mudlib/`: `mudlib/` is a directory developers populate by hand and
    # `docker compose` mounts read-only, so a CI input does not belong in it.
    ("pin is not mudlib content", ["mudlib/README.md"], True,
     "runtime mudlib content"),
    ("warp.ref is not swept by a glob", ["warp.ref", "README.md"], True,
     "pinned mudlib rev"),
    ("build script", ["crates/loom-vm/build.rs"], True, "build script output"),
    ("overlap stays relevant", ["crates/loom-vm/src/README.md"], True,
     "driver or load-bot source"),
    ("case study: PR #127", ["Cargo.lock", "crates/loom-cli/Cargo.toml",
                             "crates/loom-cli/tests/accounts_demo.rs",
                             "crates/loom-testing/src/lib.rs"], True, "dependency versions"),
    ("unknown path fails closed", ["weird/new-thing/thing.bin"], True, "fail closed"),
    ("empty diff fails closed", [], True, "fail closed"),
    ("any relevant path wins", ["docs/a.md", "crates/loom-net/src/session.rs",
                                "crates/loom-cli/tests/net_tick.rs"], True,
     "driver or load-bot source"),
    ("path outside every rule", ["Cargo.toml.bak"], True, "fail closed"),
]

# The table's runtime-*irrelevant* rows: the ones stage two must never reach,
# because there is nothing left to discount. Derived rather than typed, so
# widening the allow-list cannot leave them behind.
SKIP_TABLE = [(name, paths, reason) for (name, paths, want, reason) in TABLE if not want]
# The table's runtime-relevant rows whose paths are all buildable source -- the
# exact set the scope rule is defined to accept. Checked against
# `identity_candidate` so the shipped predicate and the shape it claims to
# implement cannot drift apart.
CANDIDATE_TABLE = [(name, paths, True, reason) for (name, paths, want, reason) in TABLE
                   if want and paths and all(fnmatch.fnmatchcase(p, IDENTITY_SOURCE[0])
                                   and not any(fnmatch.fnmatchcase(p, g)
                                               for g in IDENTITY_NEVER)
                                   for p in paths)]

# The candidate set expressed as the positive rule stage two ships: every
# relevant path must be buildable Rust source. Under fnmatch (whose `*` crosses
# `/`) `crates/*/src/*.rs` is exactly that.
WIDENED_SOURCE = IDENTITY_SOURCE
NET_ROWS = [
    # Not candidates, in four flavours: allow-listed (nothing to discount),
    # relevant-but-not-source (the proof cannot see the whole change), no diff
    # at all, and the fail-closed default.
    ("docs only", ["README.md"], False),
    ("tests only", ["crates/loom-vm/tests/vm.rs"], False),
    ("empty diff", [], False),
    ("unreadable diff (fail closed)", ["weird/new-thing/thing.bin"], False),
    ("manifest is not source", ["crates/loom-cli/Cargo.toml"], False),
    ("lockfile is not source", ["Cargo.lock"], False),
    ("build script is not source", ["crates/loom-vm/build.rs"], False),
    ("toolchain is not source", ["rust-toolchain.toml"], False),
    ("mudlib pin is not source", ["warp.ref"], False),
    ("fixture is not source", ["crates/loom-loadtest/tests/fixtures/mix.tsv"], False),
    ("bench source is not the measured program",
     ["crates/loom-vm/benches/vm_bench.rs"], False),
    ("workflow is not source", [".github/workflows/ci.yml"], False),
    ("one non-source path out of many", ["crates/loom-vm/src/vm.rs", "Cargo.lock"], False),
    # The common shape in practice, and the reason eligibility is composed
    # per-path instead of "every changed path is `src/*.rs`": the table has
    # already said the report cannot move p99, and the hash will say whether the
    # source moved the measured programs. Both halves are load-bearing, so this
    # is a candidate -- and the *next* row is the same shape with one half
    # relevant-and-not-source, which is not.
    ("source plus a report",
     ["crates/loom-net/src/session.rs", "results/2026-10-08-tick-spindle.md"], True),
    ("generated-source exception", ["crates/loom-vm/src/codegen.rs"], False),
    ("template exception", ["crates/loom-vm/src/codegen.rs.in"], False),
    # Candidates: a single source file, and source mixed only with paths the
    # table already waves through. The second shape is the common one in practice
    # -- "touch `src/`, add a test, write a line in the report" -- and it is
    # judgeable because the table already claims the waved paths cannot move p99
    # while the hash claims the source did not move the measured programs.
    ("one source file", ["crates/loom-vm/src/world.rs"], True),
    ("nested module", ["crates/loom-http/src/admin/query.rs"], True),
    ("src + tests + docs (OBI-397's shape)",
     ["crates/loom-loadtest/src/session.rs", "crates/loom-loadtest/tests/warmup.rs",
      "docs/perf.md"], True),
    ("src + committed report", ["crates/loom-cli/src/app.rs", "results/README.md"], True),
]


def never_net_test():
    """Stage two's scope rule may not outrun the table, in either direction.

    The interesting failure is silent and lives both ways. A *widening*: the
    candidate set claims a relevant path that is not buildable source, so the
    proof passes while something the gate compiles changed underneath it. A
    *narrowing that swallows a pin*: drop one irrelevance rule from the table and
    the candidate set has to shrink with it -- `identity_candidate` is defined on
    top of `classify`, so if it ever read the table's output in the wrong
    direction, removing `crates/*/tests/**` from `RULES` would silently hand the
    compiler diffs of integration tests. Returns (cases, failures).
    """
    failed = 0
    # (1) Stage two is a discount, never an upgrade: nothing the table skips may
    # be a candidate. This is the direction that would let a docs PR buy a lane
    # place, and it is the one a future "but the compiler says it is fine" edit
    # would break.
    for name, paths, _reason in SKIP_TABLE:
        if identity_candidate(paths, source=WIDENED_SOURCE, never=IDENTITY_NEVER):
            print("FAIL net: skip row %-24s -> became a candidate: stage two would build "
                  "for a diff the table already waved through, or worse, override it" % name)
            failed += 1
    # (2) The predicate and the shape it claims to implement agree on the real
    # table, using the shipped constants (no `source=`/`never=` override).
    for name, paths, _want, _reason in CANDIDATE_TABLE:
        if not identity_candidate(paths):
            print("FAIL net: candidate %-28s -> all-source and relevant, but the predicate "
                  "refuses it: the proof is narrower than its own rule" % name)
            failed += 1
    for name, paths, want in NET_ROWS:
        got = identity_candidate(paths, source=WIDENED_SOURCE, never=IDENTITY_NEVER)
        if got != want:
            print("FAIL net: %-36s -> candidate=%s (want %s)" % (name, got, want))
            failed += 1
    checked = 0
    for idx, (glob, verdict, _reason) in enumerate(RULES):
        if verdict:                       # only allow-list rules can be dropped
            continue
        before = sum(1 for _n, p, _w, _r in CANDIDATE_TABLE
                     if identity_candidate(p, source=WIDENED_SOURCE, never=IDENTITY_NEVER))
        saved = RULES[:]
        del RULES[idx]
        try:
            after = sum(1 for _n, p, _w, _r in CANDIDATE_TABLE
                        if identity_candidate(p, source=WIDENED_SOURCE, never=IDENTITY_NEVER))
        finally:
            RULES[:] = saved
        checked += 1
        if after > before:
            print("FAIL net: dropping the `%s` allow-list rule *widens* the candidate set "
                  "(%d -> %d): the scope rule must track the table, never lead it"
                  % (glob, before, after))
            failed += 1
    total = len(CANDIDATE_TABLE) + len(NET_ROWS) + checked
    print("ok   net test: %d candidate rows, %d fixed rows, %d rule-drop(s) checked"
          % (len(CANDIDATE_TABLE), len(NET_ROWS), checked))
    return total, failed


def self_test():
    failed = 0
    for name, paths, want, want_reason in TABLE:
        runtime, reason, rule = classify(paths)
        ok = runtime is want and want_reason in reason
        if ok:
            print("ok   %-28s -> %s" % (name, "lane" if runtime else "skip"))
        else:
            failed += 1
            print("FAIL %-28s -> runtime=%s reason=%r (wanted runtime=%s reason ~ %r, rule %r)"
                  % (name, runtime, reason, want, want_reason, rule))
    total = len(TABLE)
    n, f = never_net_test()
    total += n
    failed += f
    n, f = git_self_test()
    total += n
    failed += f
    print("load-lane-classify self-test: %d cases, %d failure(s)" % (total, failed))
    return 1 if failed else 0


def _git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True,
                          text=True, check=True).stdout


def git_self_test():
    """The half the table cannot express: how changed paths *reach* `classify`.

    The OBI-325 review's second defect. `git diff --name-only` detects renames by
    default, and a detected rename is reported as its destination only -- so
    moving `crates/loom-loadtest/tests/fixtures/mix.tsv` (the mirror of the mix
    E1.1 replays, therefore runtime-relevant) next to the integration tests it is
    no longer read from would list one allow-listed path and classify as
    *skip*. `git_paths` passes `--no-renames`, so both ends are read and the
    relevant source still decides. Builds a throwaway repo, changes nothing in
    this one. Returns (cases, failures).
    """
    if shutil.which("git") is None:
        print("FAIL git self-test                   -> no git on PATH: the diff-reading "
              "half of this check is untested, not passed")
        return 1, 1
    seed = {
        "crates/loom-loadtest/tests/fixtures/mix.tsv": "warp\tloadbot\tmix\n",
        "mudlib/room/lobby.c": "var short descr = \"Lobby\";\n",
        "docs/a.md": "prose\n",
    }
    moves = [("crates/loom-loadtest/tests/fixtures/mix.tsv",
              "crates/loom-cli/tests/mix.tsv"),
             ("mudlib/room/lobby.c", "docs/lobby.c")]
    tmp = tempfile.mkdtemp(prefix="load-lane-classify-selftest-")
    repo = os.path.join(tmp, "repo")
    cases = failed = 0
    cwd = os.getcwd()
    try:
        os.makedirs(repo)
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "config", "user.email", "selftest@example.invalid")
        _git(repo, "config", "user.name", "load-lane-classify self-test")
        for path, body in seed.items():
            full = os.path.join(repo, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as f:
                f.write(body)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "seed")
        base = _git(repo, "rev-parse", "HEAD").strip()
        for src, dst in moves:
            os.makedirs(os.path.dirname(os.path.join(repo, dst)), exist_ok=True)
            _git(repo, "mv", src, dst)
        _git(repo, "commit", "-q", "-m", "two renames, both destinations allow-listed")
        rng = "%s...%s" % (base, _git(repo, "rev-parse", "HEAD").strip())
        os.chdir(repo)
        paths = git_paths(rng)

        def check(name, ok, detail=""):
            nonlocal cases, failed
            cases += 1
            if ok:
                print("ok   %-28s -> %s" % (name, detail))
            else:
                failed += 1
                print("FAIL %-28s -> %s" % (name, detail))

        have = set(paths or [])
        for src, dst in moves:
            check("rename lists source",
                  src in have, "missing" if src not in have else src)
            check("rename lists destination",
                  dst in have, "missing" if dst not in have else dst)
        runtime, reason, rule = classify(paths or [])
        check("renames take the lane", runtime is True,
              "runtime=%s reason=%r" % (runtime, reason))
        # The counterfactual, so this test cannot rot into vacuity: with rename
        # detection forced on, the same range lists only the two allow-listed
        # destinations and would skip. If a future table edit makes these
        # destinations relevant, this case fails and the pairing must be redone.
        folded = subprocess.run(["git", "-C", repo, "diff", "--name-only", "-M", rng],
                                capture_output=True, text=True, check=True)
        fold = [l for l in folded.stdout.splitlines() if l.strip()]
        check("counterfactual: -M hides sources",
              set(fold) == {dst for _, dst in moves} and classify(fold)[0] is False,
              "-M lists %s -> runtime=%s" % (sorted(fold), classify(fold)[0]))
    except (OSError, subprocess.CalledProcessError) as e:
        check("git self-test ran", False, "could not build the throwaway repo: %s" % e)
        cases += 1
        failed += 1
    finally:
        os.chdir(cwd)
        shutil.rmtree(tmp, ignore_errors=True)
    return cases, failed


def git_paths(rng):
    """`git diff --name-only --no-renames BASE...HEAD`, or None if unusable.

    Three-dot on purpose: the merge-base to head diff is *this change's* files.
    Two-dot would fold in whatever `main` moved by, which is exactly the
    mis-classification a rebase-while-queued produces.

    `--no-renames` because rename detection is on by default and reports a move
    as its destination alone: a file renamed *out* of a runtime-relevant path
    into an allow-listed one would then classify as "skip the lane". Both ends of
    a move are inputs to the verdict; `git_self_test` is the regression test.
    """
    try:
        out = subprocess.run(["git", "diff", "--name-only", "--no-renames", rng],
                             capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as e:
        sys.stderr.write("load-lane-classify: cannot read %s: %s\n" % (rng, e))
        return None
    return [l for l in out.stdout.splitlines() if l.strip()]


def emit(target, summary, paths, runtime, reason, rule, identity=None):
    """Write the verdict once, then (optionally) the human-readable summary.

    `target` is the file the caller collected `$GITHUB_OUTPUT` into -- exactly
    one `runtime=` line, so the caller can add its own fallback without two
    values for one key.
    """
    kvs = [("runtime", "true" if runtime else "false"),
           ("reason", reason),
           ("files", str(len(paths)))]
    # Only when stage two is on the table at all. An absent output reads as "not
    # proven" in the workflow, which is the fail-closed direction, and there is
    # nothing to say about a diff the table already skipped.
    if identity is not None and runtime:
        kvs.append(("identity", "true" if identity else "false"))
    if target:
        with open(target, "a", encoding="utf-8") as f:
            for k, v in kvs:
                f.write("%s=%s\n" % (k, v))
    else:
        for k, v in kvs:
            sys.stdout.write("%s=%s\n" % (k, v))
    sum_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and sum_path:
        with open(sum_path, "a", encoding="utf-8") as f:
            f.write("### `loadtest-e1-1` load-lane decision\n\n")
            if runtime:
                f.write("- **decision: takes the `loom-ci-load-lane` place and measures**\n")
            else:
                f.write("- **decision: skips the load lane and measures nothing**\n"
                        "- nothing in this diff can change the binary E1.1 builds or the "
                        "session it drives\n")
            f.write("- rule: `%s`\n" % (rule or "-"))
            f.write("- %d changed path(s): %s\n" % (
                len(paths), ", ".join("`%s`" % p for p in sorted(paths)[:12])
                + (" …" if len(paths) > 12 else "")))


def main(argv):
    ap = argparse.ArgumentParser(prog="load-lane-classify.py", description=__doc__.splitlines()[1])
    ap.add_argument("--range", dest="rng", help="git diff range, BASE...HEAD")
    ap.add_argument("--path", action="append", dest="paths", default=[],
                    help="explicit changed path (repeatable)")
    ap.add_argument("--github-output", action="store_true", dest="out",
                    help="write runtime/reason/files to $GITHUB_OUTPUT")
    ap.add_argument("--output-file", dest="output_file",
                    help="write runtime/reason/files to this file instead (the CI step "
                         "collects it into $GITHUB_OUTPUT once, so a fallback value "
                         "cannot end up beside a real one)")
    ap.add_argument("--summary", action="store_true", help="append the decision to $GITHUB_STEP_SUMMARY")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--no-identity", action="store_true", dest="no_identity",
                    help="do not emit the `identity` output (stage one only: a diff that "
                         "would have been a candidate still takes the lane)")
    ap.add_argument("--reason", help="explain a range that could not be read")
    a = ap.parse_args(argv[1:])

    if a.self_test:
        return self_test()

    if a.paths:
        paths = a.paths
    elif a.rng:
        paths = git_paths(a.rng)
        if paths is None:
            paths = []
    else:
        sys.stderr.write("load-lane-classify: no diff given (%s); treating as runtime-relevant\n"
                         % (a.reason or "nothing to read"))
        paths = []

    runtime, reason, rule = classify(paths)
    identity = None if a.no_identity else identity_candidate(paths)
    if a.reason and not paths:
        # Say *why* nothing was read: "fail closed" alone would hide that the
        # diff was unreadable rather than merely unrecognised.
        reason, rule = a.reason, "unreadable diff"
    print("load-lane: %s (%s)" % ("RUNTIME-RELEVANT -> load lane" if runtime
                                  else "runtime-irrelevant -> skip the lane", reason))
    target = a.output_file or (os.environ.get("GITHUB_OUTPUT") if a.out else None)
    emit(target, a.summary, paths, runtime, reason, rule, identity)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
