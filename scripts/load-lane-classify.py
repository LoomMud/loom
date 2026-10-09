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


def emit(target, summary, paths, runtime, reason, rule):
    """Write the verdict once, then (optionally) the human-readable summary.

    `target` is the file the caller collected `$GITHUB_OUTPUT` into -- exactly
    one `runtime=` line, so the caller can add its own fallback without two
    values for one key.
    """
    kvs = [("runtime", "true" if runtime else "false"),
           ("reason", reason),
           ("files", str(len(paths)))]
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
    if a.reason and not paths:
        # Say *why* nothing was read: "fail closed" alone would hide that the
        # diff was unreadable rather than merely unrecognised.
        reason, rule = a.reason, "unreadable diff"
    print("load-lane: %s (%s)" % ("RUNTIME-RELEVANT -> load lane" if runtime
                                  else "runtime-irrelevant -> skip the lane", reason))
    target = a.output_file or (os.environ.get("GITHUB_OUTPUT") if a.out else None)
    emit(target, a.summary, paths, runtime, reason, rule)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
