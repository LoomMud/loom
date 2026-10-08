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
regression. Three overlaps are resolved that way rather than by file type:

  * `crates/*/tests/**` is dev-only, *except* `tests/fixtures/**`, which
    `include_str!` compiles into `loom-loadtest` (its session mix is measured);
  * `crates/*/benches/*.rs` and the bench harness scripts are irrelevant to
    E1.1's p99 but are exactly what the `bench` gate measures -- and `bench`
    shares this lane, so "needs a lane place" is the union, not just E1.1;
  * `.github/workflows/ci.yml` is irrelevant to the binary, including when it
    edits the load command itself. That is not a hole: the flags that define
    the measurement are pinned by scripts/check-ci-load-lane.py, which runs in
    `hygiene` -- a required check with no `needs:` and no `if:` -- so weakening
    the gate fails CI instead of sailing past it unmeasured. The same script's
    rule 8 keeps the one input the flags do not cover, the `toolchain:` the
    workflow installs, equal to the channel `rust-toolchain.toml` declares --
    and that file *is* runtime-relevant, so a compiler bump is measured.

Usage:
  load-lane-classify.py --range BASE...HEAD [--github-output] [--summary]
  load-lane-classify.py --path P [--path P2 ...] [--github-output] [--summary]
  load-lane-classify.py --self-test          # deterministic classification table

With no `--range`/`--path` the diff is unknown, which is the same as an
unrecognised path: runtime-relevant.

Exit status is 0 in classify mode even when the tool cannot work out a diff --
that case is reported as `runtime=true`, and the caller must not have to
improvise a fail-open. `--self-test` exits 1 if any table row misclassifies.
"""

import argparse
import fnmatch
import os
import subprocess
import sys

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
    # A `tests/` file is normally dev-only, but `include_str!` pulls it into the
    # binary the gate builds -- loom-loadtest's src/mix.rs embeds
    # ../tests/fixtures/mix.tsv, which is the session mix E1.1 replays. So
    # fixtures are relevant even though the test *code* around them is not.
    ("crates/*/tests/fixtures/**", True, "fixture compiled into the binary (include_str!)"),
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
    ("compiled-in test fixture", ["crates/loom-loadtest/tests/fixtures/mix.tsv"], True,
     "fixture compiled into the binary"),
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
    print("load-lane-classify self-test: %d cases, %d failure(s)" % (len(TABLE), failed))
    return 1 if failed else 0


def git_paths(rng):
    """`git diff --name-only BASE...HEAD`, or None when the range is unusable.

    Three-dot on purpose: the merge-base to head diff is *this change's* files.
    Two-dot would fold in whatever `main` moved by, which is exactly the
    mis-classification a rebase-while-queued produces.
    """
    try:
        out = subprocess.run(["git", "diff", "--name-only", rng],
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
