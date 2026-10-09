#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
#
# Prove that an offline sqlx build and a live-DB build of `loom-persist` are not
# the same cached artifact (OBI-328).
#
# Why this needs proving instead of asserting: cargo's fingerprint for a crate
# does not include the value of `SQLX_OFFLINE`, and a macro recompile is only
# forced by touching a source file. Before `crates/loom-persist/build.rs`
# existed, a build asked to talk to the database was answered from the cache --
# `Finished dev profile`, exit 0, no `DESCRIBE` ever reaching Postgres -- and
# the person who ran it believed the schema and the `.sqlx/` cache agreed when
# no comparison had happened. The build script pins the mode into the
# fingerprint; this script is the regression test for that, run in CI (the
# `rust` job) because a unit test cannot nest a `cargo check` inside the `cargo
# test` that holds the build-directory lock.
#
# The probe is a closed localhost port as `DATABASE_URL`, so a dial is loud
# (Connection refused) and no database of anyone else's is ever contacted --
# see docs/persistence.md, "Local DB testing" (OBI-150/OBI-151). Nothing here
# reads the ambient `DATABASE_URL`.
#
# Usage (from anywhere in the repo):
#   scripts/check-sqlx-cache-modes.sh
#
# Exit codes: 0 = the two modes are separate builds; 1 = the OBI-328 cache hit
# is back (or the probe could not run).

set -euo pipefail
cd "$(dirname "$0")/.."

PACKAGE=loom-persist

fail() {
    printf 'sqlx-cache-modes: FAIL: %s\n' "$*" >&2
    exit 1
}

note() {
    printf 'sqlx-cache-modes: %s\n' "$*"
}

# Is the port free of a listener? A live build that reaches a real Postgres is a
# *successful* live build, which tells us nothing; the probe only works because
# nothing answers.
has_listener() {
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

# Two closed ports: one for the mode flip, one for the DATABASE_URL flip.
# Scanned rather than assumed, so the gate does not depend on what happens to be
# free on the runner; an explicit LOOM_SQLX_MODE_PROBE_PORT is verified instead
# of guessed.
pick_ports() {
    local -a ports=()
    local candidate
    if [ -n "${LOOM_SQLX_MODE_PROBE_PORT:-}" ]; then
        has_listener "$LOOM_SQLX_MODE_PROBE_PORT" &&
            fail "LOOM_SQLX_MODE_PROBE_PORT=$LOOM_SQLX_MODE_PROBE_PORT has a listener; the probe needs a closed port"
        ports+=("$LOOM_SQLX_MODE_PROBE_PORT")
    fi
    for candidate in 59999 59998 40011 40012 26213 26214 31319 31320; do
        [ "${#ports[@]}" -ge 2 ] && break
        case " ${ports[*]-} " in
            *" $candidate "*) continue ;;
        esac
        has_listener "$candidate" || ports+=("$candidate")
    done
    [ "${#ports[@]}" -ge 2 ] ||
        fail "found fewer than two closed localhost ports for the probe; pass LOOM_SQLX_MODE_PROBE_PORT=<closed port>"
    printf '%s\n' "${ports[@]}"
}

mapfile -t PROBE_PORTS < <(pick_ports)
PORT_A=${PROBE_PORTS[0]}
PORT_B=${PROBE_PORTS[1]}
URL_A="postgres://nobody@127.0.0.1:${PORT_A}/loom-sqlx-mode-probe"
URL_B="postgres://nobody@127.0.0.1:${PORT_B}/loom-sqlx-mode-probe"
note "probe ports: ${PORT_A}, ${PORT_B} (both closed)"

# Run one `cargo check`, capturing output and exit status without letting
# `set -e` end the script on the failure we are looking for.
#
# The assertions below match on cargo's own words ("Dirty loom-persist ...: the
# env variable SQLX_OFFLINE changed"), and CI exports `CARGO_TERM_COLOR=always`:
# colour splits those words with escape sequences (`^[[1m^[[92m Dirty^[[0m
# loom-persist`), so a pattern that matches on a terminal does not match in the
# `rust` job. Pin colour off, and strip anything left, so the gate runs the same
# logic here and on a runner. Reproduced both ways: the old script fails with
# `CARGO_TERM_COLOR=always` and passes without it.
export CARGO_TERM_COLOR=never
SCSI_SGR=$(printf '\033')

check() {
    local -a cmd=("$@")
    set +e
    CHECK_OUT=$("${cmd[@]}" 2>&1 | sed -e "s/${SCSI_SGR}\[[0-9;]*m//g")
    CHECK_STATUS=${PIPESTATUS[0]}
    set -e
}

# What a failure actually needs: the lines about this package and the errors,
# not twenty lines of "Fresh serde".
excerpt() {
    grep -E "${PACKAGE}|^error|^warning" <<<"$CHECK_OUT" | tail -15
}

# 1. The workspace default: offline, from `.sqlx/`, and successful.
note "1/4 checking ${PACKAGE} offline (the workspace default)"
check env -u DATABASE_URL SQLX_OFFLINE=true cargo check -p "$PACKAGE"
[ "$CHECK_STATUS" -eq 0 ] ||
    fail "the offline default build did not succeed; nothing else here is meaningful:
$(grep -E "${PACKAGE}|^error|^warning" <<<"$CHECK_OUT" | tail -15)"

# 2. The mode flip, on the same unchanged sources. This is the OBI-328 case.
note "2/4 the same crate, live mode, closed port -- must recompile and must dial"
check env SQLX_OFFLINE=false DATABASE_URL="$URL_A" cargo check -p "$PACKAGE" -v
[ "$CHECK_STATUS" -ne 0 ] ||
    fail "a live-DB build exited 0 against port ${PORT_A}, which nothing listens on.
The macros never connected, so the build was answered from cargo's cache: the
OBI-328 hazard is back. Check that crates/loom-persist/build.rs still emits
cargo:rerun-if-env-changed=SQLX_OFFLINE."
grep -Eq "(Compiling|Checking|Dirty) ${PACKAGE} " <<<"$CHECK_OUT" ||
    fail "${PACKAGE} was not recompiled on the SQLX_OFFLINE flip -- cargo reused the offline artifact:
$(excerpt)"
grep -q "error communicating with database" <<<"$CHECK_OUT" ||
    fail "the live build recompiled but never tried to connect (expected 'error communicating with database'):
$(excerpt)"
note "  -> $(grep -Em1 "(Dirty|Fresh) ${PACKAGE} " <<<"$CHECK_OUT" | sed 's/^ *//')"

# 3. Only DATABASE_URL changes: still live, a different closed port. A live
#    build against a second database must not reuse the first one's expansion.
note "3/4 live mode again, only DATABASE_URL differs -- must recompile and dial again"
check env SQLX_OFFLINE=false DATABASE_URL="$URL_B" cargo check -p "$PACKAGE" -v
[ "$CHECK_STATUS" -ne 0 ] ||
    fail "a second live-DB build (different DATABASE_URL) exited 0 against closed port ${PORT_B}"
# The distinguishing evidence here is cargo's own reason: the previous live
# build failed, so a recompile alone would prove nothing.
grep -Eq "Dirty ${PACKAGE} .*the env variable DATABASE_URL changed" <<<"$CHECK_OUT" ||
    fail "cargo did not report the crate as dirty when only DATABASE_URL changed (if this is a
wording change in cargo rather than a real regression, the rest of this script still
passing is the evidence -- update the pattern, do not delete the check):
$(excerpt)"
grep -q "error communicating with database" <<<"$CHECK_OUT" ||
    fail "the second live build recompiled but never tried to connect:
$(excerpt)"

# 4. Leave the workspace the way a normal `cargo build` would find it: an
#    offline artifact, so nothing after this in CI inherits a half-built crate.
note "4/4 back to the offline default"
check env -u DATABASE_URL SQLX_OFFLINE=true cargo check -p "$PACKAGE" -v
[ "$CHECK_STATUS" -eq 0 ] ||
    fail "the offline build after the probe did not succeed:
$(grep -E "${PACKAGE}|^error|^warning" <<<"$CHECK_OUT" | tail -15)"
grep -Eq "Dirty ${PACKAGE} .*the env variable SQLX_OFFLINE changed" <<<"$CHECK_OUT" ||
    note "  (note: cargo rebuilt for a different reason here, which is fine -- a failed build is never cached)"

note "OK: an offline build and a live-DB build of ${PACKAGE} are separate builds, and each flip names its reason"
