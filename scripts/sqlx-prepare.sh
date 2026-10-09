#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
#
# Refresh the committed sqlx query cache (`.sqlx/`, workspace root) for
# `loom-persist`'s `query!` macros -- against a Postgres this run owns and
# throws away, never against the ambient `DATABASE_URL` (OBI-321, OBI-151).
#
# Why this exists: `.cargo/config.toml` makes `SQLX_OFFLINE=true` the
# default, so a plain `cargo build` compiles the macros from `.sqlx/` and
# never connects. That is the right default, but it means the cache is now
# the only thing standing between a query edit and a compile error, so the
# refresh path has to be one obvious command that cannot point at somebody
# else's database. A bare `cargo sqlx prepare` in an agent shell would use
# `DATABASE_URL`, and on a Paperclip agent shell `DATABASE_URL` is
# Paperclip's control-plane Postgres (OBI-150).
#
# Usage (from anywhere in the repo):
#   scripts/sqlx-prepare.sh
#
# What it does:
#   1. re-exec itself under `scripts/with-disposable-postgres.sh`, which
#      boots a throwaway instance, exports `LOOM_TEST_*` URLs and unsets
#      `DATABASE_URL`/`LOOM_DB_MIGRATE_URL`;
#   2. applies `loom-persist`'s migrations to it as `loom_owner`;
#   3. runs `cargo sqlx prepare` with the one explicit `SQLX_OFFLINE=false`
#      opt-in the build system needs (that is how the live-DB refresh is
#      allowed to override the workspace default -- `force = false` in
#      `.cargo/config.toml` means an environment value still wins);
#   4. re-checks the macros offline, from the cache just written, with the
#      overrides removed -- so a refresh that produces a cache the default
#      build cannot use fails here instead of in CI.
#
# Then review `git diff .sqlx` and commit it with the query change.

set -euo pipefail
cd "$(dirname "$0")/.."

# Step 1: run inside the disposable instance, always. If the marker isn't
# set we are *outside* it, so hand off and re-exec -- do not connect.
if [ "${LOOM_SQLX_PREPARE_IN_DISPOSABLE:-}" != "1" ]; then
    export LOOM_SQLX_PREPARE_IN_DISPOSABLE=1
    exec scripts/with-disposable-postgres.sh -- scripts/sqlx-prepare.sh
fi

# Below here we are the child of `with-disposable-postgres.sh`: a Postgres
# booted by this run, on 127.0.0.1, that nothing else can reach.
if [ -z "${LOOM_TEST_DB_MIGRATE_URL:-}" ]; then
    echo "sqlx-prepare: LOOM_TEST_DB_MIGRATE_URL is unset -- expected to run under" >&2
    echo "  scripts/with-disposable-postgres.sh (which step 1 above re-execs into)." >&2
    exit 1
fi

if ! cargo sqlx --version >/dev/null 2>&1; then
    echo 'sqlx-prepare: the "cargo sqlx" subcommand is missing.' >&2
    echo '  install it with: cargo install sqlx-cli --no-default-features --features postgres' >&2
    exit 1
fi

# Step 2: the schema has to exist before `DESCRIBE` can read it. Migrations
# run as loom_owner (D-27.4); `loom migrate` reads LOOM_DB_MIGRATE_URL, which
# the parent script deliberately leaves unset, so map the disposable owner
# URL onto it here rather than inventing a second entrypoint.
echo "sqlx-prepare: applying migrations to the disposable database"
LOOM_DB_MIGRATE_URL="$LOOM_TEST_DB_MIGRATE_URL" cargo run -q -p loom-cli -- migrate

# Step 3: the opt-in. `sqlx-cli`'s own `prepare` also sets SQLX_OFFLINE=false
# on the `cargo check` it spawns; setting it here too keeps the intent legible
# and does not depend on that internal. DATABASE_URL is the *owner* URL: the
# macros must be able to describe tables *and* `security definer` functions,
# which the unprivileged `loom_app` login cannot show (and CI's cache was
# generated the same way -- see docs/persistence.md).
#
# Note where `-p` goes: sqlx-cli 0.8's `prepare` has no package selection of
# its own -- everything after `--` is passed to the `cargo check` it runs, so
# the package and target filters belong there. `loom-persist` is the only
# crate with `query!` macros, and `--tests` is what pulls in the macros its
# integration tests use.
echo "sqlx-prepare: refreshing .sqlx/ from the disposable database"
SQLX_OFFLINE=false DATABASE_URL="$LOOM_TEST_DB_MIGRATE_URL" \
    cargo sqlx prepare --workspace -- -p loom-persist --tests

# Step 4: prove the default (offline) build can use what we just wrote.
# `SQLX_OFFLINE` is not part of cargo's fingerprint, so a cached `cargo check`
# would silently do nothing; drop loom-persist's artifacts first so the
# macros really do re-expand against `.sqlx/`.
echo "sqlx-prepare: re-checking the macros offline from the refreshed cache"
unset SQLX_OFFLINE DATABASE_URL
cargo clean -p loom-persist
cargo check -p loom-persist -p loom-cli --tests

changed=$(git status --porcelain .sqlx | wc -l)
if [ "$changed" = "0" ]; then
    echo "sqlx-prepare: .sqlx/ unchanged (cache already matched the database + queries)"
else
    echo "sqlx-prepare: .sqlx/ changed ($changed files); review 'git diff .sqlx' and commit it"
fi
