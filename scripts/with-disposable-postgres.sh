#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
#
# Boot a throwaway, disposable Postgres instance that this run owns,
# export LOOM_TEST_DATABASE_URL/LOOM_TEST_DB_MIGRATE_URL/LOOM_SMOKE_DATABASE_URL
# for it, run the given command, and always tear the instance down
# afterwards -- success, failure, or signal (OBI-151).
#
# Usage:
#   scripts/with-disposable-postgres.sh -- <command> [args...]
#
# Example:
#   scripts/with-disposable-postgres.sh -- \
#     cargo test -p loom-cli --test roles_demo -- --test-threads=1
#
#   scripts/with-disposable-postgres.sh -- \
#     cargo run -p loom-cli -- serve --mudlib mudlib
#
# Never set DATABASE_URL in your shell for this. This script deliberately
# does not read or forward the ambient DATABASE_URL (OBI-150: agent shells
# export it for Paperclip's own control-plane Postgres) -- it always
# creates its own instance and exports the *_TEST_*/LOOM_SMOKE_* names
# instead. loom-cli/loom-persist's DB-backed test harnesses read those
# names, never DATABASE_URL, and `loom serve` only honours
# LOOM_SMOKE_DATABASE_URL/DATABASE_URL if you explicitly export one
# yourself -- which you should not do when using this script.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/disposable-postgres-lib.sh
source scripts/disposable-postgres-lib.sh

if [ "${1:-}" != "--" ]; then
    echo "usage: $0 -- <command> [args...]" >&2
    exit 2
fi
shift

PG_BIN_DIR=$(dpg_find_pg_bin_dir)
export LD_LIBRARY_PATH="${PG_BIN_DIR}/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

SCRATCH_ROOT="${PAPERCLIP_RUN_SCRATCH_DIR:-${PAPERCLIP_SCRATCH_DIR:-${TMPDIR:-/tmp}}}"
DATA_DIR="$(mktemp -d "${SCRATCH_ROOT%/}/loom-disposable-pg.XXXXXX")"
PORT=$(dpg_free_port)
SUPERUSER=loom_owner
APP_USER=loom_app
APP_PASSWORD=loom_app_disposable
DB_NAME=loom

STARTED=0

dpg_cleanup() {
    if [ "$STARTED" = 1 ]; then
        echo "with-disposable-postgres: stopping disposable Postgres (port $PORT, $DATA_DIR)" >&2
        "$PG_BIN_DIR/bin/pg_ctl" -D "$DATA_DIR" -m fast stop >/dev/null 2>&1 || true
    fi
    rm -rf "$DATA_DIR" "$DATA_DIR.initdb.log" "$DATA_DIR-bootstrap.log" "$DATA_DIR-server.log"
}
trap dpg_cleanup EXIT INT TERM

echo "with-disposable-postgres: initdb ($DATA_DIR)" >&2
"$PG_BIN_DIR/bin/initdb" -D "$DATA_DIR" -U "$SUPERUSER" -A trust --no-sync -E UTF8 \
    >"$DATA_DIR.initdb.log" 2>&1 || {
    cat "$DATA_DIR.initdb.log" >&2
    exit 1
}
rm -f "$DATA_DIR.initdb.log"

# Bootstrap the same two-login shape CI's docker service creates (see
# .github/workflows/ci.yml): loom_owner (owns everything, runs migrations)
# and loom_app (world-runtime login, no DDL rights). This must run in
# single-user mode *before* the multi-user postmaster starts (a running
# postmaster holds the data directory's lock file, so --single can't
# attach to it) -- one statement per invocation, because CREATE DATABASE
# cannot run inside the implicit transaction block a multi-statement
# batch gets wrapped in.
dpg_single() {
    echo "$1" | "$PG_BIN_DIR/bin/postgres" --single -D "$DATA_DIR" postgres \
        >>"$DATA_DIR-bootstrap.log" 2>&1
}
dpg_single "CREATE ROLE ${APP_USER} LOGIN PASSWORD '${APP_PASSWORD}';"
dpg_single "CREATE DATABASE ${DB_NAME} OWNER ${SUPERUSER};"
dpg_single "GRANT ALL ON DATABASE ${DB_NAME} TO ${SUPERUSER};"
if grep -qi '^[0-9-]* .*ERROR' "$DATA_DIR-bootstrap.log" 2>/dev/null; then
    echo "with-disposable-postgres: bootstrap SQL failed:" >&2
    cat "$DATA_DIR-bootstrap.log" >&2
    exit 1
fi
rm -f "$DATA_DIR-bootstrap.log"

echo "with-disposable-postgres: starting on 127.0.0.1:$PORT" >&2
"$PG_BIN_DIR/bin/pg_ctl" -D "$DATA_DIR" -l "$DATA_DIR-server.log" \
    -o "-p $PORT -h 127.0.0.1 -k $DATA_DIR -c listen_addresses=127.0.0.1" \
    start >/dev/null
STARTED=1

if ! dpg_wait_ready "$PORT"; then
    echo "with-disposable-postgres: Postgres never became ready; log:" >&2
    cat "$DATA_DIR-server.log" >&2 || true
    exit 1
fi

MIGRATE_URL="postgres://${SUPERUSER}@127.0.0.1:${PORT}/${DB_NAME}"
APP_URL="postgres://${APP_USER}:${APP_PASSWORD}@127.0.0.1:${PORT}/${DB_NAME}"

dpg_assert_not_control_plane_db "$MIGRATE_URL"
dpg_assert_not_control_plane_db "$APP_URL"

export LOOM_TEST_DB_MIGRATE_URL="$MIGRATE_URL"
export LOOM_TEST_DATABASE_URL="$APP_URL"
export LOOM_SMOKE_DATABASE_URL="$APP_URL"
export LOOM_REQUIRE_DB="${LOOM_REQUIRE_DB:-1}"
# Belt-and-suspenders: make sure nothing in the child's environment can
# fall back to the ambient control-plane DATABASE_URL (OBI-150).
unset DATABASE_URL
unset LOOM_DB_MIGRATE_URL

echo "with-disposable-postgres: ready ($MIGRATE_URL / $APP_URL); running: $*" >&2
"$@"
