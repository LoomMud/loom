# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
#
# Shared functions for scripts/with-disposable-postgres.sh (OBI-151).
# Not meant to be run directly -- `source` it.
#
# OBI-150/OBI-151 background: agent shells export DATABASE_URL pointing at
# Paperclip's own control-plane Postgres. loom/warp Postgres-backed
# integration tests (roles_demo, loom-persist's own suite) and any local
# smoke-test run of `loom serve` must never touch that database. This
# library finds (or fails loudly asking for) a real Postgres server
# binary bundle already present on the machine, boots a throwaway
# instance on a random localhost port under a private, per-run data
# directory, and bootstraps the same two-login shape (`loom_owner`,
# `loom_app`) CI's docker service uses -- no `docker`, no system package
# install, and no network access required at run time.

set -euo pipefail

# Locate a directory containing bin/{initdb,pg_ctl,postgres} (and, for the
# vendored bundle case, lib/*.so next to them). Search order:
#   1. LOOM_DISPOSABLE_PG_DIR, if the caller already knows where one is.
#   2. `initdb`/`pg_ctl`/`postgres` already on PATH (a system install).
#   3. A vendored `@embedded-postgres/<os>-<arch>` npm package already
#      present under a pnpm store on this machine (no network fetch: it's
#      either there already or this step fails with an actionable error).
dpg_find_pg_bin_dir() {
    if [ -n "${LOOM_DISPOSABLE_PG_DIR:-}" ]; then
        if [ -x "$LOOM_DISPOSABLE_PG_DIR/bin/initdb" ]; then
            echo "$LOOM_DISPOSABLE_PG_DIR"
            return 0
        fi
        echo "with-disposable-postgres: LOOM_DISPOSABLE_PG_DIR=$LOOM_DISPOSABLE_PG_DIR has no bin/initdb" >&2
        return 1
    fi

    if command -v initdb >/dev/null 2>&1 && command -v pg_ctl >/dev/null 2>&1; then
        local initdb_path
        initdb_path=$(command -v initdb)
        echo "$(cd "$(dirname "$initdb_path")/.." && pwd)"
        return 0
    fi

    local arch pkg_arch candidate
    arch=$(uname -m)
    case "$arch" in
        x86_64) pkg_arch=x64 ;;
        aarch64 | arm64) pkg_arch=arm64 ;;
        *) pkg_arch="$arch" ;;
    esac

    # Search a handful of plausible pnpm/npm store roots for the vendored
    # binaries. Bounded depth: these stores can be large.
    local roots=(
        "/app/node_modules/.pnpm"
        "$HOME/.local/share/pnpm/store"
        "$PWD/node_modules/.pnpm"
    )
    for root in "${roots[@]}"; do
        [ -d "$root" ] || continue
        candidate=$(find "$root" -maxdepth 2 -type d \
            -iname "@embedded-postgres+linux-${pkg_arch}@*" 2>/dev/null | head -n1) || true
        if [ -n "$candidate" ]; then
            local native="$candidate/node_modules/@embedded-postgres/linux-${pkg_arch}/native"
            if [ -x "$native/bin/initdb" ]; then
                echo "$native"
                return 0
            fi
        fi
    done

    cat >&2 <<'EOF'
with-disposable-postgres: no Postgres server binaries found.

Tried, in order:
  1. $LOOM_DISPOSABLE_PG_DIR (not set)
  2. initdb/pg_ctl/postgres on PATH (not found)
  3. a vendored @embedded-postgres/linux-<arch> npm package under a local
     pnpm store (none found)

Fix one of:
  - set LOOM_DISPOSABLE_PG_DIR to a directory with bin/{initdb,pg_ctl,postgres}
  - `npm install @embedded-postgres/linux-x64` (or -arm64) somewhere and
    point LOOM_DISPOSABLE_PG_DIR at its `native` directory
  - install a system postgresql-server package, if this runtime allows it

If none of these are possible in this agent runtime, this is an
infra/board ask (OBI-151 scope item 2) -- report back on that issue with
which of the above is missing.
EOF
    return 1
}

# A free localhost TCP port, chosen the same way `reserve_local_port()` in
# the Rust test harnesses does: bind port 0 and read back what the kernel
# assigned, then release it immediately. There is an inherent TOCTOU race
# (another process could grab the port before postgres binds it); retried
# by the caller's own readiness loop if postgres itself fails to bind.
dpg_free_port() {
    python3 - <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
EOF
}

dpg_wait_ready() {
    local port="$1" tries=0
    while [ "$tries" -lt 100 ]; do
        if python3 - "$port" <<'EOF' >/dev/null 2>&1
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1)
s.close()
EOF
        then
            return 0
        fi
        tries=$((tries + 1))
        sleep 0.2
    done
    return 1
}

# OBI-151 hard guard, shell-side mirror of
# loom_persist::assert_not_control_plane_db (belt-and-suspenders: this
# script never points ANYTHING at a URL like this, but if a future caller
# passes one in by mistake, fail loudly instead of quietly reusing it).
dpg_assert_not_control_plane_db() {
    local url="$1"
    case "$url" in
        *@postgres:5432/* | *@postgres:5432)
            echo "with-disposable-postgres: refusing to use $url (looks like Paperclip's control-plane DB host)" >&2
            return 1
            ;;
    esac
    case "$url" in
        */paperclip | */paperclip\?*)
            echo "with-disposable-postgres: refusing to use $url (looks like Paperclip's control-plane database name)" >&2
            return 1
            ;;
    esac
    return 0
}
