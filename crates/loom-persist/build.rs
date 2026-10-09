// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Make cargo see the sqlx build mode (OBI-328).
//!
//! `sqlx::query!` expands at compile time, and *what* it expands against --
//! the committed `.sqlx/` cache, or a live `DESCRIBE` on `DATABASE_URL` -- is
//! chosen by environment variables cargo knows nothing about. Without this
//! file, `loom-persist`'s cargo fingerprint is identical whether the macros
//! talked to a database or not, so a build that is *meant* to be live-DB can be
//! answered straight from the cache: `Finished dev profile`, exit 0, and not
//! one packet sent to Postgres. Measured on OBI-321 (verification doc, section
//! 5) and re-measured for this issue, with a closed localhost port as
//! `DATABASE_URL` so that any dial is loud:
//!
//! ```text
//! unchanged crate + SQLX_OFFLINE=false -> Finished, exit 0, no dial
//! touch src/lib.rs, same command       -> error communicating with database:
//!                                         Connection refused (os error 111)
//! ```
//!
//! The fix therefore has to be a build-script directive, not a flag: name the
//! environment variables the macros read, and cargo re-runs this script -- and
//! recompiles the crate, which is what re-expands the macros -- when any of
//! them changes value. Two properties of what is emitted below:
//!
//! * `SQLX_OFFLINE` is always watched: it is the switch itself.
//! * `DATABASE_URL` (live build) and `SQLX_OFFLINE_DIR` (offline build) are
//!   watched only when the mode being compiled actually reads them. Watching
//!   the URL in offline builds too would make every unrelated `DATABASE_URL`
//!   change -- an agent shell, a different local port -- rebuild
//!   `loom-persist` and relink everything under it for a variable the macros
//!   never look at.
//!
//! `.env` is in the picture because sqlx's macros read it as a fallback
//! (`sqlx-macros-core`'s `load_dot_env`), so it can change what the macros read
//! with no process-environment change at all. Both places sqlx looks for it are
//! watched, and the mode below is resolved with the same precedence. Only files
//! that exist are named: a `rerun-if-changed` path that does not exist makes
//! cargo re-run the script and recompile the crate on *every* build (measured,
//! 0.27 s of `Compiling loom-persist` per invocation), so a `.env` created after
//! a build is picked up on the next rebuild rather than immediately. That is
//! acceptable because the workspace `[env]` pin means the mode itself never
//! comes from `.env` -- and because a live build is told its URL explicitly, per
//! docs/persistence.md.
//!
//! What this does *not* cover: the contents of `.sqlx/`. The macros read the
//! cache without recording a dependency on it, so editing a cache file with
//! unchanged sources is still a cache hit (measured: `Finished` in 0.14 s with
//! a deliberately unparseable `parameters.Left` type, then
//! `error: unknown variant BogusType` after `cargo clean -p loom-persist`).
//! That is why `scripts/sqlx-prepare.sh` still cleans the package before its
//! offline re-check, and why an unrelated `.sqlx/` refresh must not be trusted
//! to have re-validated anything.

use std::path::{Path, PathBuf};

/// Package root (`crates/loom-persist`).
fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Workspace root: `loom-persist` is a first-level member of `crates/`.
fn workspace_root() -> PathBuf {
    manifest_dir()
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(manifest_dir)
}

/// The `.env` files sqlx falls back to, in the order it tries them.
fn dot_env_files() -> Vec<PathBuf> {
    [manifest_dir().join(".env"), workspace_root().join(".env")]
        .into_iter()
        .filter(|path| path.is_file())
        .collect()
}

/// `KEY=value` from the first `.env` that defines it -- non-empty values only.
fn from_dot_env(key: &str) -> Option<String> {
    for path in dot_env_files() {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            let Some(rest) = line
                .strip_prefix(key)
                .map(str::trim_start)
                .and_then(|rest| rest.strip_prefix('='))
            else {
                continue;
            };
            let value = rest.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Read a variable the way the sqlx macro does: process environment, then
/// `.env`.
fn sqlx_env(key: &str) -> Option<String> {
    std::env::var(key).ok().or_else(|| from_dot_env(key))
}

/// sqlx 0.8 turns offline mode on for `"true"` (any case) or `"1"`, and for
/// nothing else. This has to match: disagreeing the "safe" way recompiles for a
/// mode change that never happened, disagreeing the other way is this bug.
fn offline_mode() -> bool {
    sqlx_env("SQLX_OFFLINE").is_some_and(|value| value.eq_ignore_ascii_case("true") || value == "1")
}

fn main() {
    // Emitting any rerun directive replaces cargo's default "re-run when
    // anything in the package changes", so name the script itself too.
    println!("cargo:rerun-if-changed=build.rs");
    for path in dot_env_files() {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // The switch, always.
    println!("cargo:rerun-if-env-changed=SQLX_OFFLINE");

    // Then whatever the macros read *in this mode*.
    if offline_mode() {
        println!("cargo:rerun-if-env-changed=SQLX_OFFLINE_DIR");
    } else {
        println!("cargo:rerun-if-env-changed=DATABASE_URL");
    }
}
