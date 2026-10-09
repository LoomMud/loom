// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Guards the workspace-wide sqlx offline default (OBI-321).
//!
//! `loom-persist`'s `query!` macros expand at compile time. Unless
//! `SQLX_OFFLINE` is set they connect to whatever `DATABASE_URL` says and
//! `DESCRIBE` the schema -- and on a dev or agent shell `DATABASE_URL` is an
//! unrelated live database (on a Paperclip agent shell, Paperclip's own
//! control-plane Postgres, OBI-150). The build then fails with messages that
//! read like a broken migration, next to a database someone may then "repair".
//!
//! `.cargo/config.toml` at the workspace root is what makes an offline build
//! the default. This test is the guard against it quietly disappearing, being
//! renamed, or being edited into a form that no longer works:
//!
//! - the `[env] SQLX_OFFLINE` entry must default to offline, and
//! - it must keep `force = false`, because a *forced* value would also defeat
//!   `SQLX_OFFLINE=false` and `cargo sqlx prepare` -- the documented opt-in to
//!   a live-DB build and the only way to refresh the cache
//!   (`scripts/sqlx-prepare.sh`, `docs/persistence.md`), and
//! - the committed `.sqlx/` cache must exist, because with no cache an offline
//!   default turns every query edit into a build that cannot compile.
//!
//! OBI-328 adds a fourth thing to guard: `crates/loom-persist/build.rs`, which
//! puts the mode switch into cargo's fingerprint so that an offline build and a
//! live-DB build are never the same cached artifact. `force = false` is what
//! makes a live build *possible*; the build script is what makes it *real*.
//!
//! The scan is deliberately not a TOML parser (no new dependency for a build
//! config check): `[env]` is a single table, keys are matched literally, and
//! every rejection names the reason so a human fixes the file, not the test.
//! The build-script checks below are a tripwire against that file quietly
//! disappearing or losing a directive -- the behaviour itself is proven by
//! `scripts/check-sqlx-cache-modes.sh`, which runs in CI (a unit test cannot
//! nest a `cargo check` inside the `cargo test` holding the build-dir lock).

use std::path::{Path, PathBuf};

/// The right-hand side of an `[env]` assignment, as written.
#[derive(Debug)]
enum Assignment<'a> {
    /// `KEY = "value"` -- cargo's `force` defaults to false.
    Bare(&'a str),
    /// `KEY = { value = "…", force = … }`
    Table {
        value: &'a str,
        force: Option<&'a str>,
    },
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates| crates.parent())
        .expect("loom-persist lives at <workspace>/crates/loom-persist")
        .to_path_buf()
}

/// Drop a trailing `# comment`, respecting quoted strings so a `#` inside a
/// value does not truncate the line.
fn code_part(line: &str) -> &str {
    let mut in_string = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '"' => in_string = !in_string,
            '#' if !in_string => return &line[..index],
            _ => {}
        }
    }
    line
}

/// `"…"` -> the inner text, or `None` if the token is not a quoted string.
fn quoted(text: &str) -> Option<&str> {
    let rest = text.trim().strip_prefix('"')?;
    Some(rest.strip_suffix('"')?.trim())
}

/// `KEY = <rhs>` for one line, if the line is an assignment.
fn assignment_for(line: &str) -> Option<(&str, Assignment<'_>)> {
    let (key, rhs) = code_part(line).trim().split_once('=')?;
    let key = key.trim();
    let rhs = rhs.trim();
    if key.is_empty() {
        return None;
    }
    let assignment = if let Some(inner) = rhs.strip_prefix('{').and_then(|i| i.strip_suffix('}')) {
        let mut value = None;
        let mut force = None;
        for part in inner.split(',') {
            let (name, val) = part.split_once('=')?;
            match name.trim() {
                "value" => value = Some(quoted(val)?),
                "force" => force = Some(val.trim()),
                // An unexpected key here is not an [env] assignment we
                // recognise: skip the line rather than read a value we do
                // not understand.
                _ => return None,
            }
        }
        Assignment::Table {
            value: value?,
            force,
        }
    } else {
        Assignment::Bare(quoted(rhs)?)
    };
    Some((key, assignment))
}

/// The body of the `[env]` table (cargo applies those keys to `rustc`, build
/// scripts and `cargo run`/`test` children; the same key under another table
/// would never reach the macro).
fn env_table_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut in_env = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_env = trimmed == "[env]";
            continue;
        }
        if in_env && !trimmed.is_empty() {
            lines.push(line.to_string());
        }
    }
    lines
}

#[test]
fn sqlx_offline_is_the_workspace_default() {
    let path = workspace_root().join(".cargo/config.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "{} is missing ({err}). It pins SQLX_OFFLINE=true for the workspace: without it, \
             `cargo build` runs sqlx's compile-time query! macros against the ambient \
             DATABASE_URL -- on an agent shell that is Paperclip's control-plane Postgres \
             (OBI-150/OBI-321). Restore the file; do not 'fix' a database instead.",
            path.display()
        )
    });

    let mut keys = Vec::new();
    let mut matches = 0usize;
    let mut value = String::new();
    let mut force: Option<String> = None;
    for line in env_table_lines(&text) {
        let Some((key, assignment)) = assignment_for(&line) else {
            continue;
        };
        keys.push(key.to_string());
        if key != "SQLX_OFFLINE" {
            continue;
        }
        matches += 1;
        match assignment {
            Assignment::Bare(v) => value = v.to_string(),
            Assignment::Table { value: v, force: f } => {
                value = v.to_string();
                force = f.map(str::to_string);
            }
        }
    }

    assert_eq!(
        matches,
        1,
        "{} must hold exactly one `[env] SQLX_OFFLINE` assignment; found {matches} \
         (keys seen in [env]: {keys:?})",
        path.display()
    );

    // sqlx 0.8's macro turns offline mode on for "true" (any case) or "1".
    assert!(
        value.eq_ignore_ascii_case("true") || value == "1",
        "`[env] SQLX_OFFLINE` must default the workspace to an offline build; found \
         {value:?} in {}",
        path.display()
    );

    // `force = true` would override the shell -- and the shell is exactly how
    // a live-DB build stays available: `SQLX_OFFLINE=false`, and
    // `scripts/sqlx-prepare.sh`, refresh the cache against a real database.
    if let Some(force) = &force {
        assert_eq!(
            force, "false",
            "`[env] SQLX_OFFLINE` must keep `force = false` so an explicit \
             SQLX_OFFLINE=false still opts back in to a live-DB build; found force = {force:?}"
        );
    }
}

/// Every variable that decides what `sqlx::query!` expands against, as cargo
/// `rerun-if-env-changed` directives. `SQLX_OFFLINE` is the switch; the other
/// two are what the macros read *once the switch is set* (`DATABASE_URL` when
/// live, `SQLX_OFFLINE_DIR` when offline) -- see `crates/loom-persist/build.rs`
/// for why each is watched only in the mode that reads it.
const SQLX_MODE_DIRECTIVES: [&str; 3] = [
    "cargo:rerun-if-env-changed=SQLX_OFFLINE",
    "cargo:rerun-if-env-changed=DATABASE_URL",
    "cargo:rerun-if-env-changed=SQLX_OFFLINE_DIR",
];

#[test]
fn build_script_pins_the_sqlx_mode_into_cargos_fingerprint() {
    // Cargo does not hash SQLX_OFFLINE into a crate's fingerprint, and a macro
    // recompile is only forced by a source change. Without this build script,
    // `SQLX_OFFLINE=false` on an unchanged `loom-persist` is answered from the
    // cache: `Finished`, exit 0, and no DESCRIBE ever reaches Postgres -- a
    // green build that proved nothing (OBI-321 verification doc, section 5;
    // re-measured for OBI-328 as `Fresh loom-persist ... Finished in 0.14s`).
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("build.rs");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "{} is missing ({err}). It is what makes a mode change force a re-check: cargo's \
             fingerprint does not include SQLX_OFFLINE, so a live-DB build of an unchanged \
             loom-persist is silently a cache hit (OBI-328). Restore it; \
             scripts/check-sqlx-cache-modes.sh proves the behaviour.",
            path.display()
        )
    });

    for directive in SQLX_MODE_DIRECTIVES {
        assert!(
            text.contains(directive),
            "{} must emit `{directive}`: those are the variables the sqlx macros read, and a \
             change to one that cargo has not been told about is a cached artifact, not a \
             rebuild",
            path.display()
        );
    }

    // The switch cannot itself be behind the mode test: emitting it only in one
    // branch means the flip *out* of that branch is invisible to cargo -- which
    // is the exact bug this file exists to prevent.
    let switch = SQLX_MODE_DIRECTIVES[0];
    let switch_at = text.find(switch).expect("checked above");
    let mode_branch_at = text.find("if offline_mode()").unwrap_or(usize::MAX);
    assert!(
        switch_at < mode_branch_at,
        "`{switch}` must be emitted unconditionally in {}, before the branch that picks the \
         mode-dependent watches; found it at byte {switch_at} and `if offline_mode()` at {mode_branch_at}",
        path.display()
    );

    // The mode has to be resolved the way the macro resolves it, or the watches
    // below the branch are chosen for a mode that is not the one being built.
    // sqlx 0.8: `SQLX_OFFLINE` is offline for "true" (any case) or "1", and for
    // nothing else (`sqlx-macros-core::query::init_metadata`).
    assert!(
        text.contains("eq_ignore_ascii_case(\"true\")") && text.contains("== \"1\""),
        "{} must resolve SQLX_OFFLINE with sqlx's own truthiness (\"true\" in any case, or \
         \"1\"); a different rule picks the wrong set of watches",
        path.display()
    );

    // sqlx also falls back to `.env`, so a mode flip can happen with no process
    // environment change at all; the script has to watch the file instead.
    assert!(
        text.contains(".env") && text.contains("cargo:rerun-if-changed="),
        "{} must watch the `.env` files sqlx falls back to (via `cargo:rerun-if-changed`), \
         otherwise a mode set there is invisible to cargo's fingerprint",
        path.display()
    );
}

#[test]
fn committed_sqlx_cache_exists_for_the_offline_default() {
    let dir = workspace_root().join(".sqlx");
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("{} is missing ({err})", dir.display()));
    let cached = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("query-") && name.ends_with(".json")
        })
        .count();
    assert!(
        cached > 0,
        "{} holds no query-*.json cache files. With SQLX_OFFLINE defaulting to true, `cargo \
         build` compiles the macros from that cache, so an empty cache means every query! fails \
         to build. Refresh it with scripts/sqlx-prepare.sh (a disposable Postgres) and commit \
         the result.",
        dir.display()
    );
}
