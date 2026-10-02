// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Spec `docs/threat-model-phase2.md` \u00a76.3 **M-LSP-5**: "If run as a
//! subprocess: `env_clear()` + allowlist ... no inherited secrets."
//!
//! `std::env::remove_var`/`set_var` are `unsafe fn` (platform-dependent
//! undefined behaviour with concurrent access), and this crate -- like
//! every crate except `loom-vm` -- carries `unsafe_code = "deny"`
//! (workspace lint, charter: "Confined `unsafe`: only in the `loom-vm`
//! core"). So this does not mutate the running process's own
//! environment; it **re-execs itself** with a clean one, which only
//! needs the safe [`std::process::Command`] builder (the child's
//! environment is configured at spawn time, not the parent's at
//! runtime) -- `std::os::unix::process::CommandExt::exec` replaces the
//! process image without forking, so this costs nothing but one syscall
//! and happens once at startup, before any connection is accepted.

/// Env vars worth keeping across the re-exec: everything else (in
/// particular `DATABASE_URL`, any `*_TOKEN`/`*_SECRET`/`*_KEY`, and every
/// other var a parent process might have exported) is dropped.
pub const ALLOWLIST: &[&str] = &[
    "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "RUST_LOG",
    // The sentinel itself, so the child doesn't re-exec again.
    SENTINEL,
];

/// Set (to any value) once the environment has already been cleared, so
/// `maybe_reexec` is a no-op on the child (and on every process that
/// isn't a subprocess inheriting someone else's secrets to begin with --
/// e.g. a developer running `loom-lsp --stdio` by hand doesn't need this
/// at all, but re-execing once is harmless either way).
const SENTINEL: &str = "LOOM_LSP_ENV_CLEARED";

/// `vars`, filtered down to [`ALLOWLIST`]. Pure and unit-tested
/// separately from the actual re-exec (which needs a real process and a
/// real binary path, not something a unit test should do).
pub fn filtered_env<I: IntoIterator<Item = (String, String)>>(vars: I) -> Vec<(String, String)> {
    vars.into_iter()
        .filter(|(k, _)| ALLOWLIST.contains(&k.as_str()))
        .collect()
}

/// Re-exec the current binary with [`ALLOWLIST`]-filtered environment and
/// the same arguments, unless that has already happened (the sentinel is
/// set) or re-exec isn't available (non-Unix, or the current executable
/// path can't be resolved) -- in which case this silently continues with
/// the inherited environment rather than refusing to start. Never returns
/// on success (the process image is replaced); returns on failure so
/// `main` can decide whether that is fatal.
#[cfg(unix)]
pub fn maybe_reexec() {
    use std::os::unix::process::CommandExt;

    if std::env::var_os(SENTINEL).is_some() {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let kept = filtered_env(std::env::vars());
    let err = std::process::Command::new(exe)
        .args(std::env::args().skip(1))
        .env_clear()
        .envs(kept)
        .env(SENTINEL, "1")
        .exec(); // replaces this process on success; only returns on error
    tracing::warn!(%err, "loom-lsp: re-exec with a cleared environment failed, continuing with the inherited one (M-LSP-5 degraded)");
}

#[cfg(not(unix))]
pub fn maybe_reexec() {
    // No portable "replace this process" primitive outside Unix `exec`;
    // M-LSP-5 is explicitly scoped to "if run as a subprocess", which on
    // the one deployment target that matters (Linux containers) is
    // covered by the `#[cfg(unix)]` path above.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filtered_env_keeps_the_allowlist_and_drops_everything_else() {
        let input = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("DATABASE_URL".to_string(), "postgres://secret".to_string()),
            (
                "GITHUB_APP_PRIVATE_KEY".to_string(),
                "-----BEGIN KEY".to_string(),
            ),
            ("RUST_LOG".to_string(), "info".to_string()),
        ];
        let out = filtered_env(input);
        let keys: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"PATH"));
        assert!(keys.contains(&"RUST_LOG"));
        assert!(!keys.contains(&"DATABASE_URL"));
        assert!(!keys.contains(&"GITHUB_APP_PRIVATE_KEY"));
    }
}
