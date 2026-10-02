// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Thin wrapper over the `git` CLI (D-B3.1). Every call goes through
//! [`Repo::git`]/[`Repo::git_authed`], so there is exactly one place that
//! builds the argv and (for the authed variant) injects credentials --
//! the thing the D-B3.11 test inspects.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitError {
    /// `git` exited non-zero; `stderr` is included for diagnostics (never
    /// a token -- see [`Repo::git_authed`]).
    Failed {
        args: Vec<String>,
        status: i32,
        stderr: String,
    },
    /// The `git` binary itself could not be spawned.
    Spawn(String),
    /// Output was not valid UTF-8.
    Utf8,
    /// A tree-lock guard could not be acquired (sync in progress).
    SyncInProgress,
    /// No `TokenProvider` configured; push/fetch over the authenticated
    /// remote is disabled.
    NoToken,
    /// The provider itself failed to produce a token.
    TokenProvider(String),
}

impl std::fmt::Display for GitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitError::Failed {
                args,
                status,
                stderr,
            } => {
                write!(f, "git {} exited {status}: {stderr}", args.join(" "))
            }
            GitError::Spawn(e) => write!(f, "failed to spawn git: {e}"),
            GitError::Utf8 => write!(f, "git output was not valid UTF-8"),
            GitError::SyncInProgress => write!(f, "mudlib sync in progress, retry"),
            GitError::NoToken => write!(f, "no git token provider configured"),
            GitError::TokenProvider(e) => write!(f, "token provider failed: {e}"),
        }
    }
}

impl std::error::Error for GitError {}

/// `GIT_DIR`/work-tree pair (D-B3.2): a separate git dir
/// (`/mudlib-git/warp.git`), work tree = the mudlib root. Nothing named
/// `.git` exists anywhere under the work tree.
///
/// Only the **main** repo (git dir + mudlib work tree) is addressed this
/// way. A `git worktree add`-created scratch/rebuild tree is a distinct
/// administrative area under `$GIT_DIR/worktrees/<name>/` with its own
/// `HEAD`/index; passing the *main* repo's `--git-dir`/`--work-tree` pair
/// to target it silently operates on the **main** worktree's `HEAD`
/// instead (a real git CLI footgun -- verified empirically while writing
/// the conflict-policy tests). [`WorktreeRepo`] is the correct handle for
/// those.
#[derive(Debug, Clone)]
pub struct Repo {
    pub git_dir: PathBuf,
    pub work_tree: PathBuf,
}

/// A `git worktree add`-created directory (scratch rebase / conflict
/// rebuild). Addressed by `current_dir` + git's own discovery of the
/// `.git` file it wrote there, which is the only way to reach *that*
/// worktree's own `HEAD`/index rather than the main repo's.
#[derive(Debug, Clone)]
pub struct WorktreeRepo {
    pub dir: PathBuf,
}

impl WorktreeRepo {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn git(&self, args: &[&str]) -> Result<Output, GitError> {
        let mut cmd = Command::new("git");
        cmd.current_dir(&self.dir);
        harden(&mut cmd);
        cmd.args(args);
        run(cmd, args)
    }
}

/// R1/R2 hardening applied to **every** `git` child this crate spawns
/// (CTO review OBI-209):
/// - `GIT_LITERAL_PATHSPECS=1`: a mudlib path may legally contain `*`,
///   `?`, `[` (`fileio::resolve` only forbids `..`, NUL and `.git`
///   segments). Without this, `git add -- <path>` and friends treat such
///   a path as a glob/`:(magic)` pathspec, which can stage *other*
///   builders' still-uncommitted files into this commit under the wrong
///   author and DCO sign-off (R1, verified empirically: `git add --
///   'd/*.wf'` with a dirty `d/a.wf` stages both).
/// - `GIT_TERMINAL_PROMPT=0`: never block the worker thread on an
///   interactive credential prompt.
fn harden(cmd: &mut Command) {
    cmd.env("GIT_LITERAL_PATHSPECS", "1");
    cmd.env("GIT_TERMINAL_PROMPT", "0");
}

impl Repo {
    pub fn new(git_dir: impl Into<PathBuf>, work_tree: impl Into<PathBuf>) -> Self {
        Self {
            git_dir: git_dir.into(),
            work_tree: work_tree.into(),
        }
    }

    fn base_command(&self) -> Command {
        let mut cmd = Command::new("git");
        cmd.arg("--git-dir").arg(&self.git_dir);
        cmd.arg("--work-tree").arg(&self.work_tree);
        harden(&mut cmd);
        cmd
    }

    /// Build (but do not run) the unauthenticated command for `args`.
    /// Exposed so tests can inspect the exact argv a caller would spawn
    /// without needing to run it.
    pub fn build(&self, args: &[&str]) -> Command {
        let mut cmd = self.base_command();
        cmd.args(args);
        cmd
    }

    /// Run a `git` subcommand that never touches a remote: no token is
    /// ever needed or passed.
    pub fn git(&self, args: &[&str]) -> Result<Output, GitError> {
        run(self.build(args), args)
    }

    /// Build (but do not run) the authenticated command for `args`
    /// (CTO review R3, OBI-190/OBI-209): the one place that constructs
    /// the credential-bearing `Command`, so a test can inspect its argv
    /// and env without a network call. `token` is `None` when no
    /// [`crate::TokenProvider`] is configured (push/fetch disabled,
    /// D-B3.5) -- callers must not fall back to an unauthenticated
    /// remote call in that case (R2).
    pub fn build_authed(&self, args: &[&str], token: &str) -> Command {
        let mut cmd = self.base_command();
        cmd.args(args);
        // `x-access-token:<token>` is the scheme GitHub Apps document for
        // installation tokens over HTTP Basic; carried as a pre-built
        // `Authorization` header value through env-only git config so it
        // never lands in argv, the URL, or the repo's on-disk config.
        let header = format!("Authorization: Basic {}", basic_auth(token));
        cmd.env("GIT_CONFIG_COUNT", "2");
        cmd.env("GIT_CONFIG_KEY_0", "http.extraHeader");
        cmd.env("GIT_CONFIG_VALUE_0", header);
        // R2: an empty `credential.helper` plus `GIT_TERMINAL_PROMPT=0`
        // (set globally by `harden`, repeated here for emphasis) means
        // git can never silently fall back to an ambient credential
        // helper or `~/.git-credentials` if the header above is ever
        // wrong/missing -- it fails loudly instead of using some other
        // identity (D-B3.11).
        cmd.env("GIT_CONFIG_KEY_1", "credential.helper");
        cmd.env("GIT_CONFIG_VALUE_1", "");
        // Belt-and-braces (non-blocking CTO review note): never let an
        // ambient trace env turn the header into a log line, and redact
        // credentials from whatever trace git does emit.
        cmd.env_remove("GIT_TRACE_CURL");
        cmd.env_remove("GIT_CURL_VERBOSE");
        cmd.env("GIT_TRACE_REDACT", "1");
        cmd
    }

    /// Run a `git` subcommand that talks to a remote, with credentials
    /// (D-B3.11) injected **only** through the child's environment via
    /// `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_*`/`GIT_CONFIG_VALUE_*`
    /// (`http.extraHeader`), never in argv, the remote URL, or
    /// `.git/config`. `token` is `None` when no [`crate::TokenProvider`]
    /// is configured; returns [`GitError::NoToken`] rather than ever
    /// silently running `args` unauthenticated (R2, CTO review OBI-209).
    pub fn git_authed(&self, args: &[&str], token: Option<&str>) -> Result<Output, GitError> {
        let Some(token) = token else {
            return Err(GitError::NoToken);
        };
        run(self.build_authed(args, token), args)
    }

    /// Run `args` with extra environment variables and/or stdin bytes,
    /// piped through this repo's hardened base command. The one spot
    /// `propose` (B3.3) builds a commit through git plumbing (`read-tree`
    /// / `hash-object` / `update-index` / `write-tree` / `commit-tree`)
    /// without a full working-tree checkout.
    pub(crate) fn git_piped(
        &self,
        args: &[&str],
        envs: &[(&str, &str)],
        stdin: Option<&[u8]>,
    ) -> Result<Output, GitError> {
        use std::io::Write;
        use std::process::Stdio;
        let mut cmd = self.build(args);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        if stdin.is_some() {
            cmd.stdin(Stdio::piped());
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| GitError::Spawn(e.to_string()))?;
        if let Some(data) = stdin {
            child
                .stdin
                .take()
                .expect("stdin requested above")
                .write_all(data)
                .map_err(|e| GitError::Spawn(e.to_string()))?;
        }
        let output = child
            .wait_with_output()
            .map_err(|e| GitError::Spawn(e.to_string()))?;
        if !output.status.success() {
            return Err(GitError::Failed {
                args: args.iter().map(|s| s.to_string()).collect(),
                status: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(output)
    }

    /// Whether this repo has already been seeded (D-B3.6: `mudlib-sync`
    /// becomes seed-only once this is true). Not called from anywhere in
    /// this crate yet -- the seeding step is B3.5's gitops/bootstrap
    /// wiring, not this crate's job; kept here because it is the natural
    /// place for that caller to ask the question.
    #[allow(dead_code)]
    pub fn exists(&self) -> bool {
        self.git_dir.join("HEAD").exists()
    }
}

fn basic_auth(token: &str) -> String {
    base64_encode(format!("x-access-token:{token}").as_bytes())
}

/// Minimal base64 (standard alphabet, padded) so this crate does not pull
/// in the `base64` crate for one call site.
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn run(mut cmd: Command, args: &[&str]) -> Result<Output, GitError> {
    let output = cmd.output().map_err(|e| GitError::Spawn(e.to_string()))?;
    if !output.status.success() {
        return Err(GitError::Failed {
            args: args.iter().map(|s| s.to_string()).collect(),
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(output)
}

pub fn stdout_string(output: &Output) -> Result<String, GitError> {
    String::from_utf8(output.stdout.clone()).map_err(|_| GitError::Utf8)
}

/// P0 driver rule (D-B3.2): reject any path with a `.git` segment,
/// regardless of master policy. Mirrors (and is kept independent of)
/// `loom_vm::fileio::resolve`'s own `.git` check -- this crate has no
/// dependency on `loom-vm`, so both sides enforce it rather than share
/// code across the crate boundary.
pub fn rejects_git_segment(path: &str) -> bool {
    path.split('/').any(|seg| seg.eq_ignore_ascii_case(".git"))
}

/// Make `input` safe as one `/`-separated component of a git ref name
/// (R5b, CTO review OBI-209): a conflict ref embeds a uid, which is
/// attacker-influenced (R5b names `%an`, the commit author name, as the
/// source -- itself derived from a uid a builder chose at account
/// creation). Conservative allow-list rather than shelling out to `git
/// check-ref-format`: every character outside `[A-Za-z0-9._-]` becomes
/// `_`, leading dots and a trailing `.lock` are defused, and an empty
/// result falls back to a fixed placeholder so the ref is still
/// constructible.
pub fn sanitize_ref_component(input: &str) -> String {
    let mut out: String = input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    while out.starts_with('.') {
        out.remove(0);
    }
    while out.contains("..") {
        out = out.replace("..", "_");
    }
    if out.ends_with(".lock") {
        out.push('_');
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

/// Bootstrap-only helper for tests and B3.5's seeding step (D-B3.6): not
/// called anywhere in this crate's own runtime path.
#[allow(dead_code)]
pub fn init_bare(dir: &Path) -> Result<(), GitError> {
    let mut cmd = Command::new("git");
    cmd.args(["init", "--bare", "-b", "main"]).arg(dir);
    run(cmd, &["init", "--bare"]).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R1 (CTO review OBI-209): `git add -- 'd/*.wf'` must never stage
    /// another file by glob/pathspec-magic expansion -- a mudlib path is
    /// free to contain `*`/`?`/`[` (`fileio::resolve` only forbids `..`,
    /// NUL and `.git`), so without `GIT_LITERAL_PATHSPECS=1` a builder
    /// could name a file so that its own coalesced commit scoops up a
    /// co-domain builder's still-uncommitted, unrelated write under the
    /// wrong author and DCO sign-off.
    #[test]
    fn pathspec_is_literal_not_a_glob() {
        let dir = std::env::temp_dir().join(format!(
            "loom-git-literal-pathspec-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("d")).unwrap();
        let init = Command::new("git")
            .arg("init")
            .arg("--quiet")
            .arg(&dir)
            .output()
            .unwrap();
        assert!(init.status.success());
        // A co-domain builder's unrelated, still-uncommitted file.
        std::fs::write(dir.join("d/a.wf"), "object a;\n").unwrap();

        let repo = Repo::new(dir.join(".git"), &dir);
        // No file literally named `d/*.wf` exists -- with
        // `GIT_LITERAL_PATHSPECS=1` this must fail to match anything,
        // not silently glob-match (and stage) `d/a.wf`.
        let result = repo.git(&["add", "--", "d/*.wf"]);
        assert!(
            result.is_err(),
            "expected a literal-pathspec miss, got {result:?}"
        );

        let status = repo.git(&["status", "--porcelain"]).unwrap();
        let text = stdout_string(&status).unwrap();
        assert!(
            text.trim().starts_with("??"),
            "d/a.wf must still be untracked (`??`), not staged (`A `): {text:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(
            base64_encode(b"x-access-token:abc"),
            "eC1hY2Nlc3MtdG9rZW46YWJj"
        );
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn git_segment_rejected_anywhere_in_path() {
        assert!(rejects_git_segment("/domains/x/.git/config"));
        assert!(rejects_git_segment(".git"));
        assert!(rejects_git_segment("/domains/x/.GIT/config"));
        assert!(!rejects_git_segment("/domains/x/y.wf"));
    }

    #[test]
    fn ref_component_sanitization_defuses_shell_and_ref_metacharacters() {
        assert_eq!(sanitize_ref_component("glorfindel"), "glorfindel");
        assert_eq!(sanitize_ref_component("../../etc"), "___etc");
        assert_eq!(sanitize_ref_component("a b~c^d:e?f*g[h"), "a_b_c_d_e_f_g_h");
        assert_eq!(sanitize_ref_component(".hidden"), "hidden");
        assert_eq!(sanitize_ref_component("x.lock"), "x.lock_");
        assert_eq!(sanitize_ref_component(""), "unknown");
        assert_eq!(sanitize_ref_component("..."), "unknown");
    }

    #[test]
    fn git_authed_without_token_is_an_error() {
        let repo = Repo::new("/nonexistent.git", "/nonexistent");
        assert_eq!(repo.git_authed(&["fetch"], None), Err(GitError::NoToken));
    }

    #[test]
    fn authed_command_never_carries_the_token_in_argv() {
        let repo = Repo::new("/nonexistent.git", "/nonexistent");
        let token = "super-secret-token";
        let cmd = repo.build_authed(&["push", "origin", "live:refs/heads/live/test"], token);
        let argv: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let encoded = basic_auth(token);
        assert!(!argv.iter().any(|a| a.contains(token)), "argv: {argv:?}");
        assert!(!argv.iter().any(|a| a.contains(&encoded)), "argv: {argv:?}");

        // The token (base64'd) is exactly where D-B3.11 says it should
        // be: one env var on this one `Command`, nothing else.
        let envs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        let header_value = envs
            .iter()
            .find(|(k, _)| k == "GIT_CONFIG_VALUE_0")
            .and_then(|(_, v)| v.clone())
            .expect("GIT_CONFIG_VALUE_0 must be set");
        assert_eq!(header_value, format!("Authorization: Basic {encoded}"));
        assert!(
            !envs
                .iter()
                .any(|(k, v)| k != "GIT_CONFIG_VALUE_0" && v.as_deref() == Some(token)),
            "token leaked into another env var: {envs:?}"
        );
        // R2: an empty credential helper so git can never fall back to
        // an ambient one.
        assert_eq!(
            envs.iter()
                .find(|(k, _)| k == "GIT_CONFIG_KEY_1")
                .and_then(|(_, v)| v.clone()),
            Some("credential.helper".to_string())
        );
        assert_eq!(
            envs.iter()
                .find(|(k, _)| k == "GIT_CONFIG_VALUE_1")
                .and_then(|(_, v)| v.clone()),
            Some(String::new())
        );
    }

    #[test]
    fn hardening_env_is_present_on_every_command() {
        let repo = Repo::new("/nonexistent.git", "/nonexistent");
        let cmd = repo.build(&["status"]);
        let envs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(
            envs.iter()
                .find(|(k, _)| k == "GIT_LITERAL_PATHSPECS")
                .and_then(|(_, v)| v.clone()),
            Some("1".to_string())
        );
        assert_eq!(
            envs.iter()
                .find(|(k, _)| k == "GIT_TERMINAL_PROMPT")
                .and_then(|(_, v)| v.clone()),
            Some("0".to_string())
        );
    }
}
