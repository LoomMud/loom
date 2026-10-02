// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Integration tests against a local bare remote (OBI-190 acceptance
//! criteria). Everything here uses the real `git` binary -- no mocks.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use loom_git::{GitConfig, GitWorker, GitWorkerHandle, Identity, RecompileHost, RecompileOutcome};

type RecompileCall = (Vec<String>, Vec<String>);

struct RecordingHost {
    calls: Arc<Mutex<Vec<RecompileCall>>>,
}

impl RecompileHost for RecordingHost {
    fn recompile_set(&self, changed: Vec<String>, deleted: Vec<String>) -> RecompileOutcome {
        self.calls
            .lock()
            .unwrap()
            .push((changed.clone(), deleted.clone()));
        RecompileOutcome {
            ok: true,
            recompiled: changed,
            failures: Vec::new(),
        }
    }
}

struct FixedToken(&'static str);
impl loom_git::TokenProvider for FixedToken {
    fn token(&self) -> Result<String, String> {
        Ok(self.0.to_string())
    }
}

type ConflictSkip = (String, String, String, Vec<String>, bool);

#[derive(Default)]
struct RecordingAudit {
    skipped: Mutex<Vec<ConflictSkip>>,
}
impl loom_git::AuditSink for RecordingAudit {
    fn conflict_skipped(
        &self,
        uid: &str,
        sha: &str,
        conflict_ref: &str,
        paths: &[String],
        pushed: bool,
    ) {
        self.skipped.lock().unwrap().push((
            uid.to_string(),
            sha.to_string(),
            conflict_ref.to_string(),
            paths.to_vec(),
            pushed,
        ));
    }
}

fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn git_in(git_dir: &Path, work_tree: &Path, args: &[&str]) -> std::process::Output {
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .arg("--work-tree")
        .arg(work_tree)
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

struct Fixture {
    tmp: tempfile::TempDir,
    bare: PathBuf,
    git_dir: PathBuf,
    work_tree: PathBuf,
}

impl Fixture {
    fn bare_path(&self) -> &Path {
        &self.bare
    }
    fn git_dir(&self) -> &Path {
        &self.git_dir
    }
    fn work_tree(&self) -> &Path {
        &self.work_tree
    }

    /// Read `path` (work-tree relative) from a fresh clone of the bare
    /// remote's `live/<env>` branch, so assertions never depend on the
    /// driver's own work tree having been fast-forwarded yet.
    fn remote_live_file(&self, env: &str, path: &str) -> Option<String> {
        let clone = self.tmp.path().join(format!("peek-{}", rand_suffix()));
        let out = Command::new("git")
            .args([
                "clone",
                "--quiet",
                "-b",
                &format!("live/{env}"),
                &self.bare.to_string_lossy(),
                &clone.to_string_lossy(),
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        std::fs::read_to_string(clone.join(path)).ok()
    }

    fn remote_has_ref(&self, ref_name: &str) -> bool {
        Command::new("git")
            .args([
                "--git-dir",
                &self.bare.to_string_lossy(),
                "show-ref",
                "--verify",
                "--quiet",
                ref_name,
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

fn rand_suffix() -> String {
    format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn setup() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bare = tmp.path().join("warp-bare.git");
    let git_dir = tmp.path().join("warp.git");
    let work_tree = tmp.path().join("mudlib");
    std::fs::create_dir_all(&work_tree).unwrap();

    git(
        tmp.path(),
        &[
            "init",
            "--quiet",
            "--bare",
            "-b",
            "main",
            &bare.to_string_lossy(),
        ],
    );

    // D-B3.2: separate git dir, created via GIT_DIR/GIT_WORK_TREE env, not
    // `git init --separate-git-dir` (that leaves a `.git` *file* pointer
    // in the work tree -- still "something named `.git`").
    let out = Command::new("git")
        .env("GIT_DIR", &git_dir)
        .env("GIT_WORK_TREE", &work_tree)
        .args(["init", "--quiet", "-b", "main"])
        .output()
        .expect("git init");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !work_tree.join(".git").exists(),
        "work tree must not contain a `.git` entry"
    );

    std::fs::write(work_tree.join("room.wf"), "object room;\n").unwrap();
    std::fs::create_dir_all(work_tree.join("secure")).unwrap();
    std::fs::write(work_tree.join("secure/master.wf"), "object master;\n").unwrap();

    let mut add = Command::new("git");
    add.arg("--git-dir")
        .arg(&git_dir)
        .arg("--work-tree")
        .arg(&work_tree)
        .args(["add", "-A"]);
    assert!(add.output().unwrap().status.success());

    let mut commit = Command::new("git");
    commit
        .arg("--git-dir")
        .arg(&git_dir)
        .arg("--work-tree")
        .arg(&work_tree);
    commit.args(["commit", "-m", "seed"]);
    commit
        .env("GIT_AUTHOR_NAME", "seed")
        .env("GIT_AUTHOR_EMAIL", "seed@loommud.com");
    commit
        .env("GIT_COMMITTER_NAME", "seed")
        .env("GIT_COMMITTER_EMAIL", "seed@loommud.com");
    assert!(commit.output().unwrap().status.success());

    git_in(
        &git_dir,
        &work_tree,
        &["remote", "add", "origin", &bare.to_string_lossy()],
    );
    git_in(&git_dir, &work_tree, &["push", "origin", "main"]);
    git_in(&git_dir, &work_tree, &["branch", "live"]);
    git_in(&git_dir, &work_tree, &["checkout", "live"]);

    Fixture {
        tmp,
        bare,
        git_dir,
        work_tree,
    }
}

fn spawn_worker(fx: &Fixture, env: &str) -> (GitWorkerHandle, Arc<Mutex<Vec<RecompileCall>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut config = GitConfig::new(fx.git_dir(), fx.work_tree(), "origin", env);
    config.commit_coalesce = Duration::from_millis(30);
    config.push_debounce = Duration::from_millis(20);
    config.sync_poll = Duration::from_secs(3600); // only via kick() in tests
    config.tick = Duration::from_millis(15);
    let host = RecordingHost {
        calls: calls.clone(),
    };
    let handle = GitWorker::spawn(
        config,
        Some(Box::new(FixedToken("super-secret-token"))),
        Box::new(host),
        Box::new(RecordingAudit::default()),
    );
    (handle, calls)
}

/// R2 (CTO review OBI-209): no `TokenProvider` at all -- push/fetch must
/// be skipped outright, never falling back to an unauthenticated call
/// against the real remote.
fn spawn_worker_no_token(
    fx: &Fixture,
    env: &str,
) -> (GitWorkerHandle, Arc<Mutex<Vec<RecompileCall>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut config = GitConfig::new(fx.git_dir(), fx.work_tree(), "origin", env);
    config.commit_coalesce = Duration::from_millis(30);
    config.push_debounce = Duration::from_millis(20);
    config.sync_poll = Duration::from_secs(3600);
    config.tick = Duration::from_millis(15);
    let host = RecordingHost {
        calls: calls.clone(),
    };
    let handle = GitWorker::spawn(
        config,
        None,
        Box::new(host),
        Box::new(RecordingAudit::default()),
    );
    (handle, calls)
}

fn wait_for<F: FnMut() -> bool>(mut pred: F, what: &str) {
    let start = Instant::now();
    while !pred() {
        if start.elapsed() > Duration::from_secs(10) {
            panic!("timed out waiting for: {what}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn write_then_commit_has_the_right_author_and_dco_trailer() {
    let fx = setup();
    let (handle, _calls) = spawn_worker(&fx, "test");

    std::fs::write(fx.work_tree().join("room.wf"), "object room; // v2\n").unwrap();
    let identity = Identity::for_uid("glorfindel", Some("1+glorfindel@users.noreply.github.com"));
    handle
        .tree_lock()
        .with_read(|| {
            handle
                .record_write("glorfindel", identity.clone(), "/room.wf", "ed /room.wf")
                .unwrap();
        })
        .unwrap();
    handle.barrier();

    wait_for(
        || {
            let out = Command::new("git")
                .args([
                    "--git-dir",
                    &fx.git_dir().to_string_lossy(),
                    "log",
                    "-1",
                    "--format=%s",
                ])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim() == "ed /room.wf"
        },
        "the auto-commit to land on `live`",
    );

    let log = Command::new("git")
        .args([
            "--git-dir",
            &fx.git_dir().to_string_lossy(),
            "log",
            "-1",
            "--format=%an <%ae>%n%(trailers:key=Signed-off-by,valueonly)",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&log.stdout);
    let mut lines = text.lines();
    let author = lines.next().unwrap();
    assert_eq!(author, "glorfindel <1+glorfindel@users.noreply.github.com>");
    let trailer = lines.next().unwrap_or("");
    assert!(
        trailer.contains(author),
        "trailer {trailer:?} must match author {author:?}"
    );

    // warp's own DCO gate, run against this exact commit.
    let dco_script = std::env::current_dir()
        .unwrap()
        .join("..")
        .join("..")
        .join("..")
        .join("warp/scripts/check-dco.sh");
    if dco_script.exists() {
        let status = Command::new("bash")
            .arg(&dco_script)
            .arg("HEAD~1..HEAD")
            .current_dir(fx.git_dir())
            .env("GIT_DIR", fx.git_dir())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "warp's check-dco.sh rejected the auto-commit"
        );
    }

    handle.shutdown();
}

#[test]
fn push_lands_on_live_env_branch() {
    let fx = setup();
    let (handle, _calls) = spawn_worker(&fx, "test");

    std::fs::write(fx.work_tree().join("room.wf"), "object room; // v2\n").unwrap();
    let identity = Identity::for_uid("appr1", None);
    handle
        .record_write("appr1", identity, "/room.wf", "ed /room.wf")
        .unwrap();

    wait_for(
        || fx.remote_has_ref("refs/heads/live/test"),
        "push to land on live/test",
    );
    wait_for(
        || fx.remote_live_file("test", "room.wf").as_deref() == Some("object room; // v2\n"),
        "pushed content to match the local commit",
    );

    handle.shutdown();
}

#[test]
fn upstream_main_move_is_rebased_in_and_recompile_is_called() {
    let fx = setup();
    let (handle, calls) = spawn_worker(&fx, "test");

    // A reviewer merges a PR to `main`: clone, add a new file, push.
    let clone = fx.tmp.path().join("reviewer-clone");
    let out = Command::new("git")
        .args([
            "clone",
            "--quiet",
            &fx.bare_path().to_string_lossy(),
            &clone.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    std::fs::write(clone.join("hall.wf"), "object hall;\n").unwrap();
    git(&clone, &["add", "-A"]);
    let mut commit = Command::new("git");
    commit
        .current_dir(&clone)
        .args(["commit", "-m", "add hall (#1)"]);
    commit
        .env("GIT_AUTHOR_NAME", "reviewer")
        .env("GIT_AUTHOR_EMAIL", "reviewer@loommud.com");
    commit
        .env("GIT_COMMITTER_NAME", "reviewer")
        .env("GIT_COMMITTER_EMAIL", "reviewer@loommud.com");
    assert!(commit.output().unwrap().status.success());
    git(&clone, &["push", "origin", "main"]);

    handle.kick();
    wait_for(
        || !calls.lock().unwrap().is_empty(),
        "recompile_set to be called after sync",
    );

    let (changed, _deleted) = calls.lock().unwrap().last().cloned().unwrap();
    assert!(
        changed.iter().any(|p| p == "/hall.wf"),
        "changed set was {changed:?}"
    );
    wait_for(
        || fx.work_tree().join("hall.wf").exists(),
        "the fast-forwarded work tree to contain the new file",
    );

    handle.shutdown();
}

#[test]
fn conflicting_live_commit_is_skipped_main_wins_file_is_in_changed_set() {
    let fx = setup();
    let (handle, calls) = spawn_worker(&fx, "test");

    // The builder edits room.wf on `live` (not yet pushed/synced away).
    std::fs::write(
        fx.work_tree().join("room.wf"),
        "object room; // builder's wip\n",
    )
    .unwrap();
    let identity = Identity::for_uid("appr1", None);
    handle
        .record_write("appr1", identity, "/room.wf", "ed /room.wf")
        .unwrap();
    handle.barrier();
    wait_for(
        || {
            let out = Command::new("git")
                .args([
                    "--git-dir",
                    &fx.git_dir().to_string_lossy(),
                    "log",
                    "-1",
                    "--format=%s",
                    "live",
                ])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim() == "ed /room.wf"
        },
        "builder commit to land before the conflicting main move",
    );

    // Meanwhile a reviewer merges a conflicting edit of the same file to
    // `main`.
    let clone = fx.tmp.path().join("reviewer-clone-2");
    let out = Command::new("git")
        .args([
            "clone",
            "--quiet",
            &fx.bare_path().to_string_lossy(),
            &clone.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    std::fs::write(clone.join("room.wf"), "object room; // reviewed\n").unwrap();
    git(&clone, &["add", "-A"]);
    let mut commit = Command::new("git");
    commit
        .current_dir(&clone)
        .args(["commit", "-m", "review room.wf (#2)"]);
    commit
        .env("GIT_AUTHOR_NAME", "reviewer")
        .env("GIT_AUTHOR_EMAIL", "reviewer@loommud.com");
    commit
        .env("GIT_COMMITTER_NAME", "reviewer")
        .env("GIT_COMMITTER_EMAIL", "reviewer@loommud.com");
    assert!(commit.output().unwrap().status.success());
    git(&clone, &["push", "origin", "main"]);

    handle.kick();
    wait_for(
        || !calls.lock().unwrap().is_empty(),
        "recompile_set to be called after the conflict sync",
    );

    let (changed, _deleted) = calls.lock().unwrap().last().cloned().unwrap();
    assert!(
        changed.iter().any(|p| p == "/room.wf"),
        "changed set was {changed:?}"
    );

    wait_for(
        || {
            std::fs::read_to_string(fx.work_tree().join("room.wf"))
                .ok()
                .as_deref()
                == Some("object room; // reviewed\n")
        },
        "main's content to win on the real work tree",
    );

    wait_for(
        || {
            // `conflict/live/<env>/<uid>/<sha>` ref on the bare remote
            // (see the D-B3.8 ref-naming note in `worker.rs`).
            Command::new("git")
                .args([
                    "--git-dir",
                    &fx.bare_path().to_string_lossy(),
                    "for-each-ref",
                    "refs/heads/conflict/live/test",
                ])
                .output()
                .map(|o| !o.stdout.is_empty())
                .unwrap_or(false)
        },
        "the skipped commit to be pushed to a conflict ref",
    );

    // R5b (CTO review OBI-209): the ref must carry the uid (`appr1`,
    // `Identity::for_uid`'s author *name*), not the author e-mail.
    let remote_conflict_refs = Command::new("git")
        .args([
            "--git-dir",
            &fx.bare_path().to_string_lossy(),
            "for-each-ref",
            "--format=%(refname)",
            "refs/heads/conflict/live/test",
        ])
        .output()
        .unwrap();
    let refs_text = String::from_utf8_lossy(&remote_conflict_refs.stdout).into_owned();
    assert!(
        refs_text.contains("/conflict/live/test/appr1/"),
        "conflict ref must use the uid `appr1`, not an email: {refs_text:?}"
    );

    // R5a: a local keep-ref must exist even though the push also
    // succeeded here, so the skipped commit survives regardless of push
    // outcome.
    let local_keep = Command::new("git")
        .args([
            "--git-dir",
            &fx.git_dir().to_string_lossy(),
            "for-each-ref",
            "refs/loom/conflict/test/appr1",
        ])
        .output()
        .unwrap();
    assert!(
        !local_keep.stdout.is_empty(),
        "expected a local refs/loom/conflict/test/appr1/<sha> keep-ref"
    );

    handle.shutdown();
}

#[test]
fn dotgit_path_segment_is_rejected() {
    let fx = setup();
    let (handle, _calls) = spawn_worker(&fx, "test");
    let identity = Identity::for_uid("appr1", None);
    let err = handle
        .record_write("appr1", identity, "/domains/x/.git/config", "ed x")
        .unwrap_err();
    assert!(err.to_string().contains(".git"));
    handle.shutdown();
}

#[test]
fn write_during_sync_lock_fails_fast() {
    let fx = setup();
    let (handle, _calls) = spawn_worker(&fx, "test");

    // Simulate the sync loop holding the exclusive side mid-fast-forward.
    let lock_for_thread = handle.tree_lock();
    let held = std::thread::spawn(move || {
        let _guard = lock_for_thread.write_guard();
        std::thread::sleep(Duration::from_millis(200));
    });
    std::thread::sleep(Duration::from_millis(20));
    let result = handle.tree_lock().with_read(|| 1);
    assert_eq!(result, Err(loom_git::GitError::SyncInProgress));
    held.join().unwrap();
    handle.shutdown();
}

#[test]
fn token_never_appears_in_argv_or_git_config() {
    let fx = setup();
    let remote_url_before = Command::new("git")
        .args([
            "--git-dir",
            &fx.git_dir().to_string_lossy(),
            "remote",
            "get-url",
            "origin",
        ])
        .output()
        .unwrap();
    let remote_url_before = String::from_utf8_lossy(&remote_url_before.stdout)
        .trim()
        .to_string();

    let (handle, _calls) = spawn_worker(&fx, "test");

    std::fs::write(fx.work_tree().join("room.wf"), "object room; // v3\n").unwrap();
    let identity = Identity::for_uid("appr1", None);
    handle
        .record_write("appr1", identity, "/room.wf", "ed /room.wf")
        .unwrap();
    wait_for(
        || fx.remote_has_ref("refs/heads/live/test"),
        "push to complete with the token configured",
    );

    let secret = "super-secret-token"; // matches FixedToken in spawn_worker
    let secret_b64 = base64_encode(format!("x-access-token:{secret}").as_bytes());
    // `/proc/self/cmdline` isn't available after the child exits; the
    // crate-level unit test (`cli::tests::authed_command_never_carries_the_token_in_argv`)
    // asserts the argv/env of the `Command` directly (R3, CTO review
    // OBI-209). Here we assert the *persisted* surface this test can
    // still reach after the fact: the repo's on-disk config must carry
    // neither the plaintext token, its base64 form, nor any
    // `extraheader`/`credential.helper` key -- those only ever exist as
    // env vars on one child process, never written to `.git/config`.
    let cfg = Command::new("git")
        .args(["--git-dir", &fx.git_dir().to_string_lossy(), "config", "-l"])
        .output()
        .unwrap();
    let cfg_text = String::from_utf8_lossy(&cfg.stdout);
    assert!(
        !cfg_text.contains(secret),
        "plaintext token leaked into git config: {cfg_text}"
    );
    assert!(
        !cfg_text.contains(&secret_b64),
        "base64 token leaked into git config: {cfg_text}"
    );
    assert!(
        !cfg_text.to_lowercase().contains("extraheader"),
        "an extraHeader was persisted to git config: {cfg_text}"
    );
    assert!(
        !cfg_text.to_lowercase().contains("credential.helper"),
        "a credential.helper override was persisted to git config: {cfg_text}"
    );

    let remote_url_after = Command::new("git")
        .args([
            "--git-dir",
            &fx.git_dir().to_string_lossy(),
            "remote",
            "get-url",
            "origin",
        ])
        .output()
        .unwrap();
    let remote_url_after = String::from_utf8_lossy(&remote_url_after.stdout)
        .trim()
        .to_string();
    assert_eq!(
        remote_url_before, remote_url_after,
        "the remote URL must never embed the token"
    );
    assert!(!remote_url_after.contains(secret));

    handle.shutdown();
}

/// Minimal base64 (standard alphabet, padded), matching
/// `loom_git::cli::basic_auth`'s private encoding -- duplicated here
/// (rather than exported from the crate just for this one test) so this
/// test computes the *expected* leaked form independently of the
/// production code path it is checking.
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

/// R2 (CTO review OBI-209): with no `TokenProvider` configured at all,
/// push must be skipped outright -- commits still happen locally (they
/// never need the network), but nothing reaches the remote, and no
/// unauthenticated fallback is attempted either.
#[test]
fn no_token_provider_disables_push_entirely() {
    let fx = setup();
    let (handle, _calls) = spawn_worker_no_token(&fx, "test");

    std::fs::write(fx.work_tree().join("room.wf"), "object room; // v2\n").unwrap();
    let identity = Identity::for_uid("appr1", None);
    handle
        .record_write("appr1", identity, "/room.wf", "ed /room.wf")
        .unwrap();
    handle.barrier();

    // The commit still lands locally (no network needed for that).
    wait_for(
        || {
            let out = Command::new("git")
                .args([
                    "--git-dir",
                    &fx.git_dir().to_string_lossy(),
                    "log",
                    "-1",
                    "--format=%s",
                    "live",
                ])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim() == "ed /room.wf"
        },
        "the commit to land locally even with no token provider",
    );

    // Give the (debounced, disabled) push every chance to have run, then
    // assert it never reached the remote.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !fx.remote_has_ref("refs/heads/live/test"),
        "push must be skipped with no TokenProvider, not fall back unauthenticated"
    );

    handle.shutdown();
}
