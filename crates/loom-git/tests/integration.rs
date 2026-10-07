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
            upgraded_instances: 0,
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

    /// Read `path` (work-tree relative) from the bare remote's
    /// `live/<env>` branch, so assertions never depend on the driver's own
    /// work tree having been fast-forwarded yet.
    ///
    /// OBI-222: this used to spin up a brand-new `git clone` (new temp
    /// dir, full checkout) on *every* `wait_for` poll -- cheap on an idle
    /// box, but on a loaded self-hosted runner each clone can itself take
    /// much longer than the 20ms poll interval, so the polling loop's own
    /// cost dominates the `wait_for` budget instead of the thing it's
    /// actually waiting on (the push). `git show <ref>:<path>` reads the
    /// blob straight out of the bare repo's object store -- no temp dir,
    /// no working tree, no index -- so polling stays cheap regardless of
    /// runner load.
    fn remote_live_file(&self, env: &str, path: &str) -> Option<String> {
        let out = Command::new("git")
            .args([
                "--git-dir",
                &self.bare.to_string_lossy(),
                "show",
                &format!("live/{env}:{path}"),
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
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
    // OBI-210 R4: `GitWorker::spawn` refuses to start with a
    // `TokenProvider` configured unless `remote_url` is `https://`. The
    // fixture's actual `remote` is a local bare-repo *path* (no network,
    // no real scheme) for speed -- this placeholder satisfies the gate
    // without claiming the local path remote is itself `https://`;
    // `http.<remote_url>.extraHeader` simply never matches the local
    // `file://`-style transport these tests exercise, same as
    // production code pointed at the wrong host would see.
    config.remote_url = "https://github.com/example/warp-mudlib.git".to_string();
    let host = RecordingHost {
        calls: calls.clone(),
    };
    let handle = GitWorker::spawn(
        config,
        Some(Box::new(FixedToken("super-secret-token"))),
        Box::new(host),
        Box::new(RecordingAudit::default()),
    )
    .expect("spawn with an https:// remote_url and a TokenProvider must succeed");
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
    )
    .expect("spawn with no TokenProvider must always succeed regardless of remote_url");
    (handle, calls)
}

// OBI-222: was 10s. The worker's own debounce/coalesce/tick budget in
// `spawn_worker` adds up to well under 100ms on an idle box, so 10s
// looked like a generous margin -- but on a loaded self-hosted ARC
// runner (other workflow jobs sharing the node, cgroup CPU throttling)
// every `git` subprocess call in the polling predicate can itself stall
// for seconds, and the two observed flakes (OBI-222) both happened
// during exactly that kind of contention. 30s gives real headroom
// without the fixture ever being expected to actually need it in the
// unloaded case. See also the `remote_live_file` fix in this same patch,
// which removed the main source of per-poll cost.
fn wait_for<F: FnMut() -> bool>(mut pred: F, what: &str) {
    let start = Instant::now();
    while !pred() {
        if start.elapsed() > Duration::from_secs(30) {
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
    // OBI-222: this test previously relied purely on the worker's
    // timer-based commit_coalesce/push_debounce to land the write and
    // push it -- the *second* wait_for below needs a full extra
    // commit+push cycle after the boot-time sync's own push (which is
    // what made the first wait_for below pass quickly even under load:
    // it only needs *a* push to have landed, not this write's content).
    // On a CPU-starved self-hosted runner, waiting on wall-clock timers
    // to fire is unbounded -- the worker thread only gets to check its
    // deadlines when the OS schedules it at all. `kick()` (same
    // mechanism `upstream_main_move_is_rebased_in_and_recompile_is_called`
    // and the conflict test already use) forces an immediate
    // flush-all-pending-commits-then-sync-then-push pass the next time
    // the worker thread runs at all, instead of making convergence
    // depend on comparing `Instant::now()` against a short coalesce/
    // debounce deadline that can be missed by many ticks in a row under
    // contention.
    handle.kick();

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

/// OBI-210 R1 (CTO re-review of PR #81): a dirty tree that no
/// `Msg::Write` will ever commit (here: a stray untracked file) must
/// make the sync retry back off exponentially, not re-fetch every
/// `tick` forever (previously ~10 authenticated fetches/sec against the
/// remote, unbounded).
#[test]
fn dirty_tree_retry_backs_off_instead_of_spinning() {
    let fx = setup();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let host = RecordingHost {
        calls: calls.clone(),
    };
    let mut config = GitConfig::new(fx.git_dir(), fx.work_tree(), "origin", "test");
    config.commit_coalesce = Duration::from_millis(10);
    config.push_debounce = Duration::from_millis(10);
    config.sync_poll = Duration::from_secs(3600); // only via kick()/backoff in this test
    config.tick = Duration::from_millis(20);
    config.remote_url = "https://github.com/example/warp-mudlib.git".to_string();
    let tick = config.tick;
    let handle = GitWorker::spawn(
        config,
        Some(Box::new(FixedToken("super-secret-token"))),
        Box::new(host),
        Box::new(RecordingAudit::default()),
    )
    .expect("spawn with an https:// remote_url and a TokenProvider must succeed");

    // Let the boot sync pass (nothing to do yet) finish before we set up
    // the race.
    std::thread::sleep(Duration::from_millis(100));

    // A real upstream `main` move, so the sync pass has something to
    // fast-forward onto -- an unchanged `main` returns `no_change` before
    // ever reaching the dirty-tree check at all.
    let clone = fx.tmp.path().join("reviewer-clone-dirty-tree");
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
        .args(["commit", "-m", "add hall (#2)"]);
    commit
        .env("GIT_AUTHOR_NAME", "reviewer")
        .env("GIT_AUTHOR_EMAIL", "reviewer@loommud.com");
    commit
        .env("GIT_COMMITTER_NAME", "reviewer")
        .env("GIT_COMMITTER_EMAIL", "reviewer@loommud.com");
    assert!(commit.output().unwrap().status.success());
    git(&clone, &["push", "origin", "main"]);

    // Dirty the work tree with a stray untracked file no `Msg::Write`
    // will ever commit (a driver artifact, a rejected write, ...).
    std::fs::write(fx.work_tree().join("stray.tmp"), "oops\n").unwrap();

    handle.kick();
    // Give the first (failing) sync pass a head start.
    std::thread::sleep(Duration::from_millis(100));

    let fetch_head = fx.git_dir().join("FETCH_HEAD");
    let count_fetches_in = |window: Duration| -> u32 {
        let start = Instant::now();
        let mut last_mtime = std::fs::metadata(&fetch_head)
            .ok()
            .and_then(|m| m.modified().ok());
        let mut count = 0;
        while start.elapsed() < window {
            if let Ok(meta) = std::fs::metadata(&fetch_head)
                && let Ok(mtime) = meta.modified()
                && Some(mtime) != last_mtime
            {
                count += 1;
                last_mtime = Some(mtime);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        count
    };

    let fetches = count_fetches_in(Duration::from_secs(2));
    // Unthrottled spinning at `tick` (20 ms) would produce on the order
    // of 100 fetches in 2 s; exponential backoff starting at `tick` and
    // doubling (20, 40, 80, 160, 320, 640, 1280 ms, ...) produces a
    // handful before the window elapses.
    assert!(
        fetches < 20,
        "expected backoff to bound fetch attempts well under 2s/tick={tick:?}, got {fetches}"
    );

    // The dirty tree must never be force-overwritten: the stray file is
    // still there, and `live` must not have been fast-forwarded out from
    // under it.
    assert!(
        fx.work_tree().join("stray.tmp").exists(),
        "a dirty tree must never be force-overwritten by the fast-forward"
    );

    handle.shutdown();
}

/// OBI-210 R4 (CTO decision: belongs here, not just B3.5's bootstrap
/// wiring): refuse to start rather than ever send an installation token
/// to a non-`https://` remote.
#[test]
fn spawn_refuses_a_token_provider_with_a_non_https_remote() {
    let fx = setup();
    let mut config = GitConfig::new(fx.git_dir(), fx.work_tree(), "origin", "test");
    config.remote_url = fx.bare_path().to_string_lossy().into_owned();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let host = RecordingHost { calls };
    let result = GitWorker::spawn(
        config,
        Some(Box::new(FixedToken("super-secret-token"))),
        Box::new(host),
        Box::new(RecordingAudit::default()),
    );
    assert!(
        result.is_err(),
        "a TokenProvider with a non-https:// remote_url must refuse to start"
    );
}

/// The same non-`https://` `remote_url` is fine when no `TokenProvider`
/// is configured at all -- nothing is ever sent, so there is no
/// credential to misdirect.
#[test]
fn spawn_allows_a_non_https_remote_with_no_token_provider() {
    let fx = setup();
    let mut config = GitConfig::new(fx.git_dir(), fx.work_tree(), "origin", "test");
    config.remote_url = fx.bare_path().to_string_lossy().into_owned();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let host = RecordingHost { calls };
    let handle = GitWorker::spawn(
        config,
        None,
        Box::new(host),
        Box::new(RecordingAudit::default()),
    )
    .expect("no TokenProvider means no credential to misdirect -- must not refuse to start");
    handle.shutdown();
}

// --- OBI-272 (B3.3 slice 5): post-merge PR report wired into `SyncMain`.
// A loopback fake GitHub server standing in for the real API, same
// pattern as `tests/propose.rs`'s `spawn_fake_github`.

mod post_merge_report {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    use loom_git::{
        GitHubAppClient, GitHubAppError, ProposeConfig, ProposeGitHubConfig, PullRequest,
        PullRequestOpener, ReportGitHub, TokenProvider, UreqClient,
    };

    struct FakeGitHub {
        addr: String,
        comments: Arc<Mutex<Vec<(u64, String)>>>,
        /// Set once the fake server has actually served the forced 503
        /// (OBI-278 review item 2) -- exposed so
        /// `github_5xx_during_report_does_not_fail_sync_main` can assert
        /// the 503 really happened, not just that the test ran without
        /// hanging.
        failed_once: Arc<std::sync::atomic::AtomicBool>,
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    fn read_full_request(stream: &mut TcpStream) -> Option<String> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(end) = find_subslice(&buf, b"\r\n\r\n") {
                let header_text = String::from_utf8_lossy(&buf[..end]);
                let content_length: usize = header_text
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                if buf.len().saturating_sub(end + 4) >= content_length {
                    break;
                }
            }
            let n = stream.read(&mut chunk).ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        if buf.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(&buf).into_owned())
        }
    }

    /// `respond_5xx_once` lets the "a GitHub 5xx must not fail the sync"
    /// acceptance case force exactly one failing response before the
    /// server starts behaving normally.
    fn spawn_fake_github(respond_5xx_once: bool) -> FakeGitHub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let comments = Arc::new(Mutex::new(Vec::new()));
        let comments_clone = comments.clone();
        let failed_once = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let failed_once_handle = failed_once.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let req = match read_full_request(&mut stream) {
                    Some(r) => r,
                    None => continue,
                };
                let (head, body) = req.split_once("\r\n\r\n").unwrap_or((&req, ""));
                let path = head
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("")
                    .to_string();
                let (status, resp_body) = if path.contains("access_tokens") {
                    (
                        201,
                        r#"{"token":"ghs_abc","expires_at":"2099-01-01T00:00:00Z"}"#.to_string(),
                    )
                } else if path.ends_with("/pulls") && path.contains("/commits/") {
                    // Commits-to-pulls fallback -- not expected to be hit
                    // by this test's merge-commit subject, but answered
                    // anyway so an unexpected call fails loudly on the
                    // assertion instead of hanging.
                    (200, "[]".to_string())
                } else if path.contains("/issues/") && path.ends_with("/comments") {
                    if respond_5xx_once
                        && !failed_once.swap(true, std::sync::atomic::Ordering::SeqCst)
                    {
                        (503, r#"{"message":"server error"}"#.to_string())
                    } else {
                        let number: u64 = path
                            .trim_start_matches("/repos/LoomMud/warp/issues/")
                            .trim_end_matches("/comments")
                            .parse()
                            .unwrap_or(0);
                        comments_clone
                            .lock()
                            .unwrap()
                            .push((number, body.to_string()));
                        (201, "{}".to_string())
                    }
                } else {
                    (404, "{}".to_string())
                };
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    resp_body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(resp_body.as_bytes());
            }
        });
        FakeGitHub {
            addr,
            comments,
            failed_once: failed_once_handle,
        }
    }

    // Shared throwaway test fixture (see `loom_git`'s own jwt test module
    // docs): not a real GitHub App key, just something
    // `GitHubAppClient::new` accepts.
    fn test_pem() -> String {
        include_str!("testdata/test_key.pkcs8.pem").to_string()
    }

    fn github_client(server: &FakeGitHub) -> Arc<GitHubAppClient<UreqClient>> {
        Arc::new(
            GitHubAppClient::new("1", "2", &test_pem(), UreqClient::default())
                .unwrap()
                .with_api_base(format!("http://{}", server.addr)),
        )
    }

    struct TokenAdapter(Arc<GitHubAppClient<UreqClient>>);
    impl TokenProvider for TokenAdapter {
        fn token(&self) -> Result<String, String> {
            self.0.token()
        }
    }

    struct ReportAdapter(Arc<GitHubAppClient<UreqClient>>);
    impl ReportGitHub for ReportAdapter {
        fn commit_pulls(
            &self,
            owner: &str,
            repo: &str,
            sha: &str,
        ) -> Result<Vec<loom_git::PullRef>, GitHubAppError> {
            self.0.commit_pulls(owner, repo, sha)
        }
        fn create_issue_comment(
            &self,
            owner: &str,
            repo: &str,
            number: u64,
            body: &str,
        ) -> Result<(), GitHubAppError> {
            self.0.create_issue_comment(owner, repo, number, body)
        }
    }

    /// `propose` itself is never exercised by these tests -- this is
    /// only here because [`ProposeGitHubConfig::pr_opener`] isn't an
    /// `Option`.
    struct UnusedPrOpener;
    impl PullRequestOpener for UnusedPrOpener {
        fn open_pull_request(
            &self,
            _owner: &str,
            _repo: &str,
            _head: &str,
            _base: &str,
            _title: &str,
            _body: &str,
        ) -> Result<PullRequest, GitHubAppError> {
            panic!("post_merge_report tests never call propose()")
        }
    }

    struct FixedInstancesHost {
        calls: Arc<Mutex<Vec<RecompileCall>>>,
        upgraded_instances: usize,
    }
    impl RecompileHost for FixedInstancesHost {
        fn recompile_set(&self, changed: Vec<String>, deleted: Vec<String>) -> RecompileOutcome {
            self.calls
                .lock()
                .unwrap()
                .push((changed.clone(), deleted.clone()));
            RecompileOutcome {
                ok: true,
                recompiled: changed,
                upgraded_instances: self.upgraded_instances,
                failures: Vec::new(),
            }
        }
    }

    fn spawn_reporting_worker(
        fx: &Fixture,
        server: &FakeGitHub,
        env: &str,
        upgraded_instances: usize,
    ) -> (GitWorkerHandle, Arc<Mutex<Vec<RecompileCall>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let host = FixedInstancesHost {
            calls: calls.clone(),
            upgraded_instances,
        };
        let mut config = GitConfig::new(fx.git_dir(), fx.work_tree(), "origin", env);
        config.commit_coalesce = Duration::from_millis(10);
        config.push_debounce = Duration::from_millis(10);
        config.sync_poll = Duration::from_secs(3600); // only via kick() in tests
        config.tick = Duration::from_millis(10);
        config.remote_url = "https://github.com/example/warp-mudlib.git".to_string();
        let client = github_client(server);
        let handle = GitWorker::spawn_with_propose(
            config,
            Some(Box::new(TokenAdapter(client.clone()))),
            Box::new(host),
            Box::new(RecordingAudit::default()),
            ProposeConfig {
                authorizer: Box::new(loom_git::AllowAllAuthorizer),
                quota: Box::new(loom_git::InMemoryQuota::new()),
                limits: loom_git::ProposeLimits::default(),
                github: Some(ProposeGitHubConfig {
                    pr_opener: Box::new(UnusedPrOpener),
                    owner: "LoomMud".to_string(),
                    repo: "warp".to_string(),
                    report_client: Some(Arc::new(ReportAdapter(client))),
                }),
            },
        )
        .expect("spawn with an https:// remote_url and a TokenProvider must succeed");
        (handle, calls)
    }

    /// Same as [`spawn_reporting_worker`], but with the push/fetch
    /// `TokenProvider` and the post-merge `ReportGitHub` pointed at two
    /// *different* fake servers -- needed when a test wants one of them
    /// (typically the report side) to be slow without that also
    /// stalling every ordinary tick's token refresh, which is unrelated
    /// to what the test is exercising (OBI-278).
    fn spawn_reporting_worker_split_servers(
        fx: &Fixture,
        token_server: &FakeGitHub,
        report_server: &FakeGitHub,
        env: &str,
        upgraded_instances: usize,
    ) -> (GitWorkerHandle, Arc<Mutex<Vec<RecompileCall>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let host = FixedInstancesHost {
            calls: calls.clone(),
            upgraded_instances,
        };
        let mut config = GitConfig::new(fx.git_dir(), fx.work_tree(), "origin", env);
        config.commit_coalesce = Duration::from_millis(10);
        config.push_debounce = Duration::from_millis(10);
        config.sync_poll = Duration::from_secs(3600); // only via kick() in tests
        config.tick = Duration::from_millis(10);
        config.remote_url = "https://github.com/example/warp-mudlib.git".to_string();
        let token_client = github_client(token_server);
        let report_client = github_client(report_server);
        let handle = GitWorker::spawn_with_propose(
            config,
            Some(Box::new(TokenAdapter(token_client))),
            Box::new(host),
            Box::new(RecordingAudit::default()),
            ProposeConfig {
                authorizer: Box::new(loom_git::AllowAllAuthorizer),
                quota: Box::new(loom_git::InMemoryQuota::new()),
                limits: loom_git::ProposeLimits::default(),
                github: Some(ProposeGitHubConfig {
                    pr_opener: Box::new(UnusedPrOpener),
                    owner: "LoomMud".to_string(),
                    repo: "warp".to_string(),
                    report_client: Some(Arc::new(ReportAdapter(report_client))),
                }),
            },
        )
        .expect("spawn with an https:// remote_url and a TokenProvider must succeed");
        (handle, calls)
    }

    /// Merges a feature branch into `main` (on the bare remote) with
    /// GitHub's own `--no-ff` merge-commit subject
    /// (`Merge pull request #<n> from ...`), the same convention
    /// `merged_commits`/`extract_merge_commit_pr_number` are built
    /// around.
    fn merge_a_pr_into_main(fx: &Fixture, clone_name: &str, pr_number: u64) {
        let clone = fx.tmp.path().join(clone_name);
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
        git(&clone, &["checkout", "-b", "feature"]);
        std::fs::write(clone.join("hall.wf"), "object hall;\n").unwrap();
        git(&clone, &["add", "-A"]);
        let mut commit = Command::new("git");
        commit
            .current_dir(&clone)
            .args(["commit", "-m", "add hall"]);
        commit
            .env("GIT_AUTHOR_NAME", "reviewer")
            .env("GIT_AUTHOR_EMAIL", "reviewer@loommud.com");
        commit
            .env("GIT_COMMITTER_NAME", "reviewer")
            .env("GIT_COMMITTER_EMAIL", "reviewer@loommud.com");
        assert!(commit.output().unwrap().status.success());
        git(&clone, &["checkout", "main"]);
        let mut merge = Command::new("git");
        merge.current_dir(&clone).args([
            "merge",
            "--no-ff",
            "-m",
            &format!("Merge pull request #{pr_number} from LoomMud/feature"),
            "feature",
        ]);
        merge
            .env("GIT_AUTHOR_NAME", "reviewer")
            .env("GIT_AUTHOR_EMAIL", "reviewer@loommud.com");
        merge
            .env("GIT_COMMITTER_NAME", "reviewer")
            .env("GIT_COMMITTER_EMAIL", "reviewer@loommud.com");
        assert!(merge.output().unwrap().status.success());
        git(&clone, &["push", "origin", "main"]);
    }

    /// Acceptance: a `SyncMain` over a `--no-ff` merge against the
    /// loopback fake GitHub posts exactly one comment on the right PR,
    /// carrying the instance count.
    #[test]
    fn no_ff_merge_posts_exactly_one_comment_with_instance_count() {
        let fx = setup();
        let server = spawn_fake_github(false);
        let (handle, calls) = spawn_reporting_worker(&fx, &server, "test", 3);

        // Establish a known `refs/loom/last-main` via the boot sync
        // (first sync has no prior `main` SHA on record, so it must
        // never try to report).
        handle.barrier();
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            server.comments.lock().unwrap().is_empty(),
            "first sync must never report (no prior `main` SHA)"
        );

        merge_a_pr_into_main(&fx, "reviewer-clone-report", 42);

        handle.kick();
        wait_for(
            || !calls.lock().unwrap().is_empty(),
            "recompile_set to be called after the merge sync",
        );
        wait_for(
            || !server.comments.lock().unwrap().is_empty(),
            "a PR comment to be posted after the merge sync",
        );

        // Give any stray extra delivery a moment to show up before
        // asserting "exactly one".
        std::thread::sleep(Duration::from_millis(200));
        let comments = server.comments.lock().unwrap();
        assert_eq!(
            comments.len(),
            1,
            "expected exactly one comment, got {comments:?}"
        );
        let (pr_number, body) = &comments[0];
        assert_eq!(
            *pr_number, 42,
            "comment must land on PR #42, not another one"
        );
        assert!(
            body.contains("3 live instance"),
            "comment body must carry the instance count: {body}"
        );

        handle.shutdown();
    }

    /// Acceptance: a GitHub 5xx while posting the report must never fail
    /// the `SyncMain` pass -- the fast-forward and recompile still
    /// happen, only the comment attempt itself fails (and is logged).
    #[test]
    fn github_5xx_during_report_does_not_fail_sync_main() {
        let fx = setup();
        let server = spawn_fake_github(true);
        let (handle, calls) = spawn_reporting_worker(&fx, &server, "test", 1);

        handle.barrier();
        std::thread::sleep(Duration::from_millis(100));

        merge_a_pr_into_main(&fx, "reviewer-clone-report-5xx", 7);

        handle.kick();
        wait_for(
            || !calls.lock().unwrap().is_empty(),
            "recompile_set to be called even though the report will 5xx",
        );
        wait_for(
            || fx.work_tree().join("hall.wf").exists(),
            "the fast-forwarded work tree to contain the new file regardless of the report outcome",
        );

        // OBI-278 review item 2: assert the forced 503 was actually
        // served, not just that the test happened to pass without
        // hitting it (the report runs on a detached thread -- see
        // `report_post_merge` -- so it can lag behind the fast-forward
        // asserted above).
        wait_for(
            || server.failed_once.load(std::sync::atomic::Ordering::SeqCst),
            "the fake GitHub server to have actually served the forced 503 for the comment attempt",
        );
        assert!(
            server.comments.lock().unwrap().is_empty(),
            "a single-attempt comment that got a 503 must not also show up as posted"
        );

        handle.shutdown();
    }

    /// Acceptance (OBI-278): a GitHub that *doesn't* error, just sleeps
    /// past `UreqClient`'s own per-call timeout, must not stall
    /// `SyncMain` -- the report runs on a detached thread, so the sync
    /// pass (fast-forward + recompile) finishes on its own schedule
    /// regardless of how long the stalled report thread eventually takes
    /// to give up.
    ///
    /// Bound asserted here: the whole test -- `handle.kick()` through the
    /// fast-forwarded work tree showing up -- finishes in well under
    /// `crate::report::REPORT_TOTAL_DEADLINE` (30s), let alone the
    /// several minutes a synchronous report blocked on a hung GitHub
    /// could have taken (`UreqClient`'s 10s timeout doesn't even apply
    /// here, since nothing ever responds at all).
    #[test]
    fn slow_github_during_report_does_not_stall_sync_main() {
        let fx = setup();
        let connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let connected_clone = connected.clone();
        // A listener that accepts a connection, then sleeps *past*
        // `UreqClient`'s own 10s per-call timeout before ever responding
        // -- a fake GitHub that is merely very slow, not one that hangs
        // forever, so this directly exercises the per-call timeout path
        // the issue describes rather than relying on a connection reset.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                connected_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                std::thread::sleep(Duration::from_secs(12));
                // The client (UreqClient, 10s timeout) has almost
                // certainly already given up and closed its side by
                // now -- this write is best-effort and its result
                // doesn't matter either way.
                drop(stream);
            }
        });
        let server = FakeGitHub {
            addr,
            comments: Arc::new(Mutex::new(Vec::new())),
            failed_once: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        // A separate, fast, fake GitHub for the push/fetch
        // `TokenProvider` side -- every tick's token refresh
        // (`resolve_token`) must keep working at its ordinary pace; it
        // is unrelated to the slow report path this test exercises.
        let token_server = spawn_fake_github(false);
        let (handle, calls) =
            spawn_reporting_worker_split_servers(&fx, &token_server, &server, "test", 1);

        handle.barrier();
        std::thread::sleep(Duration::from_millis(100));

        merge_a_pr_into_main(&fx, "reviewer-clone-report-hang", 9);

        let started = std::time::Instant::now();
        handle.kick();
        wait_for(
            || !calls.lock().unwrap().is_empty(),
            "recompile_set to be called even though GitHub is about to stall answering the report",
        );
        wait_for(
            || fx.work_tree().join("hall.wf").exists(),
            "the fast-forwarded work tree to contain the new file regardless of the stalled report",
        );
        let sync_elapsed = started.elapsed();
        // Bound #1: `SyncMain` itself (fast-forward + recompile) is
        // never blocked on the report at all -- it is observed complete
        // in well under a second in practice; 5s gives ample CI margin
        // while still being nowhere near the "minutes" a synchronous
        // report over a slow GitHub could have taken.
        assert!(
            sync_elapsed < Duration::from_secs(5),
            "SyncMain (fast-forward + recompile) must not be stalled by a slow GitHub report \
             call, took {sync_elapsed:?}"
        );

        // Bound #2: the detached report thread (`report_post_merge`)
        // really was dispatched, not silently skipped -- its outbound
        // HTTP call reaching the (slow) fake GitHub shows up almost
        // immediately too, independent of the git-worker thread's own
        // pace. From there, `UreqClient`'s existing 10s per-call timeout
        // bounds how long that one in-flight call can run, comfortably
        // inside `report::REPORT_TOTAL_DEADLINE`'s 30s total ceiling for
        // the whole pass -- not the open-ended "stall for minutes" this
        // ticket started from.
        wait_for(
            || connected.load(std::sync::atomic::Ordering::SeqCst),
            "the detached report thread to have reached out to the (slow) fake GitHub",
        );
        let total_elapsed = started.elapsed();
        assert!(
            total_elapsed < Duration::from_secs(5),
            "dispatching the report's HTTP call must also happen promptly, not after the \
             git-worker thread's own work; took {total_elapsed:?}"
        );

        handle.shutdown();
    }
}
