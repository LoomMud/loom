// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The `GitWorker` thread (D-B3.1): one serialised job queue (commit,
//! push, sync; `propose` is B3.3's job, not implemented here) that is the
//! only thing in the driver allowed to run `git`.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use crate::cli::{GitError, Repo, WorktreeRepo, rejects_git_segment, stdout_string};
use crate::github::pulls::PullRequestOpener;
use crate::identity::{Identity, driver_identity};
use crate::lock::TreeLock;
use crate::propose::{
    self, ProposeAuthorizer, ProposeError, ProposeGitHub, ProposeLimits, ProposeQuota,
    ProposeRequest, ProposeResult,
};

/// Mints (and caches) the short-lived installation token used for push
/// and fetch (D-B3.5/D-B3.11). `None` configured anywhere up the chain
/// means "push disabled", not an error.
pub trait TokenProvider: Send + Sync {
    fn token(&self) -> Result<String, String>;
}

/// A [`TokenProvider`] resolved once per sync/push attempt (R2, CTO
/// review OBI-209): distinguishes "no provider configured" (push/fetch
/// skipped, `"disabled"`) from "the provider errored" (also skipped, but
/// logged and counted as `"failed"` rather than silently falling back to
/// an unauthenticated remote call).
enum TokenStatus {
    Absent,
    Ok(String),
    Err(String),
}

fn resolve_token(provider: &Option<Box<dyn TokenProvider>>) -> TokenStatus {
    match provider {
        None => TokenStatus::Absent,
        Some(p) => match p.token() {
            Ok(t) => TokenStatus::Ok(t),
            Err(e) => TokenStatus::Err(e),
        },
    }
}

/// What a merge-sized batch of changes needs on the other side of the
/// `loom-git` / world-thread boundary (design doc §0 "B3.1 interface
/// contract"). The caller that owns both a `World` and this worker is
/// responsible for turning `changed`/`deleted` into `bcvm::ChangeSet` and
/// calling `World::recompile_set` -- see the crate-level docs.
pub trait RecompileHost: Send + Sync {
    fn recompile_set(&self, changed: Vec<String>, deleted: Vec<String>) -> RecompileOutcome;
}

#[derive(Debug, Clone, Default)]
pub struct RecompileOutcome {
    pub ok: bool,
    pub recompiled: Vec<String>,
    pub failures: Vec<(String, String)>,
}

/// D-B3.8: what happens to a `live`-only commit that cannot be cherry
/// picked onto the new `main` without conflict. The wiring caller decides
/// how `audit_log` and author-notify actually work (persist/notify are
/// not this crate's job). `pushed` is whether the conflict ref actually
/// reached the remote (R5a, CTO review OBI-209): a local
/// `refs/loom/conflict/...` keep-ref is always written first regardless,
/// so the commit is never lost even when `pushed` is `false`.
pub trait AuditSink: Send + Sync {
    fn conflict_skipped(
        &self,
        uid: &str,
        sha: &str,
        conflict_ref: &str,
        paths: &[String],
        pushed: bool,
    );
}

pub struct NoopAudit;
impl AuditSink for NoopAudit {
    fn conflict_skipped(
        &self,
        _uid: &str,
        _sha: &str,
        _conflict_ref: &str,
        _paths: &[String],
        _pushed: bool,
    ) {
    }
}

#[derive(Debug, Clone)]
pub struct GitConfig {
    pub git_dir: PathBuf,
    pub work_tree: PathBuf,
    /// Remote name (`git remote add <remote> ...`), usually `origin`.
    pub remote: String,
    /// `<env>` in `live/<env>` (D-B3.3): `staging`, `prod`, or a test env.
    pub env_name: String,
    /// Per-`(uid, path)` commit coalescing window (D-B3.4: 2 s default).
    pub commit_coalesce: Duration,
    /// Push debounce (D-B3.5: 30 s default).
    pub push_debounce: Duration,
    /// Poll interval for `SyncMain` when nothing kicks it (D-B3.7: 5 min
    /// default).
    pub sync_poll: Duration,
    /// Worker loop wake-up granularity. Production can leave this at the
    /// default; tests shrink it (and the durations above) to keep the
    /// suite fast.
    pub tick: Duration,
    /// Test-only escape hatch (R2, CTO review OBI-209): with no
    /// [`TokenProvider`] configured, push/fetch against `remote` are
    /// skipped entirely by default (`"disabled"`), never silently falling
    /// back to an unauthenticated call that could pick up an ambient
    /// credential helper. Integration tests against a local path remote
    /// (no auth needed at all) set this `true` explicitly; production
    /// code must never set it.
    pub allow_unauthenticated_remote: bool,
}

impl GitConfig {
    pub fn new(
        git_dir: impl Into<PathBuf>,
        work_tree: impl Into<PathBuf>,
        remote: impl Into<String>,
        env_name: impl Into<String>,
    ) -> Self {
        Self {
            git_dir: git_dir.into(),
            work_tree: work_tree.into(),
            remote: remote.into(),
            env_name: env_name.into(),
            commit_coalesce: Duration::from_secs(2),
            push_debounce: Duration::from_secs(30),
            sync_poll: Duration::from_secs(300),
            tick: Duration::from_millis(100),
            allow_unauthenticated_remote: false,
        }
    }
}

enum Msg {
    Write {
        uid: String,
        identity: Identity,
        path: String,
        command: String,
    },
    Propose {
        req: ProposeRequest,
        resp: SyncSender<Result<ProposeResult, ProposeError>>,
    },
    Kick,
    Barrier(SyncSender<()>),
    Shutdown,
}

struct PendingCommit {
    identity: Identity,
    /// Most recently written path for this `(uid, path)` key -- always
    /// equal to the key's path; kept for symmetry with `command`.
    path: String,
    command: String,
    deadline: Instant,
}

/// Cloneable, `Send + Sync` handle to a running [`GitWorker`] thread.
/// Dropping the last handle does not stop the thread; call
/// [`GitWorkerHandle::shutdown`] explicitly.
#[derive(Clone)]
pub struct GitWorkerHandle {
    tx: SyncSender<Msg>,
    tree_lock: TreeLock,
    join: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl GitWorkerHandle {
    /// The tree lock a `write_file` call site takes (non-blocking) around
    /// the filesystem write, before calling [`Self::record_write`].
    pub fn tree_lock(&self) -> TreeLock {
        self.tree_lock.clone()
    }

    /// Queue the auto-commit for a just-succeeded `write_file`/files-API
    /// write (D-B3.4). `path` is mudlib-absolute (`/domains/x/y.wf`).
    /// Coalesced per `(uid, path)` on the worker thread; this call never
    /// blocks and never touches the filesystem itself.
    pub fn record_write(
        &self,
        uid: &str,
        identity: Identity,
        path: &str,
        command: &str,
    ) -> Result<(), GitError> {
        if rejects_git_segment(path) {
            // Defence in depth -- `loom-vm::fileio::resolve` is the real
            // P0 gate and should have refused this write already.
            return Err(GitError::Failed {
                args: vec!["record_write".to_string()],
                status: -1,
                stderr: "path contains a `.git` segment".to_string(),
            });
        }
        self.tx
            .send(Msg::Write {
                uid: uid.to_string(),
                identity,
                path: path.to_string(),
                command: command.to_string(),
            })
            .map_err(|_| GitError::Spawn("GitWorker thread is gone".to_string()))
    }

    /// Wake the sync loop immediately instead of waiting for the next
    /// poll tick (D-B3.7: the webhook's only effect).
    pub fn kick(&self) {
        let _ = self.tx.send(Msg::Kick);
    }

    /// Block until every message sent before this call has been received
    /// by the worker thread (test/determinism helper -- does **not** wait
    /// for coalescing/debounce timers to elapse, only for the queue to
    /// drain up to this point).
    pub fn barrier(&self) {
        let (tx, rx) = sync_channel(0);
        if self.tx.send(Msg::Barrier(tx)).is_ok() {
            let _ = rx.recv();
        }
    }

    /// Run the `propose` job (B3.3, design doc §4) on the worker thread,
    /// serialised with commit/push/sync (D-B3.1). Blocks until the job
    /// completes -- same shape as [`Self::barrier`], not a fire-and-forget
    /// message.
    pub fn propose(&self, req: ProposeRequest) -> Result<ProposeResult, ProposeError> {
        let (tx, rx) = sync_channel(0);
        if self.tx.send(Msg::Propose { req, resp: tx }).is_err() {
            return Err(ProposeError::Git(GitError::Spawn(
                "GitWorker thread is gone".to_string(),
            )));
        }
        rx.recv().unwrap_or_else(|_| {
            Err(ProposeError::Git(GitError::Spawn(
                "GitWorker thread is gone".to_string(),
            )))
        })
    }

    pub fn shutdown(&self) {
        let _ = self.tx.send(Msg::Shutdown);
        if let Some(j) = self.join.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = j.join();
        }
    }
}

/// The dedicated `loom-warp-propose` App's PR-create side (D-B3.9):
/// optional, independent of the (also optional) push [`TokenProvider`]
/// above -- "no App configured" (design doc §4 step 7) means this is
/// `None`, not that push/fetch are also disabled.
pub struct ProposeGitHubConfig {
    pub pr_opener: Box<dyn PullRequestOpener>,
    pub owner: String,
    pub repo: String,
}

/// Everything `propose` (B3.3) needs beyond the commit/push/sync config
/// above: the master-gate authorizer, the rate/open-proposal quota, the
/// limits, and (optionally) the GitHub App's PR-create side.
pub struct ProposeConfig {
    pub authorizer: Box<dyn ProposeAuthorizer>,
    pub quota: Box<dyn ProposeQuota>,
    pub limits: ProposeLimits,
    pub github: Option<ProposeGitHubConfig>,
}

impl ProposeConfig {
    /// `propose` with no GitHub App configured at all (step 7): every
    /// call still runs limits/authz/commit-build, then returns
    /// [`ProposeError::NoGitHubApp`] with the commit kept locally.
    pub fn disabled() -> Self {
        Self {
            authorizer: Box::new(crate::propose::AllowAllAuthorizer),
            quota: Box::new(crate::propose::InMemoryQuota::new()),
            limits: ProposeLimits::default(),
            github: None,
        }
    }
}

pub struct GitWorker;

impl GitWorker {
    /// Spawn the worker thread and return a handle. `token_provider`
    /// absent means push/fetch-with-auth is disabled (D-B3.5); the caller
    /// is expected to have already logged the boot warning.
    pub fn spawn(
        config: GitConfig,
        token_provider: Option<Box<dyn TokenProvider>>,
        recompile_host: Box<dyn RecompileHost>,
        audit: Box<dyn AuditSink>,
    ) -> GitWorkerHandle {
        Self::spawn_with_propose(
            config,
            token_provider,
            recompile_host,
            audit,
            ProposeConfig::disabled(),
        )
    }

    /// [`Self::spawn`] plus the `propose` (B3.3) wiring.
    pub fn spawn_with_propose(
        config: GitConfig,
        token_provider: Option<Box<dyn TokenProvider>>,
        recompile_host: Box<dyn RecompileHost>,
        audit: Box<dyn AuditSink>,
        propose_config: ProposeConfig,
    ) -> GitWorkerHandle {
        let (tx, rx) = sync_channel(4096);
        let tree_lock = TreeLock::new();
        let worker_lock = tree_lock.clone();
        let join = std::thread::Builder::new()
            .name("loom-git-worker".to_string())
            .spawn(move || {
                run(
                    config,
                    rx,
                    worker_lock,
                    token_provider,
                    recompile_host,
                    audit,
                    propose_config,
                );
            })
            .expect("spawn loom-git worker thread");
        GitWorkerHandle {
            tx,
            tree_lock,
            join: Arc::new(Mutex::new(Some(join))),
        }
    }
}

fn run(
    config: GitConfig,
    rx: Receiver<Msg>,
    tree_lock: TreeLock,
    token_provider: Option<Box<dyn TokenProvider>>,
    recompile_host: Box<dyn RecompileHost>,
    audit: Box<dyn AuditSink>,
    propose_config: ProposeConfig,
) {
    let repo = Repo::new(&config.git_dir, &config.work_tree);
    let mut pending: std::collections::HashMap<(String, String), PendingCommit> =
        std::collections::HashMap::new();
    let mut push_dirty = false;
    let mut push_deadline: Option<Instant> = None;
    let mut last_sync = Instant::now();
    let mut sync_requested = true; // run one sync pass on boot

    loop {
        match rx.recv_timeout(config.tick) {
            Ok(Msg::Write {
                uid,
                identity,
                path,
                command,
            }) => {
                pending.insert(
                    (uid, path.clone()),
                    PendingCommit {
                        identity,
                        path,
                        command,
                        deadline: Instant::now() + config.commit_coalesce,
                    },
                );
            }
            Ok(Msg::Propose { req, resp }) => {
                handle_propose(
                    &repo,
                    &config,
                    &mut pending,
                    &mut push_dirty,
                    &mut push_deadline,
                    &token_provider,
                    &propose_config,
                    req,
                    resp,
                );
            }
            Ok(Msg::Kick) => sync_requested = true,
            Ok(Msg::Barrier(done)) => {
                let _ = done.send(());
            }
            Ok(Msg::Shutdown) => {
                flush_all_commits(&repo, &mut pending, &mut push_dirty, &mut push_deadline);
                break;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
        // Drain whatever else is immediately available without waiting
        // another full tick (keeps coalescing tight under load).
        loop {
            match rx.try_recv() {
                Ok(Msg::Write {
                    uid,
                    identity,
                    path,
                    command,
                }) => {
                    pending.insert(
                        (uid, path.clone()),
                        PendingCommit {
                            identity,
                            path,
                            command,
                            deadline: Instant::now() + config.commit_coalesce,
                        },
                    );
                }
                Ok(Msg::Propose { req, resp }) => {
                    handle_propose(
                        &repo,
                        &config,
                        &mut pending,
                        &mut push_dirty,
                        &mut push_deadline,
                        &token_provider,
                        &propose_config,
                        req,
                        resp,
                    );
                }
                Ok(Msg::Kick) => sync_requested = true,
                Ok(Msg::Barrier(done)) => {
                    let _ = done.send(());
                }
                Ok(Msg::Shutdown) => {
                    flush_all_commits(&repo, &mut pending, &mut push_dirty, &mut push_deadline);
                    return;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    flush_all_commits(&repo, &mut pending, &mut push_dirty, &mut push_deadline);
                    return;
                }
            }
        }

        flush_due_commits(&repo, &mut pending, &mut push_dirty, &mut push_deadline);

        if sync_requested || last_sync.elapsed() >= config.sync_poll {
            sync_requested = false;
            last_sync = Instant::now();
            // D-B3.7: pending commits drain before the lock is taken.
            flush_all_commits(&repo, &mut pending, &mut push_dirty, &mut push_deadline);
            let token_status = resolve_token(&token_provider);
            let retry = run_sync_main(
                &repo,
                &config,
                &tree_lock,
                &token_status,
                &*recompile_host,
                &*audit,
            );
            if retry {
                // R4: the tree wasn't clean (or `live` moved) right when
                // we were about to fast-forward it -- try again next
                // tick instead of ever force-overwriting a write that
                // landed in that window.
                sync_requested = true;
            }
            // D-B3.5: push after every sync too.
            push_dirty = true;
            push_deadline = Some(Instant::now());
        }

        if push_dirty && push_deadline.is_some_and(|d| Instant::now() >= d) {
            let token_status = resolve_token(&token_provider);
            let result = push_live(&repo, &config, &token_status);
            crate::metrics::record_push(result);
            push_dirty = false;
            push_deadline = None;
        }
    }
}

fn flush_uid_commits(
    repo: &Repo,
    pending: &mut std::collections::HashMap<(String, String), PendingCommit>,
    uid: &str,
    push_dirty: &mut bool,
    push_deadline: &mut Option<Instant>,
) {
    let keys: Vec<(String, String)> = pending.keys().filter(|(u, _)| u == uid).cloned().collect();
    for key in keys {
        if let Some(pc) = pending.remove(&key) {
            commit_one(repo, &pc);
            *push_dirty = true;
            push_deadline.get_or_insert(Instant::now());
        }
    }
}

/// Design doc §4 step 1 ("drain pending commits for the proposer") plus
/// the whole propose job: builds [`ProposeGitHub`] from the worker's
/// configured push token (reused for fetch/push, D-B3.9's note that the
/// same App token provider serves both roles) and `propose_config`'s PR
/// opener, then hands off to [`propose::run_propose`].
#[allow(clippy::too_many_arguments)]
fn handle_propose(
    repo: &Repo,
    config: &GitConfig,
    pending: &mut std::collections::HashMap<(String, String), PendingCommit>,
    push_dirty: &mut bool,
    push_deadline: &mut Option<Instant>,
    token_provider: &Option<Box<dyn TokenProvider>>,
    propose_config: &ProposeConfig,
    req: ProposeRequest,
    resp: SyncSender<Result<ProposeResult, ProposeError>>,
) {
    flush_uid_commits(repo, pending, &req.uid, push_dirty, push_deadline);

    let github = match (token_provider.as_deref(), propose_config.github.as_ref()) {
        (Some(tp), Some(gh_cfg)) => Some(ProposeGitHub {
            token_provider: tp,
            pr_opener: gh_cfg.pr_opener.as_ref(),
            owner: &gh_cfg.owner,
            repo: &gh_cfg.repo,
        }),
        _ => None,
    };
    let result = propose::run_propose(
        repo,
        config,
        github.as_ref(),
        propose_config.authorizer.as_ref(),
        propose_config.quota.as_ref(),
        &propose_config.limits,
        req,
        SystemTime::now(),
    );
    let _ = resp.send(result);
}

fn flush_due_commits(
    repo: &Repo,
    pending: &mut std::collections::HashMap<(String, String), PendingCommit>,
    push_dirty: &mut bool,
    push_deadline: &mut Option<Instant>,
) {
    let now = Instant::now();
    let due: Vec<(String, String)> = pending
        .iter()
        .filter(|(_, v)| v.deadline <= now)
        .map(|(k, _)| k.clone())
        .collect();
    for key in due {
        if let Some(pc) = pending.remove(&key) {
            commit_one(repo, &pc);
            *push_dirty = true;
            push_deadline.get_or_insert(now + Duration::from_secs(30));
        }
    }
}

fn flush_all_commits(
    repo: &Repo,
    pending: &mut std::collections::HashMap<(String, String), PendingCommit>,
    push_dirty: &mut bool,
    push_deadline: &mut Option<Instant>,
) {
    let keys: Vec<(String, String)> = pending.keys().cloned().collect();
    for key in keys {
        if let Some(pc) = pending.remove(&key) {
            commit_one(repo, &pc);
            *push_dirty = true;
            push_deadline.get_or_insert(Instant::now());
        }
    }
}

fn commit_one(repo: &Repo, pc: &PendingCommit) {
    // Work-tree-relative path: mudlib-absolute paths always start with
    // `/`; git wants a path relative to the work tree.
    let rel = pc.path.trim_start_matches('/');
    if let Err(e) = repo.git(&["add", "--", rel]) {
        tracing::warn!(path = %pc.path, error = %e, "loom-git: `git add` failed");
        return;
    }
    // Nothing staged (e.g. the write produced byte-identical content):
    // skip, don't create an empty commit.
    if repo.git(&["diff", "--cached", "--quiet"]).is_ok() {
        return;
    }
    let driver = driver_identity();
    let message = format!("{}\n\n{}", pc.command, pc.identity.signed_off_by_trailer());
    let mut cmd = repo.build(&["commit", "-m", &message]);
    cmd.env("GIT_AUTHOR_NAME", &pc.identity.name);
    cmd.env("GIT_AUTHOR_EMAIL", &pc.identity.email);
    cmd.env("GIT_COMMITTER_NAME", &driver.name);
    cmd.env("GIT_COMMITTER_EMAIL", &driver.email);
    match cmd.output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            tracing::warn!(
                path = %pc.path,
                stderr = %String::from_utf8_lossy(&out.stderr),
                "loom-git: `git commit` failed"
            );
        }
        Err(e) => {
            tracing::warn!(path = %pc.path, error = %e, "loom-git: failed to spawn git commit")
        }
    }
}

fn push_live(repo: &Repo, config: &GitConfig, token_status: &TokenStatus) -> &'static str {
    let refspec = format!("live:refs/heads/live/{}", config.env_name);
    let args = ["push", "--force-with-lease", &config.remote, &refspec];
    match token_status {
        TokenStatus::Ok(t) => match repo.git_authed(&args, Some(t)) {
            Ok(_) => "ok",
            Err(_) => "failed",
        },
        TokenStatus::Err(e) => {
            tracing::warn!(error = %e, "loom-git: token provider failed, push skipped");
            "failed"
        }
        TokenStatus::Absent => {
            // R2 (CTO review OBI-209): no provider configured means
            // push is disabled, never a silent unauthenticated fallback
            // that could pick up an ambient credential helper
            // (D-B3.11). `allow_unauthenticated_remote` is a test-only
            // escape hatch for a local path remote that needs no auth at
            // all.
            if config.allow_unauthenticated_remote {
                match repo.git(&args) {
                    Ok(_) => "ok",
                    Err(_) => "failed",
                }
            } else {
                "disabled"
            }
        }
    }
}

/// Runs `fetch`/`push` with `token_status`'s credentials, or skips
/// entirely (never an unauthenticated fallback, R2) unless
/// `config.allow_unauthenticated_remote` is set.
fn remote_git(
    repo: &Repo,
    config: &GitConfig,
    token_status: &TokenStatus,
    args: &[&str],
) -> Option<Result<std::process::Output, GitError>> {
    match token_status {
        TokenStatus::Ok(t) => Some(repo.git_authed(args, Some(t))),
        TokenStatus::Err(e) => {
            tracing::warn!(error = %e, "loom-git: token provider failed");
            None
        }
        TokenStatus::Absent => {
            if config.allow_unauthenticated_remote {
                Some(repo.git(args))
            } else {
                None
            }
        }
    }
}

/// D-B3.7/D-B3.8: fetch `main`, rebase `live` onto it in a scratch
/// worktree, and either fast-forward the real work tree (clean rebase) or
/// rebuild `live` as `main` + surviving cherry-picks (conflict). Returns
/// `true` when the caller should retry on the next tick instead of
/// treating this pass as settled (R4: the tree wasn't safely
/// fast-forwardable this time).
///
/// Runs `git` either against the main repo's explicit `--git-dir`/
/// `--work-tree`, or (for a `git worktree add`-created scratch/rebuild
/// directory) via `current_dir` discovery of that worktree's own `.git`
/// gitlink -- see [`WorktreeRepo`]'s docs for why the two are not
/// interchangeable.
trait GitRunner {
    fn git(&self, args: &[&str]) -> Result<std::process::Output, GitError>;
}
impl GitRunner for Repo {
    fn git(&self, args: &[&str]) -> Result<std::process::Output, GitError> {
        Repo::git(self, args)
    }
}
impl GitRunner for WorktreeRepo {
    fn git(&self, args: &[&str]) -> Result<std::process::Output, GitError> {
        WorktreeRepo::git(self, args)
    }
}

fn run_sync_main(
    repo: &Repo,
    config: &GitConfig,
    tree_lock: &TreeLock,
    token_status: &TokenStatus,
    recompile_host: &dyn RecompileHost,
    audit: &dyn AuditSink,
) -> bool {
    let fetch_args = ["fetch", config.remote.as_str(), "main"];
    match remote_git(repo, config, token_status, &fetch_args) {
        Some(Ok(_)) => {}
        Some(Err(e)) => {
            tracing::warn!(error = %e, "loom-git: fetch main failed");
            crate::metrics::record_sync("fetch_failed");
            return false;
        }
        None => {
            crate::metrics::record_sync("disabled");
            return false;
        }
    }

    let new_main = match rev_parse(repo, "FETCH_HEAD") {
        Ok(sha) => sha,
        Err(e) => {
            tracing::warn!(error = %e, "loom-git: could not resolve FETCH_HEAD");
            crate::metrics::record_sync("fetch_failed");
            return false;
        }
    };
    let old_main = rev_parse(repo, "refs/loom/last-main").ok();
    if old_main.as_deref() == Some(new_main.as_str()) {
        crate::metrics::record_sync("no_change");
        return false;
    }
    let old_live = match rev_parse(repo, "live") {
        Ok(sha) => sha,
        Err(e) => {
            tracing::warn!(error = %e, "loom-git: no `live` ref");
            crate::metrics::record_sync("fetch_failed");
            return false;
        }
    };

    let scratch = config.git_dir.join("sync-scratch");
    let _ = repo.git(&["worktree", "remove", "--force", &scratch.to_string_lossy()]);
    let _ = std::fs::remove_dir_all(&scratch);
    if let Err(e) = repo.git(&[
        "worktree",
        "add",
        "--detach",
        &scratch.to_string_lossy(),
        &old_live,
    ]) {
        tracing::warn!(error = %e, "loom-git: worktree add failed");
        crate::metrics::record_sync("fetch_failed");
        return false;
    }
    let scratch_repo = WorktreeRepo::new(&scratch);
    let rebase_ok = scratch_repo.git(&["rebase", &new_main]).is_ok();
    let new_live = if rebase_ok {
        rev_parse(&scratch_repo, "HEAD").unwrap_or_else(|_| old_live.clone())
    } else {
        let _ = scratch_repo.git(&["rebase", "--abort"]);
        rebuild_live_skipping_conflicts(
            repo,
            &old_main,
            &old_live,
            &new_main,
            config,
            token_status,
            audit,
        )
    };

    let _ = repo.git(&["worktree", "remove", "--force", &scratch.to_string_lossy()]);
    let _ = std::fs::remove_dir_all(&scratch);

    if new_live == old_live {
        // Nothing survived (shouldn't normally happen -- `main` itself is
        // always in the result -- but guard against an empty rebuild).
        crate::metrics::record_sync(if rebase_ok {
            "no_change"
        } else {
            "conflict_resolved"
        });
        return false;
    }

    let (changed, deleted) = diff_name_status(repo, &old_live, &new_live);

    // R4 (CTO review OBI-209): a write that lands after the
    // `flush_all_commits` above but before this write-guard is taken is
    // not blocked by the tree lock (it only guards the fast-forward
    // itself). Checking the tree is clean and `live` hasn't moved *under
    // the lock*, immediately before ever touching the work tree, closes
    // that window: if either check fails, some other write raced us, so
    // we abandon this fast-forward rather than silently discarding it
    // with `checkout -f`/`clean -fd`, and ask the caller to retry.
    let needs_retry;
    {
        let _guard = tree_lock.write_guard();
        let status_clean = repo
            .git(&["status", "--porcelain"])
            .ok()
            .and_then(|o| stdout_string(&o).ok())
            .map(|s| s.trim().is_empty())
            .unwrap_or(false);
        let live_unchanged = rev_parse(repo, "live")
            .map(|s| s == old_live)
            .unwrap_or(false);
        let tree_safe = status_clean && live_unchanged;
        needs_retry = !tree_safe
            || repo
                .git(&["update-ref", "refs/heads/live", &new_live])
                .is_err()
            || repo.git(&["checkout", "-f", "live"]).is_err();
        if !needs_retry {
            let _ = repo.git(&["clean", "-fd"]);
        }
    }
    if needs_retry {
        crate::metrics::record_sync("retry_dirty_tree");
        return true;
    }
    let _ = repo.git(&["update-ref", "refs/loom/last-main", &new_main]);

    let ahead = rev_list_count(repo, &new_main, &new_live);
    crate::metrics::set_live_ahead_commits(ahead);
    crate::metrics::record_sync(if rebase_ok { "ok" } else { "conflict_resolved" });

    if !changed.is_empty() || !deleted.is_empty() {
        let outcome = recompile_host.recompile_set(changed, deleted);
        crate::metrics::record_sync(if outcome.ok {
            "recompiled"
        } else {
            "compile_failed"
        });
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn rebuild_live_skipping_conflicts(
    repo: &Repo,
    old_main: &Option<String>,
    old_live: &str,
    new_main: &str,
    config: &GitConfig,
    token_status: &TokenStatus,
    audit: &dyn AuditSink,
) -> String {
    // live-only commits: everything on `old_live` that isn't on the base
    // we rebased from (`old_main` if known, else the merge base with
    // `new_main`).
    let base = match old_main {
        Some(m) => m.clone(),
        None => merge_base(repo, old_live, new_main).unwrap_or_else(|| new_main.to_string()),
    };
    let live_only = rev_list_reverse(repo, &base, old_live);

    let rebuild_dir = config.git_dir.join("sync-rebuild");
    let _ = repo.git(&[
        "worktree",
        "remove",
        "--force",
        &rebuild_dir.to_string_lossy(),
    ]);
    let _ = std::fs::remove_dir_all(&rebuild_dir);
    if repo
        .git(&[
            "worktree",
            "add",
            "--detach",
            &rebuild_dir.to_string_lossy(),
            new_main,
        ])
        .is_err()
    {
        return old_live.to_string();
    }
    let rebuild_repo = WorktreeRepo::new(&rebuild_dir);

    for sha in &live_only {
        let ok = rebuild_repo
            .git(&["cherry-pick", "--keep-redundant-commits", sha])
            .is_ok();
        if !ok {
            let _ = rebuild_repo.git(&["cherry-pick", "--abort"]);
            // R5b (CTO review OBI-209): `%an` is the uid
            // (`Identity::for_uid` sets the author *name* to the uid,
            // not the email) -- `%ae` was the wrong field and also
            // attacker-shaped, hence the sanitization below regardless.
            let uid_raw = commit_author_name(repo, sha).unwrap_or_else(|| "unknown".to_string());
            let uid = crate::cli::sanitize_ref_component(&uid_raw);
            let paths = commit_paths(repo, sha);
            // D-B3.8 names this `live/<env>/conflict/<uid>/<sha>`, but a
            // ref cannot have both `refs/heads/live/<env>` *and*
            // `refs/heads/live/<env>/conflict/...` -- git's ref
            // hierarchy forbids a ref from being both a leaf and a
            // directory (D/F conflict), verified empirically here
            // against a real (loose *and* reftable-backend) bare remote.
            // Confirmed with Aragorn as a correction to D-B3.8; using a
            // sibling namespace that preserves the same information
            // (env/uid/sha) without colliding with `live/<env>` itself.
            let conflict_ref = format!("conflict/live/{}/{}/{}", config.env_name, uid, sha);
            // R5a: write a local keep-ref *before* attempting the push,
            // so the skipped commit stays reachable (survives `gc`) even
            // if the push fails, is disabled (no token), or the remote
            // rejects it -- `live` itself no longer references it once
            // rebuilt.
            let local_keep_ref = format!("refs/loom/conflict/{}/{}/{}", config.env_name, uid, sha);
            let _ = repo.git(&["update-ref", &local_keep_ref, sha]);
            let push_args = [
                "push",
                &config.remote,
                &format!("{sha}:refs/heads/{conflict_ref}"),
            ];
            let pushed = remote_git(repo, config, token_status, &push_args)
                .map(|r| r.is_ok())
                .unwrap_or(false);
            audit.conflict_skipped(&uid, sha, &conflict_ref, &paths, pushed);
        }
    }
    let result = rev_parse(&rebuild_repo, "HEAD").unwrap_or_else(|_| old_live.to_string());
    let _ = repo.git(&[
        "worktree",
        "remove",
        "--force",
        &rebuild_dir.to_string_lossy(),
    ]);
    let _ = std::fs::remove_dir_all(&rebuild_dir);
    result
}

fn rev_parse(repo: &dyn GitRunner, rev: &str) -> Result<String, GitError> {
    let out = repo.git(&["rev-parse", rev])?;
    Ok(stdout_string(&out)?.trim().to_string())
}

fn merge_base(repo: &dyn GitRunner, a: &str, b: &str) -> Option<String> {
    repo.git(&["merge-base", a, b])
        .ok()
        .and_then(|o| stdout_string(&o).ok())
        .map(|s| s.trim().to_string())
}

fn rev_list_reverse(repo: &dyn GitRunner, from: &str, to: &str) -> Vec<String> {
    let range = format!("{from}..{to}");
    repo.git(&["rev-list", "--reverse", &range])
        .ok()
        .and_then(|o| stdout_string(&o).ok())
        .map(|s| {
            s.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn rev_list_count(repo: &dyn GitRunner, from: &str, to: &str) -> u64 {
    let range = format!("{from}..{to}");
    repo.git(&["rev-list", "--count", &range])
        .ok()
        .and_then(|o| stdout_string(&o).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn commit_author_name(repo: &dyn GitRunner, sha: &str) -> Option<String> {
    repo.git(&["log", "-1", "--format=%an", sha])
        .ok()
        .and_then(|o| stdout_string(&o).ok())
        .map(|s| s.trim().to_string())
}

fn commit_paths(repo: &dyn GitRunner, sha: &str) -> Vec<String> {
    repo.git(&["show", "--name-only", "--format=", sha])
        .ok()
        .and_then(|o| stdout_string(&o).ok())
        .map(|s| {
            s.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn diff_name_status(repo: &dyn GitRunner, old: &str, new: &str) -> (Vec<String>, Vec<String>) {
    let range = format!("{old}..{new}");
    let mut changed = Vec::new();
    let mut deleted = Vec::new();
    if let Ok(out) = repo.git(&["diff", "--name-status", &range])
        && let Ok(text) = stdout_string(&out)
    {
        for line in text.lines() {
            let mut parts = line.splitn(2, '\t');
            let status = parts.next().unwrap_or("");
            let path = parts.next().unwrap_or("").to_string();
            if path.is_empty() {
                continue;
            }
            if status.starts_with('D') {
                deleted.push(format!("/{path}"));
            } else if status.starts_with('R') {
                // `R100\told\tnew` -- the new path is the second tab field,
                // already consumed by the first `splitn`; re-split to get
                // both.
                let mut rparts = line.split('\t');
                rparts.next();
                let old_path = rparts.next().unwrap_or("");
                let new_path = rparts.next().unwrap_or("");
                if !old_path.is_empty() {
                    deleted.push(format!("/{old_path}"));
                }
                if !new_path.is_empty() {
                    changed.push(format!("/{new_path}"));
                }
            } else {
                changed.push(format!("/{path}"));
            }
        }
    }
    (changed, deleted)
}
