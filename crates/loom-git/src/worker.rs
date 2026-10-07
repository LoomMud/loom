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
    /// How many currently-live objects run one of `recompiled`'s programs
    /// (mirrors `loom_vm::bcvm::RecompileReport::upgraded_instances`,
    /// OBI-89: install is lazy, so this counts who *will* migrate on next
    /// access, not a synchronous migration that already happened).
    pub upgraded_instances: usize,
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
    /// The remote's URL (OBI-210 R4, CTO decision: belongs in loom-git,
    /// not just B3.5's bootstrap wiring). Used to scope the credential
    /// header to exactly this remote via
    /// `http.<remote_url>.extraHeader` instead of a global
    /// `http.extraHeader` that every `git` invocation (including ones
    /// talking to an entirely different host, e.g. a submodule or a
    /// future second remote) would also pick up. [`GitWorker::spawn`]
    /// refuses to start with a [`TokenProvider`] configured unless this
    /// is `https://`: an installation token must never be sent to a
    /// plain-`http://`/`git://`/`ssh://` remote where it could leak in
    /// the clear or to the wrong host.
    pub remote_url: String,
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
        let remote = remote.into();
        Self {
            git_dir: git_dir.into(),
            work_tree: work_tree.into(),
            // Callers that need the credential header scoped correctly
            // (anything with a `TokenProvider`) must set `remote_url`
            // explicitly -- this constructor has no way to know the URL
            // a bare `remote` *name* resolves to, and defaulting it to
            // the name itself is a safe, inert placeholder for the
            // `allow_unauthenticated_remote`/no-token test paths that
            // never read it.
            remote_url: remote.clone(),
            remote,
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
    /// The same dedicated App (D-B3.9), used for the post-merge
    /// `SyncMain` PR report (OBI-213/OBI-272: `merged_commits` +
    /// `report_recompile`). `None` here means that report is skipped
    /// entirely -- distinct from `pr_opener`, since a `propose`-only test
    /// double doesn't necessarily also implement
    /// [`crate::report::ReportGitHub`].
    ///
    /// `Arc`, not `Box` (OBI-278): the actual network calls run on a
    /// detached thread (see [`report_post_merge`]), never the
    /// git-worker thread itself, so this has to be cheaply cloneable
    /// into that thread rather than borrowed for the duration of the
    /// call.
    pub report_client: Option<Arc<dyn crate::report::ReportGitHub>>,
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
    ///
    /// Refuses to start (OBI-210 R4, CTO decision) when a
    /// [`TokenProvider`] is configured but `config.remote_url` is not an
    /// `https://` URL: an installation token is HTTP(S)-bearer-shaped
    /// (`Authorization: Basic ...` over `http.extraHeader`) and must
    /// never be pointed at a plain-`http://` remote (sent in the clear)
    /// or an `ssh://`/`git://` one (the header would simply be ignored,
    /// silently downgrading to push/fetch disabled -- surprising enough
    /// on its own to fail loudly instead).
    pub fn spawn(
        config: GitConfig,
        token_provider: Option<Box<dyn TokenProvider>>,
        recompile_host: Box<dyn RecompileHost>,
        audit: Box<dyn AuditSink>,
    ) -> Result<GitWorkerHandle, String> {
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
    ) -> Result<GitWorkerHandle, String> {
        if token_provider.is_some() && !config.remote_url.starts_with("https://") {
            return Err(format!(
                "loom-git: refusing to start -- a TokenProvider is configured but \
                 remote_url {:?} is not an https:// URL (OBI-210 R4)",
                config.remote_url
            ));
        }
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
        Ok(GitWorkerHandle {
            tx,
            tree_lock,
            join: Arc::new(Mutex::new(Some(join))),
        })
    }
}

/// OBI-210 R1 (CTO review of PR #82): the pure doubling-and-cap step
/// `run`'s main loop uses to schedule the next dirty-tree retry, pulled
/// out so a test can exercise exactly what the worker calls rather than
/// re-implementing the formula.
fn next_dirty_retry_backoff(current: Duration, cap: Duration) -> Duration {
    current.saturating_mul(2).min(cap)
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
    // OBI-210 R1 (CTO re-review): a dirty tree that no `Msg::Write` will
    // ever commit (a stray untracked file, a rejected write, a driver
    // artifact) must not turn `retry=true` into an unthrottled re-fetch
    // every `tick`. `dirty_retry_backoff` starts at `config.tick` and
    // doubles on every consecutive retry, capped at `config.sync_poll`;
    // it resets the moment a sync pass settles (retry no longer needed).
    let mut dirty_retry_backoff = config.tick.max(Duration::from_millis(1));
    let mut dirty_retry_due: Option<Instant> = None;
    let mut last_dirty_warn: Option<Instant> = None;

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

        let retry_due = dirty_retry_due.is_some_and(|d| Instant::now() >= d);
        if sync_requested || retry_due || last_sync.elapsed() >= config.sync_poll {
            sync_requested = false;
            dirty_retry_due = None;
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
                &propose_config,
            );
            match retry {
                Some(dirty_paths) => {
                    // OBI-210 R1: back off instead of retrying every
                    // `tick` -- a dirty tree that no `Msg::Write` will
                    // ever commit (a stray untracked file, a rejected
                    // write, a driver artifact) must not turn into an
                    // unthrottled re-fetch loop against the remote.
                    let backoff = dirty_retry_backoff;
                    dirty_retry_due = Some(Instant::now() + backoff);
                    dirty_retry_backoff = next_dirty_retry_backoff(backoff, config.sync_poll);
                    if last_dirty_warn.is_none_or(|t| t.elapsed() >= backoff) {
                        tracing::warn!(
                            paths = ?dirty_paths,
                            backoff_ms = backoff.as_millis(),
                            "loom-git: work tree not clean, backing off the fast-forward retry"
                        );
                        last_dirty_warn = Some(Instant::now());
                    }
                }
                None => {
                    // Settled (or a failure unrelated to a dirty tree,
                    // e.g. fetch failed): a fresh dirty-tree episode
                    // should start backing off from the bottom again.
                    dirty_retry_backoff = config.tick.max(Duration::from_millis(1));
                    last_dirty_warn = None;
                }
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
        TokenStatus::Ok(t) => match repo.git_authed(&args, Some(t), &config.remote_url) {
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
        TokenStatus::Ok(t) => Some(repo.git_authed(args, Some(t), &config.remote_url)),
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
    propose_config: &ProposeConfig,
) -> Option<Vec<String>> {
    let fetch_args = ["fetch", config.remote.as_str(), "main"];
    match remote_git(repo, config, token_status, &fetch_args) {
        Some(Ok(_)) => {}
        Some(Err(e)) => {
            tracing::warn!(error = %e, "loom-git: fetch main failed");
            crate::metrics::record_sync("fetch_failed");
            return None;
        }
        None => {
            crate::metrics::record_sync("disabled");
            return None;
        }
    }

    let new_main = match rev_parse(repo, "FETCH_HEAD") {
        Ok(sha) => sha,
        Err(e) => {
            tracing::warn!(error = %e, "loom-git: could not resolve FETCH_HEAD");
            crate::metrics::record_sync("fetch_failed");
            return None;
        }
    };
    let old_main = rev_parse(repo, "refs/loom/last-main").ok();
    if old_main.as_deref() == Some(new_main.as_str()) {
        crate::metrics::record_sync("no_change");
        return None;
    }
    let old_live = match rev_parse(repo, "live") {
        Ok(sha) => sha,
        Err(e) => {
            tracing::warn!(error = %e, "loom-git: no `live` ref");
            crate::metrics::record_sync("fetch_failed");
            return None;
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
        return None;
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
        //
        // `main` itself did move (we already returned above when it
        // hadn't) even though `live` didn't need to change for it --
        // record that now, not just on the fast-forward path below, or
        // `old_main` never advances past `None` until the *next* `main`
        // move that actually touches `live`, and every pass in between
        // wrongly looks like "first sync" to `report_post_merge`
        // (OBI-272).
        //
        // This branch intentionally posts no post-merge PR report for
        // this range (OBI-278): `report_post_merge` is only called below
        // once `live` has actually moved, and that is deliberate here --
        // `main` moved but produced no change worth telling any PR about
        // (its rebuild already landed in an earlier pass, or it touched
        // nothing that survives onto `live`), so there is nothing to
        // report yet. The *next* pass that does move `live` reports
        // against `refs/loom/last-main` as just updated below, so the
        // range is never silently dropped, only deferred.
        let _ = repo.git(&["update-ref", "refs/loom/last-main", &new_main]);
        crate::metrics::record_sync(if rebase_ok {
            "no_change"
        } else {
            "conflict_resolved"
        });
        return None;
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
    //
    // OBI-210 R2 (CTO re-review): `live` must only ever point somewhere
    // the work tree actually reflects. Detach HEAD and check out
    // `new_live` *first* -- while `refs/heads/live` still points at
    // `old_live`, so a checkout failure leaves both the ref and the
    // branch untouched -- and only then move `refs/heads/live` and
    // re-attach `HEAD` to it. The previous order (`update-ref` then
    // `checkout -f live`) could leave `live` already moved to `new_live`
    // while the work tree was still on `old_live`'s contents if the
    // checkout step failed; the next pass would then see
    // `new_live == old_live`'s *old* value no longer matching `live` and
    // limp along with a stale tree forever, since `refs/loom/last-main`
    // is only advanced below this block.
    let mut needs_retry = false;
    let dirty_paths: Vec<String>;
    {
        let _guard = tree_lock.write_guard();
        let status_output = repo
            .git(&["status", "--porcelain"])
            .ok()
            .and_then(|o| stdout_string(&o).ok());
        let status_clean = status_output
            .as_deref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(false);
        dirty_paths = status_output
            .as_deref()
            .map(|s| {
                s.lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let live_unchanged = rev_parse(repo, "live")
            .map(|s| s == old_live)
            .unwrap_or(false);
        let tree_safe = status_clean && live_unchanged;
        if !tree_safe {
            needs_retry = true;
        } else if repo
            .git(&["checkout", "-f", "--detach", &new_live])
            .is_err()
        {
            // OBI-210 follow-up (CTO review of PR #82): a `checkout -f
            // --detach` that fails partway can leave the work tree
            // mid-checkout even though `refs/heads/live`/`HEAD` are
            // still exactly as they were (`live` at `old_live`). Left
            // alone, the *next* pass would see that half-updated tree as
            // dirty and back off forever instead of self-healing. `live`
            // itself is still `old_live` here, so a best-effort
            // `checkout -f live` is safe and gives the tree a chance to
            // recover before the next retry.
            let _ = repo.git(&["checkout", "-f", "live"]);
            needs_retry = true;
        } else if repo
            .git(&["update-ref", "refs/heads/live", &new_live])
            .is_err()
            || repo
                .git(&["symbolic-ref", "HEAD", "refs/heads/live"])
                .is_err()
        {
            // Checkout succeeded (work tree now matches `new_live`) but
            // moving the ref/re-attaching HEAD failed -- roll `live`
            // back to `old_live` and re-detach there so the ref and the
            // work tree stay consistent with each other rather than
            // advancing one without the other.
            let _ = repo.git(&["update-ref", "refs/heads/live", &old_live]);
            let _ = repo.git(&["checkout", "-f", "live"]);
            needs_retry = true;
        } else {
            let _ = repo.git(&["clean", "-fd"]);
        }
    }
    if needs_retry {
        crate::metrics::record_sync("retry_dirty_tree");
        // OBI-210 R1: the caller backs this off exponentially (capped at
        // `sync_poll`) instead of retrying every `tick` -- a stray
        // untracked file, a rejected write, or a driver artifact that no
        // `Msg::Write` will ever commit must not turn into an
        // unthrottled re-fetch loop against the remote.
        return Some(dirty_paths);
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
        // OBI-272 (B3.3 slice 5): best-effort post-merge PR report --
        // off the tree lock (already released above), and a GitHub
        // failure here must never fail the sync itself.
        report_post_merge(
            repo,
            config,
            propose_config,
            old_main.as_deref(),
            &new_main,
            &new_live,
            &outcome,
        );
    }
    None
}

/// OBI-213/OBI-272 (D-B3.13/D-B3.14): after a successful recompile,
/// comment on whatever PR(s) just merged into the moved range of `main`
/// with what happened. Skipped entirely (not an error) when there's no
/// `GitHubAppClient` configured for this ([`ProposeGitHubConfig`]'s
/// `report_client`), or when `old_main` is `None` (first sync: nothing
/// to diff against).
///
/// OBI-278: the actual GitHub calls (`resolve_pull_requests`'s
/// commits-to-pulls fallback, then up to [`crate::report::MAX_UNIQUE_PRS`]
/// `create_issue_comment` calls) run on a **detached thread**, bounded
/// by [`crate::report::REPORT_TOTAL_DEADLINE`] total -- never the
/// git-worker thread this function is called from. `UreqClient`'s own
/// per-call timeout (10s) times up to 100 commits plus 20 comments could
/// otherwise stall commit/push/sync for minutes on a slow GitHub.
/// `merged_commits` itself stays synchronous here: it is a local `git
/// log`, not a network call, and the caller needs its `is_empty()` to
/// decide whether there's anything to report at all. Every failure past
/// that point (a GitHub 5xx, a transport timeout) is logged on the
/// detached thread and otherwise swallowed -- this must never fail, or
/// even delay, the `SyncMain` pass it's reporting on.
fn report_post_merge(
    repo: &Repo,
    config: &GitConfig,
    propose_config: &ProposeConfig,
    old_main: Option<&str>,
    new_main: &str,
    new_live: &str,
    outcome: &RecompileOutcome,
) {
    let Some(gh_cfg) = propose_config.github.as_ref() else {
        return;
    };
    let Some(report_client) = gh_cfg.report_client.clone() else {
        return;
    };
    let Some(old_main) = old_main else {
        tracing::debug!(
            "loom-git: no prior `main` SHA on record, skipping post-merge PR report (first sync)"
        );
        return;
    };
    let commits = match crate::report::merged_commits(repo, old_main, new_main) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "loom-git: merged_commits failed, skipping post-merge PR report");
            return;
        }
    };
    if commits.is_empty() {
        return;
    }
    let owner = gh_cfg.owner.clone();
    let repo_name = gh_cfg.repo.clone();
    let env_name = config.env_name.clone();
    let new_live = new_live.to_string();
    let outcome = outcome.clone();
    // Cutoff for *starting* calls; the whole pass ends by
    // start + REPORT_TOTAL_DEADLINE (30s) even with one call in flight.
    let deadline = crate::report::report_call_cutoff(Instant::now());
    let spawned = std::thread::Builder::new()
        .name("loom-git-report".to_string())
        .spawn(move || {
            let _ = crate::report::report_recompile(
                report_client.as_ref(),
                &owner,
                &repo_name,
                &env_name,
                &new_live,
                &commits,
                &outcome,
                deadline,
            );
        });
    if let Err(e) = spawned {
        tracing::warn!(error = %e, "loom-git: failed to spawn post-merge PR report thread");
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    struct NullHost;
    impl RecompileHost for NullHost {
        fn recompile_set(&self, changed: Vec<String>, deleted: Vec<String>) -> RecompileOutcome {
            RecompileOutcome {
                ok: true,
                recompiled: changed,
                upgraded_instances: 0,
                failures: deleted.into_iter().map(|d| (d, String::new())).collect(),
            }
        }
    }

    fn git_ok(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .expect("spawn git");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A bare `main` + a driver repo already on `live` (same shape as
    /// `tests/integration.rs::setup`, trimmed for a white-box unit test
    /// that needs to reach into `git_dir` directly).
    struct Fixture {
        _tmp: tempfile::TempDir,
        bare: PathBuf,
        git_dir: PathBuf,
        work_tree: PathBuf,
    }

    fn setup() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let bare = tmp.path().join("remote.git");
        git_ok(
            tmp.path(),
            &[
                "init",
                "--quiet",
                "--bare",
                "-b",
                "main",
                bare.to_str().unwrap(),
            ],
        );

        let work_tree = tmp.path().join("work");
        std::fs::create_dir_all(&work_tree).unwrap();
        let git_dir = work_tree.join(".git");
        git_ok(&work_tree, &["init", "--quiet", "-b", "main"]);
        std::fs::write(work_tree.join("room.wf"), "object room;\n").unwrap();
        git_ok(&work_tree, &["add", "-A"]);
        let mut commit = Command::new("git");
        commit
            .current_dir(&work_tree)
            .args(["commit", "-m", "init"]);
        commit
            .env("GIT_AUTHOR_NAME", "driver")
            .env("GIT_AUTHOR_EMAIL", "driver@loommud.com")
            .env("GIT_COMMITTER_NAME", "driver")
            .env("GIT_COMMITTER_EMAIL", "driver@loommud.com");
        assert!(commit.output().unwrap().status.success());
        git_ok(
            &work_tree,
            &["remote", "add", "origin", bare.to_str().unwrap()],
        );
        git_ok(&work_tree, &["push", "origin", "main"]);
        git_ok(&work_tree, &["branch", "live"]);
        git_ok(&work_tree, &["checkout", "live"]);

        Fixture {
            _tmp: tmp,
            bare,
            git_dir,
            work_tree,
        }
    }

    fn test_config(fx: &Fixture) -> GitConfig {
        let mut config = GitConfig::new(fx.git_dir.clone(), fx.work_tree.clone(), "origin", "test");
        config.allow_unauthenticated_remote = true;
        config
    }

    /// OBI-210 R2 (CTO re-review of PR #81): if `checkout -f --detach
    /// <new_live>` succeeds but moving `refs/heads/live`/re-attaching
    /// `HEAD` then fails, `live` must be rolled back to `old_live` rather
    /// than left pointing at a commit the work tree (and `HEAD`) don't
    /// actually reflect.
    ///
    /// Root-sensitive (CTO review of PR #82): relies on a `0o555`
    /// `refs/heads` directory actually denying the write that forces the
    /// ref-move failure this test exercises -- root ignores Unix
    /// permission bits, so this would silently pass for the wrong reason
    /// under a root test runner. CI runs as non-root.
    #[test]
    fn checkout_succeeds_but_ref_move_fails_rolls_live_back() {
        let fx = setup();
        let config = test_config(&fx);
        let repo = Repo::new(&fx.git_dir, &fx.work_tree);
        let tree_lock = TreeLock::new();

        // A real upstream `main` move so the sync pass has something to
        // fast-forward onto.
        let clone = fx.work_tree.parent().unwrap().join("reviewer-clone");
        git_ok(
            fx.work_tree.parent().unwrap(),
            &[
                "clone",
                "--quiet",
                fx.bare.to_str().unwrap(),
                clone.to_str().unwrap(),
            ],
        );
        std::fs::write(clone.join("hall.wf"), "object hall;\n").unwrap();
        git_ok(&clone, &["add", "-A"]);
        let mut commit = Command::new("git");
        commit
            .current_dir(&clone)
            .args(["commit", "-m", "add hall"]);
        commit
            .env("GIT_AUTHOR_NAME", "reviewer")
            .env("GIT_AUTHOR_EMAIL", "reviewer@loommud.com")
            .env("GIT_COMMITTER_NAME", "reviewer")
            .env("GIT_COMMITTER_EMAIL", "reviewer@loommud.com");
        assert!(commit.output().unwrap().status.success());
        git_ok(&clone, &["push", "origin", "main"]);

        let old_live = rev_parse(&repo, "live").unwrap();

        // Make `refs/heads` unwritable (but still readable/traversable)
        // so `checkout -f --detach <sha>` -- which only rewrites `HEAD`
        // and the index, neither of which live under `refs/` -- still
        // succeeds, but the subsequent `update-ref refs/heads/live` (a
        // write under `refs/heads/`) fails.
        let refs_heads = fx.git_dir.join("refs").join("heads");
        let mut perms = std::fs::metadata(&refs_heads).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&refs_heads, perms).unwrap();

        let token_status = TokenStatus::Absent;
        let propose_config = ProposeConfig::disabled();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_sync_main(
                &repo,
                &config,
                &tree_lock,
                &token_status,
                &NullHost,
                &NoopAudit,
                &propose_config,
            )
        }));

        // Always restore permissions before asserting/unwinding further,
        // so a failing assertion doesn't leave the temp dir impossible
        // for `tempfile` to clean up.
        let mut perms = std::fs::metadata(&refs_heads).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&refs_heads, perms).unwrap();

        let outcome = result.unwrap();
        assert!(
            outcome.is_some(),
            "a failed ref move must ask the caller to retry, not silently settle"
        );

        let live_after = rev_parse(&repo, "live").unwrap();
        assert_eq!(
            live_after, old_live,
            "`live` must be rolled back to `old_live`, not left dangling at `new_live`"
        );

        let head_out = repo.git(&["symbolic-ref", "HEAD"]).unwrap();
        let head = stdout_string(&head_out).unwrap();
        assert_eq!(
            head.trim(),
            "refs/heads/live",
            "HEAD must be re-attached to `refs/heads/live`, not left detached"
        );

        // The work tree must match whatever `live`/`HEAD` actually points
        // to -- no stale mismatch between the ref and the checked-out
        // content.
        assert!(!fx.work_tree.join("hall.wf").exists());
        assert!(fx.work_tree.join("room.wf").exists());
    }

    /// OBI-210 R1: the backoff computed by the worker's main loop grows
    /// and is capped at `sync_poll`.
    #[test]
    fn dirty_retry_backoff_doubles_and_caps() {
        let cap = Duration::from_secs(1);
        let mut backoff = Duration::from_millis(20);
        let mut seen = Vec::new();
        for _ in 0..10 {
            seen.push(backoff);
            backoff = next_dirty_retry_backoff(backoff, cap);
        }
        assert_eq!(
            seen,
            vec![
                Duration::from_millis(20),
                Duration::from_millis(40),
                Duration::from_millis(80),
                Duration::from_millis(160),
                Duration::from_millis(320),
                Duration::from_millis(640),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
            ]
        );
    }
}
