// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `git_propose` (P2-B3.3, design doc §2 D-B3.9/§4 `propose`): the one
//! driver entry point behind both the in-game `propose` command and
//! `POST /api/v1/propose`. Runs on the `GitWorker` thread, serialised
//! with commit/push/sync (D-B3.1) -- see [`crate::worker`] for the job
//! queue wiring; this module only implements the propose job's own
//! logic so it can be unit tested without a running worker thread.
//!
//! # Flow (design doc §4)
//! 1. Drain pending commits for the proposer (worker's job, not this
//!    module's -- see `GitWorker`'s `Msg::Propose` handling).
//! 2. Expand directories to tracked `.wf`/`.txt` files under `live`;
//!    enforce the file-count/byte-size/open-proposal/daily limits.
//! 3. Apply the `as` mapping (`S/... -> T/...`) to both paths and the
//!    literal `"S/` occurrences inside file contents, counting rewrites.
//! 4. Resolve `main`'s tree (fetching it fresh when a token is
//!    available, else the best locally known `main`) and build the
//!    propose commit as that tree + the mapped files, via git plumbing
//!    (no working-tree checkout, so it never touches `live`'s checkout
//!    or the tree lock).
//! 5. The master gate: `valid_propose` per mapped (target) path,
//!    `valid_read` per source path.
//! 6. Push `propose/<uid>/<stamp>-<slug>` and open a PR. With no
//!    GitHub App configured, the local commit still lands under
//!    `refs/loom/propose/<uid>/<stamp>-<slug>` for a later retry, and
//!    the call returns a clear [`ProposeError::NoGitHubApp`].

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use crate::cli::{GitError, Repo, sanitize_ref_component, stdout_string};
use crate::github::GitHubAppError;
use crate::github::pulls::{PullRequest, PullRequestOpener};
use crate::identity::Identity;
use crate::worker::{GitConfig, TokenProvider};

/// `<=200 files, <=1 MiB total, <=5 open proposals/uid, <=20/day`
/// (design doc §4, OBI-211 acceptance).
#[derive(Debug, Clone)]
pub struct ProposeLimits {
    pub max_files: usize,
    pub max_bytes: u64,
    pub max_open_per_uid: usize,
    pub max_per_day: usize,
}

impl Default for ProposeLimits {
    fn default() -> Self {
        Self {
            max_files: 200,
            max_bytes: 1024 * 1024,
            max_open_per_uid: 5,
            max_per_day: 20,
        }
    }
}

/// The master gate (D-B3.9): `valid_propose` per mapped target path,
/// `valid_read` per source path. The real implementation calls into
/// warp's `can_propose` (OBI-193/warp#12); until that merges, callers
/// wire a test double or a thin adapter against the documented
/// interface.
pub trait ProposeAuthorizer: Send + Sync {
    fn valid_propose(&self, uid: &str, tier: &str, target_path: &str) -> bool;
    fn valid_read(&self, uid: &str, tier: &str, source_path: &str) -> bool;
}

/// Test/bootstrap double: every path passes. Never wire this in
/// production -- see [`ProposeAuthorizer`] docs.
pub struct AllowAllAuthorizer;
impl ProposeAuthorizer for AllowAllAuthorizer {
    fn valid_propose(&self, _uid: &str, _tier: &str, _target_path: &str) -> bool {
        true
    }
    fn valid_read(&self, _uid: &str, _tier: &str, _source_path: &str) -> bool {
        true
    }
}

/// Test double for the authz-denial tests (T2 -> `protected`, T1 ->
/// `domain_live`): denies every path.
pub struct DenyAllAuthorizer;
impl ProposeAuthorizer for DenyAllAuthorizer {
    fn valid_propose(&self, _uid: &str, _tier: &str, _target_path: &str) -> bool {
        false
    }
    fn valid_read(&self, _uid: &str, _tier: &str, _source_path: &str) -> bool {
        false
    }
}

/// Open-proposal and daily-rate bookkeeping (design doc §4 limits 3/4).
/// The real wiring persists this in `audit_log`/a dedicated table so it
/// survives a driver restart and is corrected when a PR is closed
/// (future slice, once the merge webhook lands) -- this trait is the
/// seam for that; [`InMemoryQuota`] is the process-local default used
/// until then.
pub trait ProposeQuota: Send + Sync {
    /// Currently open proposals for `uid`.
    fn open_count(&self, uid: &str) -> usize;
    /// Proposals opened by `uid` in the trailing 24h.
    fn today_count(&self, uid: &str) -> usize;
    /// Record a newly opened proposal.
    fn record(&self, uid: &str, now: SystemTime);
}

#[derive(Default)]
pub struct InMemoryQuota {
    opens: Mutex<std::collections::HashMap<String, Vec<SystemTime>>>,
}

impl InMemoryQuota {
    pub fn new() -> Self {
        Self::default()
    }
}

const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);

impl ProposeQuota for InMemoryQuota {
    fn open_count(&self, uid: &str) -> usize {
        // Process-local proxy for "open PRs": every recorded proposal
        // counts until the process restarts or a future slice wires the
        // merge-webhook close signal. See the trait docs.
        self.opens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(uid)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    fn today_count(&self, uid: &str) -> usize {
        let now = SystemTime::now();
        self.opens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(uid)
            .map(|v| {
                v.iter()
                    .filter(|t| now.duration_since(**t).map(|d| d < ONE_DAY).unwrap_or(true))
                    .count()
            })
            .unwrap_or(0)
    }

    fn record(&self, uid: &str, now: SystemTime) {
        self.opens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(uid.to_string())
            .or_default()
            .push(now);
    }
}

#[derive(Debug, Clone)]
pub struct ProposeRequest {
    pub uid: String,
    /// Display tier (`T1`..`T5`) for the PR body and the authorizer
    /// calls -- the driver reads this from the staff/session row, never
    /// from request input.
    pub tier: String,
    pub identity: Identity,
    /// Mudlib-absolute paths or directories to propose.
    pub paths: Vec<String>,
    /// `as <target-prefix>`: the `T` in `S/... -> T/...`. `S` is derived
    /// from `paths` (their longest common path prefix, or the single
    /// path itself when only one is given).
    pub target_prefix: Option<String>,
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposeError {
    NoGitHubApp,
    NoFiles,
    TooManyFiles(usize),
    TooLarge(u64),
    TooManyOpenProposals(usize),
    DailyLimitExceeded(usize),
    Denied { path: String, reason: String },
    Git(GitError),
    GitHub(String),
}

impl std::fmt::Display for ProposeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposeError::NoGitHubApp => write!(
                f,
                "no GitHub App configured for propose; the commit is kept locally for retry"
            ),
            ProposeError::NoFiles => write!(f, "no tracked .wf/.txt files under the given paths"),
            ProposeError::TooManyFiles(n) => write!(f, "{n} files exceeds the propose limit"),
            ProposeError::TooLarge(n) => write!(f, "{n} bytes exceeds the propose size limit"),
            ProposeError::TooManyOpenProposals(n) => {
                write!(f, "already at the open-proposal limit ({n})")
            }
            ProposeError::DailyLimitExceeded(n) => write!(f, "daily propose limit ({n}) reached"),
            ProposeError::Denied { path, reason } => {
                write!(f, "denied: {path} ({reason})")
            }
            ProposeError::Git(e) => write!(f, "{e}"),
            ProposeError::GitHub(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProposeError {}

impl From<GitHubAppError> for ProposeError {
    fn from(e: GitHubAppError) -> Self {
        ProposeError::GitHub(e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposeResult {
    pub pr_url: String,
    pub pr_number: u64,
    pub files: usize,
    pub rewrites: usize,
    pub branch: String,
}

/// Resolved GitHub identity for the propose job: the dedicated
/// `loom-warp-propose` App (D-B3.9), never a shared PAT.
pub struct ProposeGitHub<'a> {
    pub token_provider: &'a dyn TokenProvider,
    pub pr_opener: &'a dyn PullRequestOpener,
    pub owner: &'a str,
    pub repo: &'a str,
}

#[allow(clippy::too_many_arguments)]
pub fn run_propose(
    repo: &Repo,
    config: &GitConfig,
    github: Option<&ProposeGitHub<'_>>,
    authorizer: &dyn ProposeAuthorizer,
    quota: &dyn ProposeQuota,
    limits: &ProposeLimits,
    req: ProposeRequest,
    now: SystemTime,
) -> Result<ProposeResult, ProposeError> {
    if quota.open_count(&req.uid) >= limits.max_open_per_uid {
        return Err(ProposeError::TooManyOpenProposals(limits.max_open_per_uid));
    }
    if quota.today_count(&req.uid) >= limits.max_per_day {
        return Err(ProposeError::DailyLimitExceeded(limits.max_per_day));
    }

    let sources = expand_tracked_files(repo, &req.paths)?;
    if sources.is_empty() {
        return Err(ProposeError::NoFiles);
    }
    if sources.len() > limits.max_files {
        return Err(ProposeError::TooManyFiles(sources.len()));
    }

    let source_prefix = common_prefix(&req.paths);
    let mapping = req
        .target_prefix
        .as_ref()
        .map(|t| (source_prefix.clone(), t.clone()));

    // Master gate: `valid_read` on every source path.
    for s in &sources {
        if !authorizer.valid_read(&req.uid, &req.tier, s) {
            return Err(ProposeError::Denied {
                path: s.clone(),
                reason: "valid_read".to_string(),
            });
        }
    }

    let mut total_bytes: u64 = 0;
    let mut rewrites = 0usize;
    let mut mapped_files: Vec<(String, Vec<u8>)> = Vec::with_capacity(sources.len());
    for s in &sources {
        let rel = s.trim_start_matches('/');
        let out = repo
            .git(&["cat-file", "-p", &format!("live:{rel}")])
            .map_err(ProposeError::Git)?;
        let content = out.stdout;
        total_bytes += content.len() as u64;
        let (mapped_path, mapped_content, n) = apply_mapping(s, &content, &mapping);
        rewrites += n;
        if !authorizer.valid_propose(&req.uid, &req.tier, &mapped_path) {
            return Err(ProposeError::Denied {
                path: mapped_path,
                reason: "valid_propose".to_string(),
            });
        }
        mapped_files.push((mapped_path, mapped_content));
    }
    if total_bytes > limits.max_bytes {
        return Err(ProposeError::TooLarge(total_bytes));
    }

    let live_sha = rev_parse(repo, "live").map_err(ProposeError::Git)?;
    let token = match github {
        Some(gh) => Some(gh.token_provider.token().map_err(ProposeError::GitHub)?),
        None => None,
    };
    let main_sha = resolve_main_sha(repo, config, token.as_deref())?;

    let stamp = format_stamp(now);
    let slug = slugify(&req.title);
    let uid_component = sanitize_ref_component(&req.uid);
    let branch = format!("propose/{uid_component}/{stamp}-{slug}");

    let pr_body = build_pr_body(
        &req,
        &sources,
        &mapping,
        rewrites,
        &config.env_name,
        &live_sha,
    );
    let message = format!(
        "propose: {}\n\n{}",
        sanitize_title(&req.title),
        req.identity.signed_off_by_trailer()
    );
    let commit_sha = build_commit(
        repo,
        &config.git_dir,
        &main_sha,
        &mapped_files,
        &req.identity,
        &message,
    )
    .map_err(ProposeError::Git)?;

    // D-B3.9/T-GH-* M-GH-2: the local keep-ref is written *before* ever
    // touching the network, so the commit survives even when there is
    // no App configured or the push fails (same shape as R5a's conflict
    // keep-ref in `worker.rs`).
    let local_keep_ref = format!("refs/loom/propose/{uid_component}/{stamp}-{slug}");
    repo.git(&["update-ref", &local_keep_ref, &commit_sha])
        .map_err(ProposeError::Git)?;

    let Some(gh) = github else {
        return Err(ProposeError::NoGitHubApp);
    };
    let token = token.expect("token minted above when `github` is Some");
    repo.git_authed(
        &[
            "push",
            &config.remote,
            &format!("{commit_sha}:refs/heads/{branch}"),
        ],
        Some(&token),
        &config.remote_url,
    )
    .map_err(ProposeError::Git)?;

    let pr: PullRequest = gh
        .pr_opener
        .open_pull_request(
            gh.owner,
            gh.repo,
            &branch,
            "main",
            &sanitize_title(&req.title),
            &pr_body,
        )
        .map_err(ProposeError::from)?;

    quota.record(&req.uid, now);

    Ok(ProposeResult {
        pr_url: pr.html_url,
        pr_number: pr.number,
        files: sources.len(),
        rewrites,
        branch,
    })
}

/// `git ls-tree -r --name-only live -- <path>` covers both a tracked
/// file and a directory expansion uniformly; filtered to `.wf`/`.txt`
/// (design doc §4 step 1).
fn expand_tracked_files(repo: &Repo, paths: &[String]) -> Result<Vec<String>, ProposeError> {
    let mut out = Vec::new();
    for p in paths {
        let rel = p.trim_start_matches('/');
        let listed = repo
            .git(&["ls-tree", "-r", "--name-only", "live", "--", rel])
            .map_err(ProposeError::Git)?;
        let text = stdout_string(&listed).map_err(ProposeError::Git)?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.ends_with(".wf") || line.ends_with(".txt") {
                out.push(format!("/{line}"));
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// `S` in `S/... -> T/...`: the longest common `/`-separated-component
/// prefix of the given paths, or the single path itself when there is
/// only one (design doc §4's mapping step; see module docs for why `S`
/// is derived rather than supplied -- only the target prefix `T` is an
/// explicit `as` argument).
fn common_prefix(paths: &[String]) -> String {
    if paths.is_empty() {
        return String::new();
    }
    if paths.len() == 1 {
        return paths[0].trim_end_matches('/').to_string();
    }
    fn split(p: &str) -> Vec<&str> {
        p.trim_matches('/').split('/').collect()
    }
    let mut common: Vec<&str> = split(&paths[0]);
    for p in &paths[1..] {
        let parts = split(p);
        let n = common.len().min(parts.len());
        let mut i = 0;
        while i < n && common[i] == parts[i] {
            i += 1;
        }
        common.truncate(i);
    }
    format!("/{}", common.join("/"))
}

/// Applies the `S/... -> T/...` mapping to one path and its content,
/// returning the rewritten path, rewritten content, and the number of
/// literal `"S/` occurrences rewritten in the content (counted for the
/// PR body, design doc §4).
fn apply_mapping(
    path: &str,
    content: &[u8],
    mapping: &Option<(String, String)>,
) -> (String, Vec<u8>, usize) {
    let Some((from, to)) = mapping else {
        return (path.to_string(), content.to_vec(), 0);
    };
    let mapped_path = if let Some(rest) = path.strip_prefix(from.as_str()) {
        format!("{to}{rest}")
    } else {
        path.to_string()
    };
    // Only rewrite recognisably textual content (.wf/.txt are always
    // UTF-8 in this mudlib); a non-UTF-8 blob is passed through
    // unchanged rather than corrupted.
    match std::str::from_utf8(content) {
        Ok(text) => {
            let count = text.matches(from.as_str()).count();
            let rewritten = text.replace(from.as_str(), to);
            (mapped_path, rewritten.into_bytes(), count)
        }
        Err(_) => (mapped_path, content.to_vec(), 0),
    }
}

fn resolve_main_sha(
    repo: &Repo,
    config: &GitConfig,
    token: Option<&str>,
) -> Result<String, ProposeError> {
    if let Some(t) = token {
        repo.git_authed(
            &["fetch", &config.remote, "main"],
            Some(t),
            &config.remote_url,
        )
        .map_err(ProposeError::Git)?;
        return rev_parse(repo, "FETCH_HEAD").map_err(ProposeError::Git);
    }
    for candidate in [
        "refs/loom/last-main".to_string(),
        format!("refs/remotes/{}/main", config.remote),
        "main".to_string(),
    ] {
        if let Ok(sha) = rev_parse(repo, &candidate) {
            return Ok(sha);
        }
    }
    Err(ProposeError::Git(GitError::Failed {
        args: vec!["rev-parse".to_string()],
        status: -1,
        stderr: "no known `main` ref to build the propose commit from".to_string(),
    }))
}

fn rev_parse(repo: &Repo, rev: &str) -> Result<String, GitError> {
    let out = repo.git(&["rev-parse", rev])?;
    Ok(stdout_string(&out)?.trim().to_string())
}

/// `main`'s tree + the mapped files from `live` HEAD (no deletions in
/// v1, design doc §4 step 3), built with plumbing so it never touches
/// the checked-out work tree or needs the tree lock.
fn build_commit(
    repo: &Repo,
    git_dir: &Path,
    main_sha: &str,
    files: &[(String, Vec<u8>)],
    identity: &Identity,
    message: &str,
) -> Result<String, GitError> {
    let index_path = git_dir.join(format!(
        "propose-index-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    let _ = std::fs::remove_file(&index_path);
    let index_str = index_path.to_string_lossy().into_owned();
    let envs = [("GIT_INDEX_FILE", index_str.as_str())];

    let result = (|| -> Result<String, GitError> {
        repo.git_piped(&["read-tree", main_sha], &envs, None)?;
        for (path, content) in files {
            let rel = path.trim_start_matches('/');
            let hashed = repo.git_piped(&["hash-object", "-w", "--stdin"], &[], Some(content))?;
            let blob_sha = stdout_string(&hashed)?.trim().to_string();
            let cacheinfo = format!("100644,{blob_sha},{rel}");
            repo.git_piped(
                &["update-index", "--add", "--cacheinfo", &cacheinfo],
                &envs,
                None,
            )?;
        }
        let tree_out = repo.git_piped(&["write-tree"], &envs, None)?;
        let tree_sha = stdout_string(&tree_out)?.trim().to_string();

        let driver = crate::identity::driver_identity();
        let mut cmd = repo.build(&["commit-tree", &tree_sha, "-p", main_sha, "-m", message]);
        cmd.env("GIT_AUTHOR_NAME", &identity.name);
        cmd.env("GIT_AUTHOR_EMAIL", &identity.email);
        cmd.env("GIT_COMMITTER_NAME", &driver.name);
        cmd.env("GIT_COMMITTER_EMAIL", &driver.email);
        let out = cmd.output().map_err(|e| GitError::Spawn(e.to_string()))?;
        if !out.status.success() {
            return Err(GitError::Failed {
                args: vec!["commit-tree".to_string()],
                status: out.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    })();

    let _ = std::fs::remove_file(&index_path);
    result
}

fn unique_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn format_stamp(now: SystemTime) -> String {
    let secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let dt = time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

fn slugify(title: &str) -> String {
    let mut slug: String = title
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    let slug = slug.trim_matches('-');
    let slug = if slug.len() > 40 { &slug[..40] } else { slug };
    if slug.is_empty() {
        "proposal".to_string()
    } else {
        slug.to_string()
    }
}

/// M-GH-9 (threat model §6.4): neutralise `@` mentions in builder text
/// with a zero-width space so no GitHub mention ever fires from a PR
/// title/body, and cap length so a huge paste can't bloat the PR.
const MAX_BODY_LEN: usize = 2048;
const MAX_TITLE_LEN: usize = 256;

fn neutralize_mentions(text: &str) -> String {
    text.replace('@', "@\u{200B}")
}

fn sanitize_title(title: &str) -> String {
    let t = neutralize_mentions(title);
    if t.len() > MAX_TITLE_LEN {
        t.chars().take(MAX_TITLE_LEN).collect()
    } else {
        t
    }
}

fn sanitize_body_text(body: &str) -> String {
    let t = neutralize_mentions(body);
    if t.len() > MAX_BODY_LEN {
        format!(
            "{}... (truncated at {MAX_BODY_LEN} bytes)",
            t.chars().take(MAX_BODY_LEN).collect::<String>()
        )
    } else {
        t
    }
}

fn build_pr_body(
    req: &ProposeRequest,
    sources: &[String],
    mapping: &Option<(String, String)>,
    rewrites: usize,
    env_name: &str,
    live_sha: &str,
) -> String {
    let mapping_line = match mapping {
        Some((from, to)) => format!("`{from}/...` -> `{to}/...` ({rewrites} content rewrite(s))"),
        None => "(none)".to_string(),
    };
    let mut out = String::new();
    out.push_str(&format!("**Proposer:** {} (tier {})\n", req.uid, req.tier));
    out.push_str(&format!("**Environment:** {env_name}\n"));
    out.push_str(&format!("**Source `live` SHA:** {live_sha}\n"));
    out.push_str(&format!("**Mapping:** {mapping_line}\n\n"));
    out.push_str("**Source paths:**\n");
    for s in sources {
        out.push_str(&format!("- `{s}`\n"));
    }
    out.push_str("\n**Description:**\n\n");
    out.push_str(&sanitize_body_text(&req.body));
    out.push_str("\n\n---\n**Reviewer checklist**\n");
    out.push_str("- [ ] Diff touches only the listed source paths (mapped)\n");
    out.push_str("- [ ] No `.github/`, `CODEOWNERS`, or repo-root files\n");
    out.push_str("- [ ] Mapping rewrites look correct (paths and in-file references)\n");
    out.push_str("- [ ] Behaviour matches the description above\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_prefix_single_path_is_itself() {
        assert_eq!(
            common_prefix(&["/domains/legolas/widget".to_string()]),
            "/domains/legolas/widget"
        );
    }

    #[test]
    fn common_prefix_multiple_paths() {
        let paths = vec![
            "/domains/legolas/widget/a.wf".to_string(),
            "/domains/legolas/widget/b/c.wf".to_string(),
        ];
        assert_eq!(common_prefix(&paths), "/domains/legolas/widget");
    }

    #[test]
    fn mapping_rewrites_path_and_literal_content_occurrences() {
        let mapping = Some((
            "/domains/legolas/widget".to_string(),
            "/domains/example".to_string(),
        ));
        let content =
            b"inherit \"/domains/legolas/widget/base\";\n// /domains/legolas/widget again\n";
        let (path, rewritten, n) = apply_mapping("/domains/legolas/widget/a.wf", content, &mapping);
        assert_eq!(path, "/domains/example/a.wf");
        assert_eq!(n, 2);
        let text = String::from_utf8(rewritten).unwrap();
        assert!(text.contains("/domains/example/base"));
        assert!(!text.contains("/domains/legolas/widget"));
    }

    #[test]
    fn no_mapping_is_a_no_op() {
        let (path, content, n) = apply_mapping("/domains/x/a.wf", b"hello", &None);
        assert_eq!(path, "/domains/x/a.wf");
        assert_eq!(content, b"hello");
        assert_eq!(n, 0);
    }

    #[test]
    fn mention_neutralization_defuses_at_mentions() {
        assert_eq!(
            neutralize_mentions("ping @org/root"),
            "ping @\u{200B}org/root"
        );
    }

    #[test]
    fn in_memory_quota_tracks_open_and_daily_counts() {
        let quota = InMemoryQuota::new();
        let now = SystemTime::now();
        assert_eq!(quota.open_count("glorfindel"), 0);
        assert_eq!(quota.today_count("glorfindel"), 0);
        quota.record("glorfindel", now);
        quota.record("glorfindel", now);
        assert_eq!(quota.open_count("glorfindel"), 2);
        assert_eq!(quota.today_count("glorfindel"), 2);
        let old = now - Duration::from_secs(25 * 60 * 60);
        quota.record("glorfindel", old);
        assert_eq!(quota.open_count("glorfindel"), 3);
        // The 25h-old entry doesn't count toward "today".
        assert_eq!(quota.today_count("glorfindel"), 2);
    }

    #[test]
    fn slug_is_lowercase_hyphenated_and_bounded() {
        assert_eq!(slugify("Fix the Thing!!"), "fix-the-thing");
        assert_eq!(slugify(""), "proposal");
        let long = "x".repeat(100);
        assert_eq!(slugify(&long).len(), 40);
    }
}
