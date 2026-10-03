// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! B3.3 slice 4 (OBI-213, design doc D-B3.13/D-B3.14): after a
//! `SyncMain`-triggered recompile, find the PR(s) that just merged into
//! the moved range of `main` and comment on each with what happened.
//!
//! # Finding the PR
//! - Prefer the squash-merge commit subject's trailing `(#N)`
//!   (GitHub appends this itself; see [`extract_pr_number`]) -- no API
//!   call needed, since `loom-git`'s own `git log` already has the
//!   subject.
//! - Second, this repo's actual merge convention: GitHub's own
//!   `Merge pull request #N from ...` merge-commit subject (see
//!   [`extract_merge_commit_pr_number`]) -- also no API call.
//! - Fall back to GitHub's commits-to-pulls API
//!   (`GET /repos/{owner}/{repo}/commits/{sha}/pulls`,
//!   [`super::GitHubAppClient::commit_pulls`]) for anything else
//!   (rebase-merges, a hand-written subject).
//!
//! [`merged_commits`] walks `--first-parent`: a merge-commit-based
//! workflow (this repo's) means `old_main..new_main` without
//! `--first-parent` also includes every commit *on* each merged PR
//! branch (its own "Merge remote-tracking branch 'github/main'" noise
//! included) -- each of those costs a commits-to-pulls API call for
//! nothing, since `--first-parent` alone already gives exactly one
//! commit per merged PR.
//!
//! # Reporting
//! [`comment_body`] builds the report; D-B3.14's all-or-nothing recompile
//! means a `RecompileOutcome { ok: false, .. }` must say plainly that the
//! *old* versions are still running, not quietly list partial progress.
//! [`report_recompile`] caps both how many commits it will resolve and
//! how many distinct PRs it will comment on in one pass
//! ([`MAX_MERGED_COMMITS`]/[`MAX_UNIQUE_PRS`]) -- `main` moving a long
//! way (a long outage, a history reset) must never turn into a burst of
//! comments on dozens of stale PRs.

use crate::cli::{GitError, Repo, stdout_string};
use crate::github::GitHubAppClient;
use crate::github::issues::PullRef;
use crate::github::transport::HttpClient;
use crate::worker::RecompileOutcome;

/// Past this many commits in the moved range, `report_recompile` logs a
/// warning and comments on nothing: almost certainly a long outage, a
/// history reset, or `old` not actually an ancestor of `new`, not an
/// ordinary `SyncMain` pass -- no PR in that range should be guessing at
/// what happened from a years-stale recompile report.
pub const MAX_MERGED_COMMITS: usize = 100;

/// Past this many *distinct* PRs resolved in one pass, stop commenting
/// (with a warning) rather than spam every one of them.
pub const MAX_UNIQUE_PRS: usize = 20;

/// Cap on list items (`recompiled`/`failures`) rendered into one comment
/// body before truncating with a "... and N more" line -- GitHub rejects
/// comment bodies over 65,536 characters, and a batch large enough to
/// need that either way is not useful read in full on a PR.
const MAX_LIST_ITEMS: usize = 50;

/// One commit in the moved range of `main` (`old_main..new_main`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedCommit {
    pub sha: String,
    pub subject: String,
}

/// `git log --first-parent --format=%H%x1f%s <old>..<new>` -- the
/// first-parent commits `main` picked up in this `SyncMain` pass, oldest
/// first. `--first-parent` matters for a merge-commit workflow (this
/// repo's): without it, the range also includes every commit each merged
/// PR branch carried internally. `\x1f` (unit separator) is the field
/// delimiter: never legal in a commit subject, so it cannot be confused
/// with one.
pub fn merged_commits(repo: &Repo, old: &str, new: &str) -> Result<Vec<MergedCommit>, GitError> {
    let range = format!("{old}..{new}");
    let out = repo.git(&[
        "log",
        "--first-parent",
        "--reverse",
        "--format=%H%x1f%s",
        &range,
    ])?;
    let text = stdout_string(&out)?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, '\u{1f}');
            let sha = parts.next()?.to_string();
            let subject = parts.next().unwrap_or("").to_string();
            if sha.is_empty() {
                None
            } else {
                Some(MergedCommit { sha, subject })
            }
        })
        .collect())
}

/// Extracts the trailing `(#N)` GitHub appends to a squash-merge commit
/// subject (`"loom-git: foo (#84)"` -> `Some(84)`). `None` for anything
/// else (merge commits, rebase-and-merge, a hand-written subject) --
/// callers fall back to [`extract_merge_commit_pr_number`] and then the
/// commits-to-pulls API for those.
pub fn extract_pr_number(subject: &str) -> Option<u64> {
    let trimmed = subject.trim_end();
    let rest = trimmed.strip_suffix(')')?;
    let open = rest.rfind("(#")?;
    let digits = &rest[open + 2..];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Extracts the PR number from GitHub's own merge-commit subject
/// (`"Merge pull request #81 from LoomMud/legolas/..."`) -- this repo's
/// actual merge convention (merge commits, not squash). No API call
/// needed, same as [`extract_pr_number`].
pub fn extract_merge_commit_pr_number(subject: &str) -> Option<u64> {
    let rest = subject.strip_prefix("Merge pull request #")?;
    let digits = rest.split(|c: char| !c.is_ascii_digit()).next()?;
    if digits.is_empty() {
        return None;
    }
    // Require the recognizable " from " that always follows the number
    // in GitHub's own subject, so an unrelated commit that merely starts
    // with digits after this prefix (unlikely, but cheap to check) is
    // not misread as a PR number.
    if !rest[digits.len()..].starts_with(" from ") {
        return None;
    }
    digits.parse().ok()
}

/// A merged commit resolved to the PR it belongs to, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCommit {
    pub commit: MergedCommit,
    pub pr_number: Option<u64>,
}

/// Resolves every commit's PR: squash-subject first, this repo's
/// merge-commit subject second, commits-to-pulls fallback third. A
/// lookup failure (transport error, non-2xx) is logged and treated the
/// same as "no PR found" -- this must never panic the sync loop over a
/// GitHub API hiccup.
pub fn resolve_pull_requests<C: HttpClient>(
    client: &GitHubAppClient<C>,
    owner: &str,
    repo: &str,
    commits: &[MergedCommit],
) -> Vec<ResolvedCommit> {
    commits
        .iter()
        .map(|commit| {
            let pr_number = extract_pr_number(&commit.subject)
                .or_else(|| extract_merge_commit_pr_number(&commit.subject))
                .or_else(|| match client.commit_pulls(owner, repo, &commit.sha) {
                    Ok(pulls) => first_pull_number(&pulls),
                    Err(e) => {
                        tracing::warn!(
                            sha = %commit.sha,
                            error = %e,
                            "loom-git: commits-to-pulls lookup failed"
                        );
                        None
                    }
                });
            ResolvedCommit {
                commit: commit.clone(),
                pr_number,
            }
        })
        .collect()
}

fn first_pull_number(pulls: &[PullRef]) -> Option<u64> {
    pulls.first().map(|p| p.number)
}

/// HTML-escapes `s` for safe embedding inside a `<pre>` block in a GitHub
/// comment (Markdown is not re-parsed inside `<pre>`, but `&`/`<`/`>`
/// still need escaping so the raw text can never be read as HTML).
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Renders `items` as a Markdown bullet list, each one path-formatted and
/// capped at [`MAX_LIST_ITEMS`] with a "... and N more" trailer.
fn render_path_list(items: &[String]) -> String {
    let mut body = String::new();
    for path in items.iter().take(MAX_LIST_ITEMS) {
        body.push_str(&format!("- `{path}`\n"));
    }
    if items.len() > MAX_LIST_ITEMS {
        body.push_str(&format!(
            "- ... and {} more\n",
            items.len() - MAX_LIST_ITEMS
        ));
    }
    body
}

/// Renders `failures` as a Markdown list, one `<pre>`-fenced block per
/// failure so a compile diagnostic's own newlines/backticks can never
/// break the comment's Markdown -- capped at [`MAX_LIST_ITEMS`].
fn render_failure_list(failures: &[(String, String)]) -> String {
    let mut body = String::new();
    for (path, err) in failures.iter().take(MAX_LIST_ITEMS) {
        body.push_str(&format!("- `{path}`:\n<pre>{}</pre>\n", html_escape(err)));
    }
    if failures.len() > MAX_LIST_ITEMS {
        body.push_str(&format!(
            "- ... and {} more\n",
            failures.len() - MAX_LIST_ITEMS
        ));
    }
    body
}

/// The report body (D-B3.13/D-B3.14): env, the new `live` SHA, what got
/// recompiled and how many live instances will pick it up, and -- per
/// the all-or-nothing recompile -- an explicit statement that a failure
/// here left the *old* versions running, never a half-upgraded set.
pub fn comment_body(env_name: &str, live_sha: &str, outcome: &RecompileOutcome) -> String {
    let mut body = format!("**loom-git sync** -- `{env_name}` is now at `{live_sha}`.\n\n");
    if outcome.ok {
        if outcome.recompiled.is_empty() {
            body.push_str("No programs needed recompiling for this change.\n");
        } else {
            // OBI-89: `install` itself is lazy, so `upgraded_instances`
            // counts objects that *will* migrate on next access, not a
            // synchronous migration that already happened -- never say
            // "live-upgraded" here, that overstates what just happened.
            body.push_str(&format!(
                "Recompiled {} program(s); {} live instance(s) will pick up the new code on next access:\n",
                outcome.recompiled.len(),
                outcome.upgraded_instances
            ));
            body.push_str(&render_path_list(&outcome.recompiled));
        }
    } else {
        body.push_str(
            "**Recompile failed -- all-or-nothing (D-B3.14): the previous versions are \
             still running, nothing was upgraded.**\n\n",
        );
        if !outcome.recompiled.is_empty() {
            body.push_str(&format!(
                "Attempted to recompile {} program(s):\n",
                outcome.recompiled.len()
            ));
            body.push_str(&render_path_list(&outcome.recompiled));
            body.push('\n');
        }
        if !outcome.failures.is_empty() {
            body.push_str("Compile failures:\n");
            body.push_str(&render_failure_list(&outcome.failures));
        }
    }
    body
}

/// Comments on every unique PR found among `commits`, in deterministic
/// (first-seen) order, capped at [`MAX_UNIQUE_PRS`] distinct PRs and
/// skipped entirely past [`MAX_MERGED_COMMITS`] commits in the moved
/// range (both logged, never a silent no-op). A commit with no
/// resolvable PR is logged and otherwise skipped -- not every commit in
/// the moved range has to be a merged PR, and this must never panic on
/// that case. Returns one entry per PR actually commented on (success or
/// [`crate::github::GitHubAppError`]), so the caller can decide
/// whether/how to surface a comment failure.
pub fn report_recompile<C: HttpClient>(
    client: &GitHubAppClient<C>,
    owner: &str,
    repo: &str,
    env_name: &str,
    live_sha: &str,
    commits: &[MergedCommit],
    outcome: &RecompileOutcome,
) -> Vec<(u64, Result<(), crate::github::GitHubAppError>)> {
    if commits.len() > MAX_MERGED_COMMITS {
        tracing::warn!(
            commits = commits.len(),
            cap = MAX_MERGED_COMMITS,
            "loom-git: moved range too large, skipping PR comments entirely \
             (likely a long outage or history reset, not an ordinary sync)"
        );
        return Vec::new();
    }
    let resolved = resolve_pull_requests(client, owner, repo, commits);
    let body = comment_body(env_name, live_sha, outcome);
    let mut seen = std::collections::BTreeSet::new();
    let mut results = Vec::new();
    for r in &resolved {
        match r.pr_number {
            Some(n) if seen.contains(&n) => {
                // Already commented on this PR via an earlier commit in
                // the same moved range.
            }
            Some(n) => {
                if seen.len() >= MAX_UNIQUE_PRS {
                    tracing::warn!(
                        cap = MAX_UNIQUE_PRS,
                        "loom-git: unique-PR cap reached, skipping remaining PR comments"
                    );
                    break;
                }
                seen.insert(n);
                let result = client.create_issue_comment(owner, repo, n, &body);
                if let Err(e) = &result {
                    tracing::warn!(pr = n, error = %e, "loom-git: PR comment failed");
                }
                results.push((n, result));
            }
            None => {
                tracing::warn!(
                    sha = %r.commit.sha,
                    subject = %r.commit.subject,
                    "loom-git: no PR found for merged commit, skipping comment"
                );
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::UreqClient;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;

    fn test_pem() -> String {
        include_str!("github/testdata/test_key.pkcs8.pem").to_string()
    }

    // --- squash-subject extraction -----------------------------------

    #[test]
    fn extracts_trailing_pr_number() {
        assert_eq!(
            extract_pr_number("loom-git: GitHub App client (#84)"),
            Some(84)
        );
        assert_eq!(extract_pr_number("fix typo (#1)"), Some(1));
    }

    #[test]
    fn non_squash_subjects_yield_none() {
        assert_eq!(
            extract_pr_number("Merge pull request #81 from foo/bar"),
            None
        );
        assert_eq!(extract_pr_number("plain commit message"), None);
        assert_eq!(extract_pr_number("trailing paren but no hash (note)"), None);
        assert_eq!(extract_pr_number("empty parens ()"), None);
        assert_eq!(extract_pr_number("not a number (#abc)"), None);
    }

    // --- merge-commit subject extraction (this repo's actual convention)

    #[test]
    fn extracts_merge_commit_pr_number() {
        assert_eq!(
            extract_merge_commit_pr_number(
                "Merge pull request #81 from LoomMud/legolas/obi-190-loom-git"
            ),
            Some(81)
        );
        assert_eq!(
            extract_merge_commit_pr_number("Merge pull request #3 from foo/bar"),
            Some(3)
        );
    }

    #[test]
    fn merge_commit_extraction_rejects_lookalikes() {
        assert_eq!(extract_merge_commit_pr_number("Merge branch 'main'"), None);
        assert_eq!(
            extract_merge_commit_pr_number("Merge pull request #81notfrom foo"),
            None
        );
        assert_eq!(
            extract_merge_commit_pr_number("Merge pull request # from foo"),
            None
        );
    }

    // --- merged_commits parsing ---------------------------------------

    fn init_test_repo() -> (std::path::PathBuf, Repo) {
        let dir = std::env::temp_dir().join(format!(
            "loom-git-merged-commits-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let init = std::process::Command::new("git")
            .arg("init")
            .arg("--quiet")
            .arg("-b")
            .arg("main")
            .arg(&dir)
            .output()
            .unwrap();
        assert!(init.status.success());
        let repo = Repo::new(dir.join(".git"), &dir);
        (dir, repo)
    }

    fn commit_in(repo: &Repo, dir: &std::path::Path, msg: &str, file: &str) {
        std::fs::write(dir.join(file), msg).unwrap();
        repo.git(&["add", "--", file]).unwrap();
        let mut cmd = repo.build(&["commit", "-m", msg]);
        cmd.env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t");
        assert!(cmd.output().unwrap().status.success());
    }

    fn head(repo: &Repo) -> String {
        repo.git(&["rev-parse", "HEAD"])
            .ok()
            .and_then(|o| stdout_string(&o).ok())
            .unwrap()
            .trim()
            .to_string()
    }

    #[test]
    fn merged_commits_parses_git_log_output() {
        let (dir, repo) = init_test_repo();
        commit_in(&repo, &dir, "first (#1)", "a.txt");
        let old = head(&repo);
        commit_in(&repo, &dir, "second (#2)", "b.txt");
        commit_in(&repo, &dir, "Merge pull request #3 from foo/bar", "c.txt");
        let new = head(&repo);

        let commits = merged_commits(&repo, &old, &new).unwrap();
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].subject, "second (#2)");
        assert_eq!(commits[1].subject, "Merge pull request #3 from foo/bar");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merged_commits_first_parent_skips_feature_branch_noise() {
        let (dir, repo) = init_test_repo();
        commit_in(&repo, &dir, "base", "a.txt");
        let old = head(&repo);

        // A feature branch with its own internal commits (including a
        // "Merge remote-tracking branch" of the kind this repo's
        // branches actually carry), merged with `--no-ff` the way this
        // repo's PRs land.
        repo.git(&["checkout", "-b", "feature"]).unwrap();
        commit_in(&repo, &dir, "feature work", "b.txt");
        commit_in(
            &repo,
            &dir,
            "Merge remote-tracking branch 'github/main' into feature",
            "c.txt",
        );
        repo.git(&["checkout", "main"]).unwrap();
        let mut cmd = repo.build(&[
            "merge",
            "--no-ff",
            "-m",
            "Merge pull request #42 from foo/feature",
            "feature",
        ]);
        cmd.env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t");
        assert!(cmd.output().unwrap().status.success());
        let new = head(&repo);

        let commits = merged_commits(&repo, &old, &new).unwrap();
        // --first-parent: exactly the merge commit, none of the feature
        // branch's own two commits.
        assert_eq!(commits.len(), 1);
        assert_eq!(
            commits[0].subject,
            "Merge pull request #42 from foo/feature"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- fake GitHub server for commits-to-pulls + issue comments -----

    struct FakeGitHub {
        addr: String,
        requests: std::sync::Arc<Mutex<Vec<(String, String)>>>,
    }

    fn spawn_fake_github(
        mut respond: impl FnMut(&str, &str, &str) -> (u16, String) + Send + 'static,
    ) -> FakeGitHub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let requests = std::sync::Arc::new(Mutex::new(Vec::new()));
        let requests_clone = requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = [0u8; 16384];
                let n = match stream.read(&mut buf) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let mut lines = req.lines();
                let first = lines.next().unwrap_or("");
                let mut parts = first.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                requests_clone
                    .lock()
                    .unwrap()
                    .push((path.clone(), body.clone()));
                let (status, resp_body) = respond(&method, &path, &body);
                let status_text = match status {
                    201 => "Created",
                    401 => "Unauthorized",
                    404 => "Not Found",
                    _ => "OK",
                };
                let resp = format!(
                    "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    resp_body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(resp_body.as_bytes());
            }
        });
        FakeGitHub { addr, requests }
    }

    fn client(server: &FakeGitHub) -> GitHubAppClient<UreqClient> {
        GitHubAppClient::new("1", "2", &test_pem(), UreqClient::default())
            .unwrap()
            .with_api_base(format!("http://{}", server.addr))
    }

    fn token_resp() -> (u16, String) {
        (
            201,
            r#"{"token":"ghs_tok","expires_at":"2099-01-01T00:00:00Z"}"#.to_string(),
        )
    }

    #[test]
    fn commits_to_pulls_fallback_resolves_non_squash_commit() {
        let server = spawn_fake_github(|_, path, _| {
            if path.contains("access_tokens") {
                token_resp()
            } else if path.ends_with("/pulls") {
                (200, r#"[{"number":99}]"#.to_string())
            } else {
                (404, "{}".to_string())
            }
        });
        let app = client(&server);
        // A subject neither squash nor this repo's merge-commit form can
        // extract from -- forces the API fallback.
        let commits = vec![MergedCommit {
            sha: "deadbeef".to_string(),
            subject: "Rebased commit, no PR marker".to_string(),
        }];
        let resolved = resolve_pull_requests(&app, "LoomMud", "loom", &commits);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].pr_number, Some(99));
        let paths: Vec<String> = server
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|(p, _)| p.clone())
            .collect();
        assert!(paths.iter().any(|p| p.contains("/commits/deadbeef/pulls")));
    }

    #[test]
    fn squash_subject_skips_the_commits_to_pulls_call() {
        let server = spawn_fake_github(|_, path, _| {
            if path.contains("access_tokens") {
                token_resp()
            } else {
                (404, "{}".to_string())
            }
        });
        let app = client(&server);
        let commits = vec![MergedCommit {
            sha: "abc123".to_string(),
            subject: "loom-git: thing (#42)".to_string(),
        }];
        let resolved = resolve_pull_requests(&app, "LoomMud", "loom", &commits);
        assert_eq!(resolved[0].pr_number, Some(42));
        let hit_pulls_api = server
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(p, _)| p.contains("/pulls"));
        assert!(
            !hit_pulls_api,
            "squash subject must resolve without a commits-to-pulls call"
        );
    }

    #[test]
    fn merge_commit_subject_skips_the_commits_to_pulls_call() {
        let server = spawn_fake_github(|_, path, _| {
            if path.contains("access_tokens") {
                token_resp()
            } else {
                (404, "{}".to_string())
            }
        });
        let app = client(&server);
        let commits = vec![MergedCommit {
            sha: "abc123".to_string(),
            subject: "Merge pull request #81 from LoomMud/legolas/obi-190-loom-git".to_string(),
        }];
        let resolved = resolve_pull_requests(&app, "LoomMud", "loom", &commits);
        assert_eq!(resolved[0].pr_number, Some(81));
        let hit_pulls_api = server
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(p, _)| p.contains("/pulls"));
        assert!(
            !hit_pulls_api,
            "merge-commit subject must resolve without a commits-to-pulls call"
        );
    }

    #[test]
    fn no_pr_found_is_logged_not_a_crash() {
        let server = spawn_fake_github(|_, path, _| {
            if path.contains("access_tokens") {
                token_resp()
            } else if path.ends_with("/pulls") {
                (200, "[]".to_string())
            } else {
                (404, "{}".to_string())
            }
        });
        let app = client(&server);
        let commits = vec![MergedCommit {
            sha: "nopr".to_string(),
            subject: "direct push, no PR".to_string(),
        }];
        let outcome = RecompileOutcome {
            ok: true,
            recompiled: vec![],
            upgraded_instances: 0,
            failures: vec![],
        };
        let results = report_recompile(
            &app, "LoomMud", "loom", "staging", "cafef00d", &commits, &outcome,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn comment_body_success_lists_recompiled_programs_and_instance_count() {
        let outcome = RecompileOutcome {
            ok: true,
            recompiled: vec!["/domains/x/y.c".to_string()],
            upgraded_instances: 3,
            failures: vec![],
        };
        let body = comment_body("staging", "cafef00d", &outcome);
        assert!(body.contains("staging"));
        assert!(body.contains("cafef00d"));
        assert!(body.contains("/domains/x/y.c"));
        assert!(body.contains("3 live instance(s)"));
        assert!(body.contains("next access"));
        assert!(!body.contains("all-or-nothing"));
        // OBI-89: install is lazy, never claim a synchronous upgrade.
        assert!(!body.contains("live-upgraded"));
    }

    #[test]
    fn comment_body_failure_says_old_versions_kept_running() {
        let outcome = RecompileOutcome {
            ok: false,
            recompiled: vec!["/domains/x/y.c".to_string()],
            upgraded_instances: 0,
            failures: vec![("/domains/x/z.c".to_string(), "parse error".to_string())],
        };
        let body = comment_body("prod", "f00dcafe", &outcome);
        assert!(body.contains("all-or-nothing"));
        assert!(body.contains("still running"));
        assert!(body.contains("/domains/x/z.c"));
        assert!(body.contains("parse error"));
    }

    #[test]
    fn comment_body_failure_text_with_backticks_and_newlines_is_fenced_safely() {
        let outcome = RecompileOutcome {
            ok: false,
            recompiled: vec![],
            upgraded_instances: 0,
            failures: vec![(
                "/domains/x/z.c".to_string(),
                "unexpected `}`\nat line 4 <eof>".to_string(),
            )],
        };
        let body = comment_body("prod", "f00dcafe", &outcome);
        assert!(body.contains("<pre>"));
        assert!(body.contains("unexpected `}`"));
        // `<eof>` must be escaped, never passed through as raw HTML.
        assert!(body.contains("&lt;eof&gt;"));
        assert!(!body.contains("<eof>"));
    }

    #[test]
    fn comment_body_truncates_long_failure_lists() {
        let failures: Vec<(String, String)> = (0..60)
            .map(|i| (format!("/domains/x/{i}.c"), "err".to_string()))
            .collect();
        let outcome = RecompileOutcome {
            ok: false,
            recompiled: vec![],
            upgraded_instances: 0,
            failures,
        };
        let body = comment_body("prod", "f00dcafe", &outcome);
        assert!(body.contains("... and 10 more"));
    }

    #[test]
    fn report_recompile_posts_one_comment_per_unique_pr() {
        let server = spawn_fake_github(|method, path, _| {
            if path.contains("access_tokens") {
                token_resp()
            } else if method == "POST" && path.contains("/issues/") && path.ends_with("/comments") {
                (201, "{}".to_string())
            } else {
                (404, "{}".to_string())
            }
        });
        let app = client(&server);
        let commits = vec![
            MergedCommit {
                sha: "sha1".to_string(),
                subject: "feature (#10)".to_string(),
            },
            // Second commit in the same squash-merged PR (shouldn't
            // happen with squash merges in practice, but a rebase-merge
            // can land several commits for one PR) -- must still only
            // produce one comment.
            MergedCommit {
                sha: "sha2".to_string(),
                subject: "feature follow-up (#10)".to_string(),
            },
        ];
        let outcome = RecompileOutcome {
            ok: true,
            recompiled: vec!["/domains/x/y.c".to_string()],
            upgraded_instances: 1,
            failures: vec![],
        };
        let results = report_recompile(
            &app, "LoomMud", "loom", "staging", "cafef00d", &commits, &outcome,
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 10);
        assert!(results[0].1.is_ok());
        let comment_calls = server
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p.contains("/issues/10/comments"))
            .count();
        assert_eq!(comment_calls, 1);
    }

    #[test]
    fn report_recompile_comment_failure_is_surfaced_not_panicked() {
        let server = spawn_fake_github(|_, path, _| {
            if path.contains("access_tokens") {
                token_resp()
            } else {
                (404, r#"{"message":"Not Found"}"#.to_string())
            }
        });
        let app = client(&server);
        let commits = vec![MergedCommit {
            sha: "sha1".to_string(),
            subject: "feature (#55)".to_string(),
        }];
        let outcome = RecompileOutcome::default();
        let results = report_recompile(
            &app, "LoomMud", "loom", "staging", "cafef00d", &commits, &outcome,
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 55);
        assert!(results[0].1.is_err());
    }

    #[test]
    fn comment_body_shape_includes_both_pieces_for_default_outcome() {
        // RecompileOutcome::default() has `ok: false` -- make sure that
        // doesn't panic or produce an empty body even with nothing to
        // report.
        let outcome = RecompileOutcome::default();
        let body = comment_body("staging", "0000000", &outcome);
        assert!(body.contains("all-or-nothing"));
    }

    #[test]
    fn huge_moved_range_skips_all_comments() {
        let server = spawn_fake_github(|_, path, _| {
            if path.contains("access_tokens") {
                token_resp()
            } else {
                panic!(
                    "unexpected call to {path}: huge range must short-circuit before any API call"
                );
            }
        });
        let app = client(&server);
        let commits: Vec<MergedCommit> = (0..(MAX_MERGED_COMMITS + 1))
            .map(|i| MergedCommit {
                sha: format!("sha{i}"),
                subject: format!("commit {i}, no marker"),
            })
            .collect();
        let outcome = RecompileOutcome::default();
        let results = report_recompile(
            &app, "LoomMud", "loom", "staging", "cafef00d", &commits, &outcome,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn unique_pr_cap_stops_commenting_past_the_limit() {
        let server = spawn_fake_github(|_, path, _| {
            if path.contains("access_tokens") {
                token_resp()
            } else if path.contains("/issues/") && path.ends_with("/comments") {
                (201, "{}".to_string())
            } else {
                (404, "{}".to_string())
            }
        });
        let app = client(&server);
        // One more unique PR than the cap allows.
        let commits: Vec<MergedCommit> = (0..(MAX_UNIQUE_PRS + 1))
            .map(|i| MergedCommit {
                sha: format!("sha{i}"),
                subject: format!("feature {i} (#{i})"),
            })
            .collect();
        let outcome = RecompileOutcome::default();
        let results = report_recompile(
            &app, "LoomMud", "loom", "staging", "cafef00d", &commits, &outcome,
        );
        assert_eq!(results.len(), MAX_UNIQUE_PRS);
    }
}
