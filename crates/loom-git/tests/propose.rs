// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `propose` (P2-B3.3, OBI-211) acceptance tests: happy path, mapping
//! rewrite + count, authz denials, each of the four limits, and the
//! no-App error path -- against the same loopback fake GitHub server
//! pattern as `github::pulls`'s unit tests (OBI-191 slice 1, PR #84).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use loom_git::{
    AllowAllAuthorizer, GitConfig, GitHubAppClient, GitWorker, Identity, NoopAudit,
    ProposeAuthorizer, ProposeConfig, ProposeError, ProposeGitHubConfig, ProposeLimits,
    ProposeQuota, ProposeRequest, PullRequest, PullRequestOpener, RecompileHost, RecompileOutcome,
    TokenProvider, UreqClient,
};

struct NoopHost;
impl RecompileHost for NoopHost {
    fn recompile_set(&self, changed: Vec<String>, _deleted: Vec<String>) -> RecompileOutcome {
        RecompileOutcome {
            ok: true,
            recompiled: changed,
            failures: Vec::new(),
        }
    }
}

// --- Fixture: a local bare remote + driver git dir/work tree, same
// shape as `tests/integration.rs`'s `setup()`. ---

struct Fixture {
    // Keeps the tempdir alive for the fixture's lifetime; never read
    // directly.
    #[allow(dead_code)]
    tmp: tempfile::TempDir,
    bare: std::path::PathBuf,
    git_dir: std::path::PathBuf,
    work_tree: std::path::PathBuf,
}

fn git_in(
    git_dir: &std::path::Path,
    work_tree: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
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

fn setup() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bare = tmp.path().join("warp-bare.git");
    let git_dir = tmp.path().join("warp.git");
    let work_tree = tmp.path().join("mudlib");
    std::fs::create_dir_all(&work_tree).unwrap();

    let init_bare = Command::new("git")
        .args([
            "init",
            "--quiet",
            "--bare",
            "-b",
            "main",
            &bare.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(init_bare.status.success());

    let out = Command::new("git")
        .env("GIT_DIR", &git_dir)
        .env("GIT_WORK_TREE", &work_tree)
        .args(["init", "--quiet", "-b", "main"])
        .output()
        .expect("git init");
    assert!(out.status.success());

    std::fs::create_dir_all(work_tree.join("domains/x")).unwrap();
    std::fs::create_dir_all(work_tree.join("protected")).unwrap();
    std::fs::create_dir_all(work_tree.join("domain_live")).unwrap();
    std::fs::write(
        work_tree.join("domains/x/a.wf"),
        "inherit \"/domains/x/base\";\nobject a;\n",
    )
    .unwrap();
    std::fs::write(work_tree.join("domains/x/b.wf"), "object b;\n").unwrap();
    std::fs::write(work_tree.join("protected/secret.wf"), "object secret;\n").unwrap();
    std::fs::write(work_tree.join("domain_live/room.wf"), "object room;\n").unwrap();

    git_in(&git_dir, &work_tree, &["add", "-A"]);
    let mut commit = Command::new("git");
    commit
        .arg("--git-dir")
        .arg(&git_dir)
        .arg("--work-tree")
        .arg(&work_tree)
        .args(["commit", "-m", "seed"])
        .env("GIT_AUTHOR_NAME", "seed")
        .env("GIT_AUTHOR_EMAIL", "seed@loommud.com")
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

// --- A fake GitHub server serving both the installation-token mint and
// the PR-create call, robust to headers/body arriving across multiple
// reads (see `github::pulls`'s unit tests for the same fix). ---

struct FakeGitHub {
    addr: String,
    pull_requests: Arc<Mutex<Vec<String>>>,
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

fn spawn_fake_github() -> FakeGitHub {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let pull_requests = Arc::new(Mutex::new(Vec::new()));
    let prs = pull_requests.clone();
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
            } else if path.contains("/pulls") {
                prs.lock().unwrap().push(body.to_string());
                (
                    201,
                    r#"{"number":7,"html_url":"https://github.com/LoomMud/warp/pull/7"}"#
                        .to_string(),
                )
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
        pull_requests,
    }
}

struct TokenAdapter(Arc<GitHubAppClient<UreqClient>>);
impl TokenProvider for TokenAdapter {
    fn token(&self) -> Result<String, String> {
        self.0.token()
    }
}
struct PrAdapter(Arc<GitHubAppClient<UreqClient>>);
impl PullRequestOpener for PrAdapter {
    fn open_pull_request(
        &self,
        owner: &str,
        repo: &str,
        head: &str,
        base: &str,
        title: &str,
        body: &str,
    ) -> Result<PullRequest, loom_git::GitHubAppError> {
        self.0
            .open_pull_request(owner, repo, head, base, title, body)
    }
}

fn test_pem() -> String {
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;
    let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    key.to_pkcs8_pem(Default::default()).unwrap().to_string()
}

fn github_client(server: &FakeGitHub) -> Arc<GitHubAppClient<UreqClient>> {
    Arc::new(
        GitHubAppClient::new("1", "2", &test_pem(), UreqClient::default())
            .unwrap()
            .with_api_base(format!("http://{}", server.addr)),
    )
}

/// Denies proposing into `/protected/...` for tier `T2` and into
/// `/domain_live/...` for tier `T1` (OBI-211 acceptance: "T2 -> protected,
/// T1 -> domain_live"); everything else, and every `valid_read`, passes.
struct TierGatedAuthorizer;
impl ProposeAuthorizer for TierGatedAuthorizer {
    fn valid_propose(&self, _uid: &str, tier: &str, target_path: &str) -> bool {
        if tier == "T2" && target_path.contains("/protected/") {
            return false;
        }
        if tier == "T1" && target_path.contains("/domain_live/") {
            return false;
        }
        true
    }
    fn valid_read(&self, _uid: &str, _tier: &str, _source_path: &str) -> bool {
        true
    }
}

struct FixedQuota {
    open: usize,
    today: usize,
}
impl ProposeQuota for FixedQuota {
    fn open_count(&self, _uid: &str) -> usize {
        self.open
    }
    fn today_count(&self, _uid: &str) -> usize {
        self.today
    }
    fn record(&self, _uid: &str, _now: std::time::SystemTime) {}
}

fn default_config(fx: &Fixture, env: &str) -> GitConfig {
    let mut config = GitConfig::new(fx.git_dir.clone(), fx.work_tree.clone(), "origin", env);
    config.commit_coalesce = Duration::from_millis(10);
    config.push_debounce = Duration::from_millis(10);
    config.sync_poll = Duration::from_secs(3600);
    config.tick = Duration::from_millis(10);
    config
}

fn base_request(paths: Vec<&str>) -> ProposeRequest {
    ProposeRequest {
        uid: "glorfindel".to_string(),
        tier: "T3".to_string(),
        identity: Identity::for_uid("glorfindel", None),
        paths: paths.into_iter().map(|s| s.to_string()).collect(),
        target_prefix: None,
        title: "Fix the thing".to_string(),
        body: "Some description of the change.".to_string(),
    }
}

#[test]
fn happy_path_opens_a_pr_with_expected_branch_and_body_shape() {
    let fx = setup();
    let server = spawn_fake_github();
    let client = github_client(&server);

    let handle = GitWorker::spawn_with_propose(
        default_config(&fx, "test"),
        Some(Box::new(TokenAdapter(client.clone()))),
        Box::new(NoopHost),
        Box::new(NoopAudit),
        ProposeConfig {
            authorizer: Box::new(AllowAllAuthorizer),
            quota: Box::new(loom_git::InMemoryQuota::new()),
            limits: ProposeLimits::default(),
            github: Some(ProposeGitHubConfig {
                pr_opener: Box::new(PrAdapter(client.clone())),
                owner: "LoomMud".to_string(),
                repo: "warp".to_string(),
            }),
        },
    );

    let result = handle
        .propose(base_request(vec!["/domains/x/a.wf"]))
        .expect("propose should succeed");

    assert_eq!(result.pr_number, 7);
    assert_eq!(result.pr_url, "https://github.com/LoomMud/warp/pull/7");
    assert_eq!(result.files, 1);
    assert!(
        result.branch.starts_with("propose/glorfindel/"),
        "branch was {}",
        result.branch
    );
    assert!(result.branch.ends_with("-fix-the-thing"));

    // The branch landed on the remote with the right author/DCO trailer.
    let log = Command::new("git")
        .args([
            "--git-dir",
            &fx.bare.to_string_lossy(),
            "log",
            "-1",
            "--format=%an <%ae>%n%(trailers:key=Signed-off-by,valueonly)",
            &format!("refs/heads/{}", result.branch),
        ])
        .output()
        .unwrap();
    assert!(log.status.success());
    let text = String::from_utf8_lossy(&log.stdout);
    let mut lines = text.lines();
    let author = lines.next().unwrap();
    assert_eq!(author, "glorfindel <glorfindel@users.loommud.com>");
    let trailer = lines.next().unwrap_or("");
    assert!(trailer.contains(author), "trailer {trailer:?}");

    // PR body shape (design doc §4): proposer, tier, env, source paths,
    // source live SHA, reviewer checklist.
    let bodies = server.pull_requests.lock().unwrap();
    let body = bodies.last().expect("expected a pulls request");
    assert!(body.contains("glorfindel"));
    assert!(body.contains("T3"));
    assert!(body.contains("test"));
    assert!(body.contains("/domains/x/a.wf"));
    assert!(body.contains("Reviewer checklist"));

    handle.shutdown();
}

#[test]
fn mapping_rewrites_paths_and_counts_content_rewrites() {
    let fx = setup();
    let server = spawn_fake_github();
    let client = github_client(&server);

    let handle = GitWorker::spawn_with_propose(
        default_config(&fx, "test"),
        Some(Box::new(TokenAdapter(client.clone()))),
        Box::new(NoopHost),
        Box::new(NoopAudit),
        ProposeConfig {
            authorizer: Box::new(AllowAllAuthorizer),
            quota: Box::new(loom_git::InMemoryQuota::new()),
            limits: ProposeLimits::default(),
            github: Some(ProposeGitHubConfig {
                pr_opener: Box::new(PrAdapter(client.clone())),
                owner: "LoomMud".to_string(),
                repo: "warp".to_string(),
            }),
        },
    );

    let mut req = base_request(vec!["/domains/x"]);
    req.target_prefix = Some("/domains/y".to_string());
    let result = handle.propose(req).expect("propose should succeed");

    // a.wf contains one literal "/domains/x/..." occurrence to rewrite.
    assert_eq!(result.rewrites, 1);
    assert_eq!(result.files, 2);

    let mapped = Command::new("git")
        .args([
            "--git-dir",
            &fx.bare.to_string_lossy(),
            "show",
            &format!("refs/heads/{}:domains/y/a.wf", result.branch),
        ])
        .output()
        .unwrap();
    assert!(mapped.status.success());
    let content = String::from_utf8_lossy(&mapped.stdout);
    assert!(content.contains("/domains/y/base"));
    assert!(!content.contains("/domains/x/"));

    handle.shutdown();
}

#[test]
fn t2_denied_proposing_into_protected() {
    let fx = setup();
    let handle = GitWorker::spawn_with_propose(
        default_config(&fx, "test"),
        None,
        Box::new(NoopHost),
        Box::new(NoopAudit),
        ProposeConfig {
            authorizer: Box::new(TierGatedAuthorizer),
            quota: Box::new(loom_git::InMemoryQuota::new()),
            limits: ProposeLimits::default(),
            github: None,
        },
    );
    let mut req = base_request(vec!["/protected/secret.wf"]);
    req.tier = "T2".to_string();
    let err = handle.propose(req).unwrap_err();
    match err {
        ProposeError::Denied { path, reason } => {
            assert!(path.contains("/protected/"));
            assert_eq!(reason, "valid_propose");
        }
        other => panic!("expected Denied, got {other:?}"),
    }
    handle.shutdown();
}

#[test]
fn t1_denied_proposing_into_domain_live() {
    let fx = setup();
    let handle = GitWorker::spawn_with_propose(
        default_config(&fx, "test"),
        None,
        Box::new(NoopHost),
        Box::new(NoopAudit),
        ProposeConfig {
            authorizer: Box::new(TierGatedAuthorizer),
            quota: Box::new(loom_git::InMemoryQuota::new()),
            limits: ProposeLimits::default(),
            github: None,
        },
    );
    let mut req = base_request(vec!["/domain_live/room.wf"]);
    req.tier = "T1".to_string();
    let err = handle.propose(req).unwrap_err();
    match err {
        ProposeError::Denied { path, reason } => {
            assert!(path.contains("/domain_live/"));
            assert_eq!(reason, "valid_propose");
        }
        other => panic!("expected Denied, got {other:?}"),
    }
    handle.shutdown();
}

#[test]
fn too_many_files_limit_is_enforced() {
    let fx = setup();
    let handle = GitWorker::spawn_with_propose(
        default_config(&fx, "test"),
        None,
        Box::new(NoopHost),
        Box::new(NoopAudit),
        ProposeConfig {
            authorizer: Box::new(AllowAllAuthorizer),
            quota: Box::new(loom_git::InMemoryQuota::new()),
            limits: ProposeLimits {
                max_files: 1,
                ..ProposeLimits::default()
            },
            github: None,
        },
    );
    // `/domains/x` expands to both a.wf and b.wf -- two files, over the
    // limit of one.
    let err = handle
        .propose(base_request(vec!["/domains/x"]))
        .unwrap_err();
    assert_eq!(err, ProposeError::TooManyFiles(2));
    handle.shutdown();
}

#[test]
fn too_large_limit_is_enforced() {
    let fx = setup();
    let handle = GitWorker::spawn_with_propose(
        default_config(&fx, "test"),
        None,
        Box::new(NoopHost),
        Box::new(NoopAudit),
        ProposeConfig {
            authorizer: Box::new(AllowAllAuthorizer),
            quota: Box::new(loom_git::InMemoryQuota::new()),
            limits: ProposeLimits {
                max_bytes: 4,
                ..ProposeLimits::default()
            },
            github: None,
        },
    );
    let err = handle
        .propose(base_request(vec!["/domains/x/b.wf"]))
        .unwrap_err();
    match err {
        ProposeError::TooLarge(n) => assert!(n > 4),
        other => panic!("expected TooLarge, got {other:?}"),
    }
    handle.shutdown();
}

#[test]
fn too_many_open_proposals_limit_is_enforced() {
    let fx = setup();
    let handle = GitWorker::spawn_with_propose(
        default_config(&fx, "test"),
        None,
        Box::new(NoopHost),
        Box::new(NoopAudit),
        ProposeConfig {
            authorizer: Box::new(AllowAllAuthorizer),
            quota: Box::new(FixedQuota { open: 5, today: 0 }),
            limits: ProposeLimits::default(),
            github: None,
        },
    );
    let err = handle
        .propose(base_request(vec!["/domains/x/a.wf"]))
        .unwrap_err();
    assert_eq!(err, ProposeError::TooManyOpenProposals(5));
    handle.shutdown();
}

#[test]
fn daily_limit_is_enforced() {
    let fx = setup();
    let handle = GitWorker::spawn_with_propose(
        default_config(&fx, "test"),
        None,
        Box::new(NoopHost),
        Box::new(NoopAudit),
        ProposeConfig {
            authorizer: Box::new(AllowAllAuthorizer),
            quota: Box::new(FixedQuota { open: 0, today: 20 }),
            limits: ProposeLimits::default(),
            github: None,
        },
    );
    let err = handle
        .propose(base_request(vec!["/domains/x/a.wf"]))
        .unwrap_err();
    assert_eq!(err, ProposeError::DailyLimitExceeded(20));
    handle.shutdown();
}

#[test]
fn no_github_app_configured_keeps_the_commit_locally_for_retry() {
    let fx = setup();
    let handle = GitWorker::spawn_with_propose(
        default_config(&fx, "test"),
        None,
        Box::new(NoopHost),
        Box::new(NoopAudit),
        ProposeConfig::disabled(),
    );
    let err = handle
        .propose(base_request(vec!["/domains/x/a.wf"]))
        .unwrap_err();
    assert_eq!(err, ProposeError::NoGitHubApp);

    // The commit is kept under `refs/loom/propose/...` for a later retry
    // (design doc §4 step 7), even though nothing was pushed.
    let refs = Command::new("git")
        .args([
            "--git-dir",
            &fx.git_dir.to_string_lossy(),
            "for-each-ref",
            "refs/loom/propose/glorfindel",
        ])
        .output()
        .unwrap();
    assert!(
        !refs.stdout.is_empty(),
        "expected a refs/loom/propose/glorfindel/<stamp>-<slug> keep-ref"
    );

    handle.shutdown();
}
