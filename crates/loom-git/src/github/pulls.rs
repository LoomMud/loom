// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The PR-create REST call (P2-B3.3, design doc §4 `propose`): opens a
//! pull request against `warp`'s `main` from a `propose/<uid>/<stamp>-
//! <slug>` branch, via the dedicated `loom-propose` GitHub App
//! (`GitHubAppClient`, OBI-191 slice 1). This is the only GitHub REST
//! call `propose` needs beyond the installation-token exchange that
//! already lives in `super`.

use serde::{Deserialize, Serialize};

use super::{GitHubAppClient, GitHubAppError, HttpClient};

#[derive(Debug, Clone, Serialize)]
struct CreatePullRequestBody<'a> {
    title: &'a str,
    head: &'a str,
    base: &'a str,
    body: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PullRequest {
    pub number: u64,
    pub html_url: String,
}

/// What `propose` needs from a GitHub client: mint a token, then open a
/// PR. A trait (rather than calling `GitHubAppClient` directly) so the
/// `GitWorker`/`propose` job logic does not need to carry the client's
/// `HttpClient` type parameter around, and so tests can substitute a
/// fake that never hits the network.
pub trait PullRequestOpener: Send + Sync {
    fn open_pull_request(
        &self,
        owner: &str,
        repo: &str,
        head: &str,
        base: &str,
        title: &str,
        body: &str,
    ) -> Result<PullRequest, GitHubAppError>;
}

impl<C: HttpClient> GitHubAppClient<C> {
    /// `POST /repos/{owner}/{repo}/pulls` (installation token, D-B3.9).
    pub fn create_pull_request(
        &self,
        owner: &str,
        repo: &str,
        head: &str,
        base: &str,
        title: &str,
        body: &str,
    ) -> Result<PullRequest, GitHubAppError> {
        let token = self.installation_token()?;
        let url = format!("{}/repos/{owner}/{repo}/pulls", self.api_base());
        let payload = CreatePullRequestBody {
            title,
            head,
            base,
            body,
        };
        let bytes = serde_json::to_vec(&payload)
            .map_err(|e| GitHubAppError::BadResponse(format!("encoding request: {e}")))?;
        let resp = self
            .transport()
            .post(&url, &token, &bytes)
            .map_err(|e| GitHubAppError::Transport(e.0))?;
        if !(200..300).contains(&resp.status) {
            return Err(GitHubAppError::Api {
                status: resp.status,
                body: super::truncate_body(&resp.body),
            });
        }
        serde_json::from_slice(&resp.body).map_err(|e| GitHubAppError::BadResponse(e.to_string()))
    }
}

impl<C: HttpClient> PullRequestOpener for GitHubAppClient<C> {
    fn open_pull_request(
        &self,
        owner: &str,
        repo: &str,
        head: &str,
        base: &str,
        title: &str,
        body: &str,
    ) -> Result<PullRequest, GitHubAppError> {
        self.create_pull_request(owner, repo, head, base, title, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::UreqClient;
    use crate::github::fake_http;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    // Shared throwaway test fixture (see `jwt`'s test module docs): not a
    // real GitHub App key, just something `load_private_key` accepts.
    fn test_pem() -> String {
        include_str!("testdata/test_key.pkcs8.pem").to_string()
    }

    /// Spawns a fake GitHub server that answers the installation-token
    /// mint on `/app/installations/...` and the PR-create call on
    /// `/repos/.../pulls`, recording the request bodies it sees.
    ///
    /// Requests are read and closed through [`fake_http`], the same
    /// complete-request path every other loopback GitHub server in this
    /// crate uses (OBI-350).
    fn spawn_fake_github() -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_clone = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let Some(req) = fake_http::read_request(&mut stream) else {
                    continue;
                };
                seen_clone
                    .lock()
                    .unwrap()
                    .push(format!("{}\n{}", req.path, req.body));
                let resp_body = if req.path.contains("access_tokens") {
                    r#"{"token":"ghs_abc","expires_at":"2099-01-01T00:00:00Z"}"#.to_string()
                } else {
                    r#"{"number":42,"html_url":"https://github.com/LoomMud/warp/pull/42"}"#
                        .to_string()
                };
                fake_http::respond(&mut stream, 201, &resp_body);
            }
        });
        (addr, seen)
    }

    #[test]
    fn opens_pull_request_against_main() {
        let (addr, seen) = spawn_fake_github();
        let app = GitHubAppClient::new("1", "2", &test_pem(), UreqClient::default())
            .unwrap()
            .with_api_base(format!("http://{addr}"));
        let pr = app
            .create_pull_request(
                "LoomMud",
                "warp",
                "propose/glorfindel/20260101-fix",
                "main",
                "Fix the thing",
                "PR body",
            )
            .unwrap();
        assert_eq!(pr.number, 42);
        assert_eq!(pr.html_url, "https://github.com/LoomMud/warp/pull/42");
        let seen = seen.lock().unwrap();
        let pulls_req = seen
            .iter()
            .find(|r| r.contains("/repos/LoomMud/warp/pulls"))
            .expect("expected a pulls request");
        assert!(pulls_req.contains("\"head\":\"propose/glorfindel/20260101-fix\""));
        assert!(pulls_req.contains("\"base\":\"main\""));
        assert!(pulls_req.contains("\"title\":\"Fix the thing\""));
    }

    #[test]
    fn non_2xx_pull_create_is_a_clear_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let Some(req) = fake_http::read_request(&mut stream) else {
                    continue;
                };
                let (status, body) = if req.path.contains("access_tokens") {
                    (
                        201,
                        r#"{"token":"ghs_abc","expires_at":"2099-01-01T00:00:00Z"}"#.to_string(),
                    )
                } else {
                    (422, r#"{"message":"Validation Failed"}"#.to_string())
                };
                fake_http::respond(&mut stream, status, &body);
            }
        });
        let app = GitHubAppClient::new("1", "2", &test_pem(), UreqClient::default())
            .unwrap()
            .with_api_base(format!("http://{addr}"));
        let err = app
            .create_pull_request("LoomMud", "warp", "propose/x/y", "main", "t", "b")
            .unwrap_err();
        match err {
            GitHubAppError::Api { status, body } => {
                assert_eq!(status, 422);
                assert!(body.contains("Validation Failed"));
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }
}
