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
    use crate::github::fake_http;
    use crate::github::fake_server;
    use std::sync::{Arc, Mutex};

    // Shared throwaway test fixture (see `jwt`'s test module docs): not a
    // real GitHub App key, just something `load_private_key` accepts.
    fn test_pem() -> String {
        include_str!("testdata/test_key.pkcs8.pem").to_string()
    }

    /// The fake GitHub this crate's PR tests talk to: `fake_server`'s
    /// per-connection fake (OBI-351), answering the installation-token mint on
    /// `/app/installations/...` and the PR create on `/repos/.../pulls`, and
    /// recording `<path>\n<body>` for every request it served.
    struct FakeGitHub {
        server: fake_server::FakeHttpServer,
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl FakeGitHub {
        fn api_base(&self) -> String {
            self.server.api_base()
        }

        fn seen(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }

        /// Assert the fake answered every connection it accepted, so a red
        /// assertion below can only mean a product bug (OBI-351).
        fn assert_healthy(&self) {
            self.server.assert_healthy();
        }
    }

    fn spawn_fake_github() -> FakeGitHub {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_in_handler = seen.clone();
        let server = fake_server::FakeHttpServer::spawn(
            move |_call: usize, request: fake_http::FakeRequest| {
                seen_in_handler
                    .lock()
                    .unwrap()
                    .push(format!("{}\n{}", request.path, request.body));
                let resp_body = if request.path.contains("access_tokens") {
                    r#"{"token":"ghs_abc","expires_at":"2099-01-01T00:00:00Z"}"#.to_string()
                } else {
                    r#"{"number":42,"html_url":"https://github.com/LoomMud/warp/pull/42"}"#
                        .to_string()
                };
                (201, resp_body)
            },
        );
        FakeGitHub { server, seen }
    }

    #[test]
    fn opens_pull_request_against_main() {
        let server = spawn_fake_github();
        let app = GitHubAppClient::new("1", "2", &test_pem(), fake_server::test_transport())
            .unwrap()
            .with_api_base(server.api_base());
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
        let seen = server.seen();
        let pulls_req = seen
            .iter()
            .find(|r| r.contains("/repos/LoomMud/warp/pulls"))
            .expect("expected a pulls request");
        assert!(pulls_req.contains("\"head\":\"propose/glorfindel/20260101-fix\""));
        assert!(pulls_req.contains("\"base\":\"main\""));
        assert!(pulls_req.contains("\"title\":\"Fix the thing\""));
        server.assert_healthy();
    }

    #[test]
    fn non_2xx_pull_create_is_a_clear_error() {
        let server =
            fake_server::FakeHttpServer::spawn(|_call: usize, request: fake_http::FakeRequest| {
                let (status, body) = if request.path.contains("access_tokens") {
                    (
                        201,
                        r#"{"token":"ghs_abc","expires_at":"2099-01-01T00:00:00Z"}"#.to_string(),
                    )
                } else {
                    (422, r#"{"message":"Validation Failed"}"#.to_string())
                };
                (status, body)
            });
        let app = GitHubAppClient::new("1", "2", &test_pem(), fake_server::test_transport())
            .unwrap()
            .with_api_base(server.api_base());
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
        // A `422` is an answer. Whatever else this test concludes, it must not
        // have been handed a closed socket dressed up as a parse failure.
        server.assert_healthy();
    }
}
