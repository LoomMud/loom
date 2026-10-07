// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! PR comments and the commits-to-pulls fallback (B3.3 slice 4, OBI-213,
//! design doc D-B3.13/D-B3.14). GitHub treats a pull request as an issue
//! for the comment endpoint, so `POST
//! /repos/{owner}/{repo}/issues/{number}/comments` is also how you
//! comment on a PR; `pull_requests:write` (already granted to the
//! `loom-warp-propose` App, see [`super::GitHubAppClient`]'s module docs)
//! covers it.

use serde::Deserialize;

use super::transport::HttpClient;
use super::{GitHubAppClient, GitHubAppError, truncate_body};

/// One element of `GET /repos/{owner}/{repo}/commits/{sha}/pulls`'s
/// response array. GitHub documents more fields; this crate only needs
/// the number.
#[derive(Debug, Clone, Deserialize)]
pub struct PullRef {
    pub number: u64,
}

impl<C: HttpClient> GitHubAppClient<C> {
    /// `GET /repos/{owner}/{repo}/commits/{sha}/pulls`: the fallback for
    /// commits whose subject never carried a squash-merge `(#N)` (a
    /// rebase-merge or a merge commit, say). Returns every PR GitHub
    /// associates with `sha`, most-recently-merged first per GitHub's own
    /// ordering; callers that want "the" PR take the first element.
    pub fn commit_pulls(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> Result<Vec<PullRef>, GitHubAppError> {
        let token = self.installation_token()?;
        let url = format!("{}/repos/{owner}/{repo}/commits/{sha}/pulls", self.api_base);
        let resp = self
            .transport
            .get(&url, &token)
            .map_err(|e| GitHubAppError::Transport(e.0))?;
        if !(200..300).contains(&resp.status) {
            return Err(GitHubAppError::Api {
                status: resp.status,
                body: truncate_body(&resp.body),
            });
        }
        serde_json::from_slice(&resp.body).map_err(|e| GitHubAppError::BadResponse(e.to_string()))
    }

    /// `POST /repos/{owner}/{repo}/issues/{number}/comments`: post `body`
    /// as a new comment on PR (or issue) `number`.
    pub fn create_issue_comment(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        body: &str,
    ) -> Result<(), GitHubAppError> {
        let token = self.installation_token()?;
        let url = format!(
            "{}/repos/{owner}/{repo}/issues/{number}/comments",
            self.api_base
        );
        let payload = serde_json::json!({ "body": body });
        let bytes =
            serde_json::to_vec(&payload).map_err(|e| GitHubAppError::BadResponse(e.to_string()))?;
        let resp = self
            .transport
            .post(&url, &token, &bytes)
            .map_err(|e| GitHubAppError::Transport(e.0))?;
        if !(200..300).contains(&resp.status) {
            return Err(GitHubAppError::Api {
                status: resp.status,
                body: truncate_body(&resp.body),
            });
        }
        Ok(())
    }
}
