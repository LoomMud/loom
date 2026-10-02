// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The GitHub side of "optional GitHub OIDC login" (OBI-174). GitHub's
//! OAuth app flow does not actually issue an OIDC `id_token`; the
//! equivalent in practice is exchanging the authorization code for an
//! access token, then calling GitHub's REST `/user` endpoint for the
//! numeric, immutable user id (GitHub logins can be renamed; the id
//! cannot, which is why `github_identities.github_id` -- not the login --
//! is the stable key).
//!
//! [`GithubIdentityProvider`] abstracts that exchange so
//! [`crate::auth::AuthService::github_login`] and its tests never need a
//! live GitHub app/network: tests use a fake
//! ([`fake::FakeGithubProvider`]). A real, network-backed implementation
//! is deliberately **not** included in this PR -- it needs an actual
//! GitHub OAuth app plus a staging secret to exercise end to end, and
//! staging access is gated behind its own governance ticket (see the
//! OBI-174 PR description for the follow-up that wires it in, and the
//! `GithubIdentityProvider` trait boundary this PR establishes so that
//! follow-up is additive, not a redesign).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GithubUser {
    pub id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GithubAuthError {
    /// The authorization code was rejected, expired, or already used.
    InvalidCode,
    /// The network/API call itself failed.
    Unavailable,
}

#[async_trait::async_trait]
pub trait GithubIdentityProvider: Send + Sync {
    /// Exchange an OAuth authorization code for the GitHub user it belongs
    /// to. Implementations must not themselves decide whether that user is
    /// linked to a staff uid -- that is `github_identities`' job, done by
    /// [`crate::auth::AuthService::github_login`] after this returns.
    async fn exchange_code(&self, code: &str) -> Result<GithubUser, GithubAuthError>;
}

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A fake [`GithubIdentityProvider`] for tests: maps a fixed set of
    /// authorization codes to GitHub user ids, with no network involved.
    #[derive(Default)]
    pub struct FakeGithubProvider {
        codes: Mutex<HashMap<String, i64>>,
    }

    impl FakeGithubProvider {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn with_code(self, code: &str, github_id: i64) -> Self {
            self.codes
                .lock()
                .unwrap()
                .insert(code.to_string(), github_id);
            self
        }
    }

    #[async_trait::async_trait]
    impl GithubIdentityProvider for FakeGithubProvider {
        async fn exchange_code(&self, code: &str) -> Result<GithubUser, GithubAuthError> {
            match self.codes.lock().unwrap().get(code) {
                Some(&id) => Ok(GithubUser { id }),
                None => Err(GithubAuthError::InvalidCode),
            }
        }
    }
}
