// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! JWT access-token claims and the tier -> scopes mapping (OBI-174).

use serde::{Deserialize, Serialize};

/// Claims carried by a signed access token. `tier`/`scopes` are a snapshot
/// taken at issue/refresh time from Postgres -- never trust a client-
/// supplied or stale copy of either for an authorization decision that
/// matters; re-derive from [`crate::auth::StaffDirectory::tier_of`] instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessClaims {
    /// The staff uid (design §5.11.3), never an account username.
    pub sub: String,
    pub tier: i16,
    pub scopes: Vec<String>,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// Expiry, Unix seconds.
    pub exp: i64,
}

/// Derive the scope set an access token gets for `tier` (design §9).
/// Deliberately additive/cumulative -- a higher tier keeps every scope of
/// every tier below it -- and deliberately conservative: this is a first
/// cut for Phase 2, to be refined with the CTO as the web IDE's actual
/// endpoints get scope-gated (see the OBI-174 PR description).
/// Claims for a short-lived, single-purpose token identifying a GitHub
/// numeric user id that OAuth already resolved but which still needs a
/// TOTP code to finish signing in (OBI-201, M-AUTH-7: "GitHub counts as
/// the password factor only"). Carries `github_id`, not a staff uid --
/// [`crate::auth::AuthService::github_login`] re-resolves the link fresh
/// when this is redeemed, the same as the original OAuth callback would
/// have, rather than trusting a uid baked into an earlier token (a link
/// could be revoked in between). Deliberately **not** [`AccessClaims`]
/// with placeholder tier/scopes -- a field-shape collision would let a
/// pending token decode as (or be confused with) a real access token.
/// `purpose` is checked on decode as a second guard even though the field
/// shapes already differ (`AccessClaims` has no `purpose`, this has no
/// `tier`/`scopes`, so cross-decoding fails on missing fields regardless).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubPendingClaims {
    pub github_id: i64,
    pub purpose: String,
    pub iat: i64,
    pub exp: i64,
}

/// The only valid [`GithubPendingClaims::purpose`] value. Checked on
/// decode, not just set on encode.
pub const GITHUB_PENDING_PURPOSE: &str = "github_totp_pending";

pub fn scopes_for_tier(tier: i16) -> Vec<String> {
    let mut scopes = Vec::new();
    if tier >= 1 {
        scopes.push("builder".to_string());
    }
    if tier >= 2 {
        scopes.push("domain:write".to_string());
    }
    if tier >= 3 {
        scopes.push("domain:lead".to_string());
        scopes.push("admin:limited".to_string());
    }
    if tier >= 4 {
        scopes.push("admin:arch".to_string());
    }
    if tier >= 5 {
        scopes.push("admin:root".to_string());
    }
    scopes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_cumulative() {
        assert_eq!(scopes_for_tier(0), Vec::<String>::new());
        assert_eq!(scopes_for_tier(1), vec!["builder"]);
        assert_eq!(scopes_for_tier(2), vec!["builder", "domain:write"]);
        let t3 = scopes_for_tier(3);
        assert!(t3.contains(&"domain:lead".to_string()));
        assert!(t3.contains(&"admin:limited".to_string()));
        assert!(t3.contains(&"builder".to_string()));
        let t5 = scopes_for_tier(5);
        assert!(t5.contains(&"admin:root".to_string()));
        assert!(t5.contains(&"admin:arch".to_string()));
    }
}
