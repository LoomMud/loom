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
