// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! JWT access-token claims and the tier -> scopes mapping (OBI-174).

use serde::{Deserialize, Serialize};

/// `aud` value for a normal access token (full session, tier/scopes
/// populated). See [`ENROL_AUDIENCE`] for the narrower bootstrap-enrolment
/// credential (OBI-199).
pub const ACCESS_AUDIENCE: &str = "loom-staff-access";

/// `aud` value for the T3+ first-enrolment credential (OBI-199,
/// M-AUTH-3): issued only when a T3+ staff member authenticates
/// correctly (username+password) but has no confirmed TOTP secret yet, so
/// cannot obtain (and does not need) a real access token. Usable only on
/// `/auth/totp/enroll` and `/auth/totp/verify` -- every other handler
/// checks `aud == ACCESS_AUDIENCE` and refuses this outright, and its
/// `tier`/`scopes` are always empty so even a handler that forgot the
/// `aud` check would find nothing to authorize.
pub const ENROL_AUDIENCE: &str = "loom-staff-enrol";

/// Claims carried by a signed access/enrolment token. `tier`/`scopes` are
/// a snapshot taken at issue/refresh time from Postgres -- never trust a
/// client- supplied or stale copy of either for an authorization decision
/// that matters; re-derive from [`crate::auth::StaffDirectory::tier_of`]
/// instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessClaims {
    /// The staff uid (design §5.11.3), never an account username.
    pub sub: String,
    /// [`ACCESS_AUDIENCE`] for a normal session, [`ENROL_AUDIENCE`] for the
    /// narrow T3+ bootstrap-enrolment credential (OBI-199).
    #[serde(default = "default_audience")]
    pub aud: String,
    pub tier: i16,
    pub scopes: Vec<String>,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// Expiry, Unix seconds.
    pub exp: i64,
}

fn default_audience() -> String {
    ACCESS_AUDIENCE.to_string()
}

impl AccessClaims {
    pub fn is_enrolment_only(&self) -> bool {
        self.aud == ENROL_AUDIENCE
    }
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
