// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! D-TM4's single-use WebSocket ticket (`docs/threat-model-phase2.md`
//! §5, used by `/lsp`, OBI-180/OBI-168): `POST /api/v1/ws-ticket`
//! (Bearer) returns a 32-byte ticket valid for 30s and bound to
//! `sub`+`sid`. The client opens the WS and must send `{"auth":ticket}`
//! in the first frame.
//!
//! Signed with [`super::statetoken::StateTokenKey`] (the same
//! not-a-JWT HMAC domain the OAuth-state/pending-TOTP tokens use) --
//! deliberately not the staff access-token EdDSA keyset, for the same
//! reason OBI-298 split those off: a bug in this (new, WS-specific) path
//! must not be able to forge, or be confused with, a real access token.
//!
//! **Single-use**, unlike the OAuth-state token: a ticket's `nonce` is
//! recorded the first time it is redeemed, and a second redemption of the
//! same ticket is refused even though the signature and expiry both
//! still check out. Query access the query string never gets this token
//! at all (D-TM4's rejected alternative) -- it is carried in the first
//! WS frame, which is not in Caddy's/Cloudflare's URI-based access logs.

use std::collections::HashMap;
use std::sync::Mutex;

use rand::RngExt;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::statetoken::{HasExpiry, StateTokenError, StateTokenKey};

/// D-TM4: "valid for 30 s".
const TICKET_TTL_SECS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsTicketError {
    /// Malformed, unsigned, or expired.
    Invalid,
    /// Well-formed and unexpired, but this exact ticket was already
    /// redeemed once (D-TM4: single-use).
    AlreadyUsed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WsTicketClaims {
    sub: String,
    sid: String,
    /// Base64url-encoded random bytes -- the identity a redemption is
    /// recorded against, distinct from the ticket's signature bytes so
    /// [`WsTicketIssuer::redeem`] doesn't need to re-derive or store the
    /// whole token string.
    nonce: String,
    exp: i64,
}

impl HasExpiry for WsTicketClaims {
    fn expires_at(&self) -> i64 {
        self.exp
    }
}

/// A ticket successfully redeemed: the uid and token-family id it was
/// issued for (D-TM4: "bound to `sub`+`sid`").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsTicketIdentity {
    pub sub: String,
    pub sid: String,
}

/// Issues and redeems D-TM4 tickets. One instance lives for the process
/// lifetime (held by [`super::AuthService`]) -- like [`StateTokenKey`],
/// its signing key is generated fresh at startup and never persisted;
/// `used` is an in-memory set only, swept of anything whose 30s TTL has
/// passed, so this never grows unbounded and a restart just invalidates
/// tickets that were already in flight (same tradeoff as the OAuth-state
/// key, at a much shorter timescale).
pub struct WsTicketIssuer {
    key: StateTokenKey,
    used: Mutex<HashMap<String, i64>>,
}

impl WsTicketIssuer {
    pub fn new() -> Self {
        Self {
            key: StateTokenKey::generate(),
            used: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue(&self, sub: &str, sid: &str) -> Result<String, StateTokenError> {
        // CTO review of PR #122, should-fix: match this crate's other
        // random-identity nonces (refresh-token plaintext, GitHub OAuth
        // state, `generate_sid`) at 32 bytes / 256 bits, not a smaller
        // one-off size -- 16 bytes was already enough entropy for this
        // nonce's actual job (de-duplicating redemptions in an in-memory
        // map with a 30s TTL), but there is no reason for it to be the
        // one random identifier in `loom-http` that doesn't match the
        // rest.
        let mut nonce = [0u8; 32];
        rand::rng().fill(&mut nonce);
        let claims = WsTicketClaims {
            sub: sub.to_string(),
            sid: sid.to_string(),
            nonce: base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, nonce),
            exp: OffsetDateTime::now_utc().unix_timestamp() + TICKET_TTL_SECS,
        };
        self.key.encode(&claims)
    }

    /// Verify + decode, then consume -- a second call with the same
    /// ticket gets [`WsTicketError::AlreadyUsed`] even though the
    /// signature/expiry still verify.
    pub fn redeem(&self, ticket: &str) -> Result<WsTicketIdentity, WsTicketError> {
        let claims: WsTicketClaims = self
            .key
            .decode(ticket)
            .map_err(|_| WsTicketError::Invalid)?;
        let mut used = self.used.lock().unwrap();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        used.retain(|_, exp| *exp > now);
        if used.contains_key(&claims.nonce) {
            return Err(WsTicketError::AlreadyUsed);
        }
        used.insert(claims.nonce.clone(), claims.exp);
        Ok(WsTicketIdentity {
            sub: claims.sub,
            sid: claims.sid,
        })
    }
}

impl Default for WsTicketIssuer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_then_redeem_round_trips_identity() {
        let issuer = WsTicketIssuer::new();
        let ticket = issuer.issue("alice", "sid-1").unwrap();
        let identity = issuer.redeem(&ticket).unwrap();
        assert_eq!(identity.sub, "alice");
        assert_eq!(identity.sid, "sid-1");
    }

    #[test]
    fn a_ticket_cannot_be_redeemed_twice() {
        let issuer = WsTicketIssuer::new();
        let ticket = issuer.issue("alice", "sid-1").unwrap();
        issuer.redeem(&ticket).unwrap();
        assert_eq!(issuer.redeem(&ticket), Err(WsTicketError::AlreadyUsed));
    }

    #[test]
    fn issued_tickets_expire_after_thirty_seconds() {
        // D-TM4 "valid for 30 s" (OBI-319 second-review point 1): pin the
        // TTL the issuer actually stamps, not just the generic expiry check.
        let issuer = WsTicketIssuer::new();
        let before = OffsetDateTime::now_utc().unix_timestamp();
        let ticket = issuer.issue("alice", "sid-1").unwrap();
        let after = OffsetDateTime::now_utc().unix_timestamp();
        let claims: WsTicketClaims = issuer.key.decode(&ticket).unwrap();
        assert!(claims.exp >= before + TICKET_TTL_SECS && claims.exp <= after + TICKET_TTL_SECS);
        assert_eq!(TICKET_TTL_SECS, 30);
    }

    #[test]
    fn an_expired_ticket_is_rejected_even_on_first_use() {
        // Signed by the right key, never redeemed, but past `exp`: refused.
        let issuer = WsTicketIssuer::new();
        let expired = issuer
            .key
            .encode(&WsTicketClaims {
                sub: "alice".to_string(),
                sid: "sid-1".to_string(),
                nonce: "n".to_string(),
                exp: OffsetDateTime::now_utc().unix_timestamp() - 1,
            })
            .unwrap();
        assert_eq!(issuer.redeem(&expired), Err(WsTicketError::Invalid));
    }

    #[test]
    fn a_malformed_ticket_is_rejected() {
        let issuer = WsTicketIssuer::new();
        assert_eq!(issuer.redeem("garbage"), Err(WsTicketError::Invalid));
    }

    #[test]
    fn a_ticket_from_a_different_issuer_is_rejected() {
        let issuer = WsTicketIssuer::new();
        let other = WsTicketIssuer::new();
        let ticket = other.issue("alice", "sid-1").unwrap();
        assert_eq!(issuer.redeem(&ticket), Err(WsTicketError::Invalid));
    }
}
