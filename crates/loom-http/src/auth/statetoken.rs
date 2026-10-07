// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Opaque, HMAC-signed tokens for the two short-lived, single-purpose
//! credentials the GitHub login flow needs (OBI-201, M-AUTH-7): the
//! `__Host-` OAuth state/PKCE cookie and the pending-TOTP cookie handed
//! back when a T3+ GitHub login still needs a code.
//!
//! Deliberately **not** JWTs, and deliberately signed with a key that has
//! nothing to do with [`super::jwt::JwtKeys`] (CTO review on PR #78,
//! must-fix 2): now that staff access tokens are EdDSA-only, collapsing
//! these two short-lived, narrow-purpose tokens into that same signing
//! domain would mean a bug anywhere in this (smaller, newer) code path
//! could forge -- or be confused with -- a real staff access token. A
//! plain `HMAC-SHA256` over a random, process-lifetime-only key needs
//! none of that keyset's rotation/overlap-window machinery: these tokens
//! live for minutes, not the weeks an access/refresh session does, and
//! the two-part `claims.sig` shape (not three-part, no `alg`/`kid`
//! header) is deliberately not JWT-shaped, so it can never even be
//! misrouted into [`super::jwt::JwtKeys::decode`] by a confused caller.
//!
//! The key is generated fresh every time this process starts and is
//! never persisted anywhere. That's intentional, not a shortcut: a
//! restart simply invalidates any GitHub login in flight (the browser is
//! mid-redirect to/from GitHub, or mid-TOTP-entry) exactly like it would
//! invalidate an in-flight TCP connection, and the fix is the same as for
//! any other transient failure -- the user retries `/auth/github/start`.
//! There is no secret file to mount, rotate, or leak for this signing
//! domain at all.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::Sha256;
use time::OffsetDateTime;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateTokenError;

/// A claims type carrying a Unix-seconds expiry, so [`StateTokenKey::decode`]
/// can enforce it generically. Kept distinct from `jwt::Expires` so this
/// module has no dependency on the EdDSA signing path at all.
pub trait HasExpiry {
    fn expires_at(&self) -> i64;
}

/// An HMAC-SHA256 key for this module's two token types only -- never
/// used to sign/verify an [`super::claims::AccessClaims`] or anything
/// else outside this file.
#[derive(Clone)]
pub struct StateTokenKey {
    key: [u8; 32],
}

impl StateTokenKey {
    /// A fresh, process-lifetime-only CSPRNG key (see the module doc for
    /// why that's the right lifetime for these tokens).
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::rng().fill(&mut key);
        Self { key }
    }

    fn mac(&self) -> HmacSha256 {
        HmacSha256::new_from_slice(&self.key)
            .expect("HMAC-SHA256 accepts a key of any length, including exactly 32 bytes")
    }

    /// Sign `claims` as `BASE64URL(claims_json).BASE64URL(hmac)`.
    pub fn encode<T: Serialize>(&self, claims: &T) -> Result<String, StateTokenError> {
        let claims_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|_| StateTokenError)?);
        let mut mac = self.mac();
        mac.update(claims_b64.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        Ok(format!("{claims_b64}.{sig_b64}"))
    }

    /// Verify the HMAC (constant-time) and expiry, then decode `claims`.
    /// Refuses a malformed token, a bad signature, or an expired one --
    /// callers additionally check their claims type's `purpose` field
    /// (this module has no concept of "purpose", only "well-formed and
    /// unexpired").
    pub fn decode<T: DeserializeOwned + HasExpiry>(
        &self,
        token: &str,
    ) -> Result<T, StateTokenError> {
        let mut parts = token.split('.');
        let (Some(claims_b64), Some(sig_b64), None) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(StateTokenError);
        };

        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| StateTokenError)?;
        let mut mac = self.mac();
        mac.update(claims_b64.as_bytes());
        mac.verify_slice(&sig_bytes).map_err(|_| StateTokenError)?;

        let claims_bytes = URL_SAFE_NO_PAD
            .decode(claims_b64)
            .map_err(|_| StateTokenError)?;
        let claims: T = serde_json::from_slice(&claims_bytes).map_err(|_| StateTokenError)?;

        if claims.expires_at() <= OffsetDateTime::now_utc().unix_timestamp() {
            return Err(StateTokenError);
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Claims {
        value: i64,
        exp: i64,
    }

    impl HasExpiry for Claims {
        fn expires_at(&self) -> i64 {
            self.exp
        }
    }

    fn claims(ttl_secs: i64) -> Claims {
        Claims {
            value: 42,
            exp: OffsetDateTime::now_utc().unix_timestamp() + ttl_secs,
        }
    }

    #[test]
    fn round_trips() {
        let key = StateTokenKey::generate();
        let token = key.encode(&claims(300)).unwrap();
        let decoded: Claims = key.decode(&token).unwrap();
        assert_eq!(decoded, claims(300));
    }

    #[test]
    fn rejects_a_token_signed_with_a_different_key() {
        let key = StateTokenKey::generate();
        let other = StateTokenKey::generate();
        let token = other.encode(&claims(300)).unwrap();
        assert!(key.decode::<Claims>(&token).is_err());
    }

    #[test]
    fn rejects_an_expired_token() {
        let key = StateTokenKey::generate();
        let token = key.encode(&claims(-1)).unwrap();
        assert!(key.decode::<Claims>(&token).is_err());
    }

    #[test]
    fn rejects_malformed_tokens() {
        let key = StateTokenKey::generate();
        for bad in ["", "a.b.c", "not-base64!.not-base64!"] {
            assert!(
                key.decode::<Claims>(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let key = StateTokenKey::generate();
        let token = key.encode(&claims(300)).unwrap();
        let (claims_b64, _sig) = token.split_once('.').unwrap();
        let tampered = format!("{claims_b64}.{}", URL_SAFE_NO_PAD.encode([0u8; 32]));
        assert!(key.decode::<Claims>(&tampered).is_err());
    }
}
