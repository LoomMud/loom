// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! JWT (HS256 only) signing/verification for access tokens (OBI-174).
//!
//! Hand-rolled rather than pulled from a library: the only algorithm this
//! service ever needs is HS256 (a single shared server secret --
//! `LOOM_JWT_SECRET` -- no asymmetric keys, no JWK discovery, no `alg`
//! negotiation), and every general-purpose Rust JWT crate available at
//! review time pulled in either a C TLS/crypto backend (`aws-lc-rs`) or,
//! for a pure-Rust backend, RSA support (`rsa` v0.9, unpatched timing
//! side-channel, RUSTSEC-2023-0071) even when only HMAC is used, which
//! `cargo deny`'s advisory gate correctly refuses. This is small enough
//! (and the "H" in HMAC already means "keep this constant-time or don't
//! bother") to own directly with `hmac`/`sha2`, both widely-used
//! RustCrypto primitives with no known advisories.
//!
//! `decode`/[`JwtKeys::decode`] always compares the signature in constant
//! time (`hmac`'s `verify_slice`, never a `==` on the raw bytes) --
//! fixing exactly the class of bug the paragraph above is about.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::OffsetDateTime;

use super::claims::AccessClaims;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtError;

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid or unverifiable token")
    }
}

impl std::error::Error for JwtError {}

#[derive(Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
}

fn header() -> Header {
    Header {
        alg: "HS256".to_string(),
        typ: "JWT".to_string(),
    }
}

#[derive(Clone)]
pub struct JwtKeys {
    secret: Vec<u8>,
}

impl JwtKeys {
    /// `secret` should be at least 32 bytes of high-entropy data (a
    /// generated, not human-chosen, value) -- `loom-cli` reads it from
    /// `LOOM_JWT_SECRET` and does not mount `/auth/*` at all without one
    /// (see the OBI-174 PR description).
    pub fn from_secret(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
        }
    }

    pub fn encode(&self, claims: &AccessClaims) -> Result<String, JwtError> {
        let header_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header()).map_err(|_| JwtError)?);
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|_| JwtError)?);
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature = self.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature);
        Ok(format!("{signing_input}.{signature_b64}"))
    }

    pub fn decode(&self, token: &str) -> Result<AccessClaims, JwtError> {
        let mut parts = token.split('.');
        let (Some(header_b64), Some(claims_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JwtError);
        };

        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).map_err(|_| JwtError)?;
        let header: Header = serde_json::from_slice(&header_bytes).map_err(|_| JwtError)?;
        if header.alg != "HS256" {
            // No algorithm negotiation: this service only ever issues and
            // accepts HS256. In particular this refuses the classic `alg:
            // none` forgery outright, not via an allow-list check anyone
            // could later loosen.
            return Err(JwtError);
        }

        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| JwtError)?;
        self.verify(signing_input.as_bytes(), &signature)?;

        let claims_bytes = URL_SAFE_NO_PAD.decode(claims_b64).map_err(|_| JwtError)?;
        let claims: AccessClaims = serde_json::from_slice(&claims_bytes).map_err(|_| JwtError)?;

        let now = OffsetDateTime::now_utc().unix_timestamp();
        if claims.exp <= now {
            return Err(JwtError);
        }

        Ok(claims)
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts a key of any length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Constant-time signature verification (`hmac::Mac::verify_slice`) --
    /// never compare the computed and presented signatures with `==`.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), JwtError> {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts a key of any length");
        mac.update(data);
        mac.verify_slice(signature).map_err(|_| JwtError)
    }
}

/// The (access, refresh) pair returned by every successful login/refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: OffsetDateTime,
    pub refresh_expires_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::claims::scopes_for_tier;

    fn sample_claims() -> AccessClaims {
        AccessClaims {
            sub: "legolas".to_string(),
            aud: crate::auth::claims::ACCESS_AUDIENCE.to_string(),
            tier: 3,
            scopes: scopes_for_tier(3),
            iat: OffsetDateTime::now_utc().unix_timestamp(),
            exp: OffsetDateTime::now_utc().unix_timestamp() + 600,
        }
    }

    #[test]
    fn round_trips() {
        let keys = JwtKeys::from_secret(b"a-test-secret-at-least-32-bytes!");
        let token = keys.encode(&sample_claims()).unwrap();
        let decoded = keys.decode(&token).unwrap();
        assert_eq!(decoded, sample_claims());
    }

    #[test]
    fn rejects_a_token_signed_with_a_different_secret() {
        let keys = JwtKeys::from_secret(b"server-secret-aaaaaaaaaaaaaaaaaa");
        let attacker_keys = JwtKeys::from_secret(b"attacker-secret-bbbbbbbbbbbbbbbb");
        let token = attacker_keys.encode(&sample_claims()).unwrap();
        assert!(keys.decode(&token).is_err());
    }

    #[test]
    fn rejects_an_expired_token() {
        let keys = JwtKeys::from_secret(b"a-test-secret-at-least-32-bytes!");
        let mut claims = sample_claims();
        claims.exp = OffsetDateTime::now_utc().unix_timestamp() - 1;
        let token = keys.encode(&claims).unwrap();
        assert!(keys.decode(&token).is_err());
    }

    #[test]
    fn rejects_alg_none_forgery() {
        let keys = JwtKeys::from_secret(b"a-test-secret-at-least-32-bytes!");
        let claims = sample_claims();
        let header_b64 = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&serde_json::json!({"alg": "none", "typ": "JWT"})).unwrap());
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let forged = format!("{header_b64}.{claims_b64}.");
        assert!(keys.decode(&forged).is_err());
    }

    #[test]
    fn rejects_malformed_tokens() {
        let keys = JwtKeys::from_secret(b"a-test-secret-at-least-32-bytes!");
        for bad in ["", "a.b", "a.b.c.d", "not-base64!.not-base64!.not-base64!"] {
            assert!(keys.decode(bad).is_err(), "expected {bad:?} to be rejected");
        }
    }
}
