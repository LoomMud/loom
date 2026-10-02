// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! EdDSA (Ed25519) JWT signing/verification for staff access tokens
//! (OBI-174 follow-up, OBI-197, M-AUTH-4).
//!
//! Replaces the original HS256-with-a-shared-secret design (reviewed in
//! PR #73 / OBI-195) with asymmetric signing from a key loaded off a
//! mounted secret file:
//!
//! - The signature algorithm is **pinned** to `EdDSA` -- `decode` refuses
//!   anything else outright, including the classic `alg: none` forgery
//!   and an attacker presenting an HS256 token (there is no HMAC key to
//!   confuse it with any more, but a stale/attacker-crafted HS256 header
//!   is still rejected by the same check).
//! - Every header carries a `kid`. [`JwtKeys`] holds a **verifier keyset**
//!   (every key this service might still need to verify) plus one
//!   *active* signing key -- so a key can be rotated by adding the new
//!   key as active while the old one stays in the keyset for the overlap
//!   window, then dropping it once every token signed with it has
//!   expired. A `kid` absent from the keyset is refused.
//! - `decode` checks `iss`, `aud` (pinned to [`AUDIENCE`] =
//!   `loom-staff-access` -- refresh tokens and WS tickets aren't JWTs and
//!   use a different value entirely, so there is no token-type confusion
//!   possible here), `exp`, and `nbf` (allowing [`NBF_SKEW_SECS`] of
//!   clock skew, not an open-ended "not yet valid" window).
//!
//! `ed25519-dalek` was picked over every general-purpose JWT crate
//! available at review time for the same reason `hmac`/`sha2` were:
//! `cargo deny`'s advisory gate (RUSTSEC-2023-0071, the `rsa` timing
//! side-channel) rules out every pure-Rust option that also pulls in RSA,
//! and the C-backed alternatives (`aws-lc-rs`) aren't acceptable in a
//! driver that must never touch unaudited FFI on the hot path. This is a
//! single widely-used, pure-Rust RustCrypto-adjacent primitive with no
//! known advisories -- see `deny.toml`.

use std::collections::HashMap;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::claims::AccessClaims;

/// The only `aud` an access token is ever issued for or accepted with
/// (D-TM2/M-AUTH-4). Refresh tokens are opaque random bytes, not JWTs at
/// all, and a future WS ticket (D-TM4) is a different, single-use,
/// non-JWT credential -- so there is no other token type this value could
/// ever be confused with.
pub const AUDIENCE: &str = "loom-staff-access";

/// Tolerated clock skew for the `nbf` check (M-AUTH-4: "`nbf` (skew <= 30
/// s)"). A token is rejected if `nbf` is more than this far in the
/// future, never accepted just because `nbf` is unset or in the past.
pub const NBF_SKEW_SECS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtError;

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid or unverifiable token")
    }
}

impl std::error::Error for JwtError {}

/// A key-file load/parse failure. Distinct from [`JwtError`] (a
/// per-request verification failure): this only ever happens once, at
/// boot, and callers are expected to fail startup loudly rather than run
/// with a partially-loaded keyset.
#[derive(Debug)]
pub struct JwtKeyError(String);

impl std::fmt::Display for JwtKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid JWT key configuration: {}", self.0)
    }
}

impl std::error::Error for JwtKeyError {}

#[derive(Serialize, Deserialize)]
struct Header {
    alg: String,
    kid: String,
    typ: String,
}

/// The on-disk shape of the mounted key file: one *active* signing key
/// (by `kid`) plus every key still in the verifier keyset (including the
/// active one). Every value is the 32-byte Ed25519 seed, base64-encoded
/// (standard alphabet, padded).
///
/// ```json
/// {
///   "active_kid": "2026-02",
///   "keys": {
///     "2026-02": "<base64 32-byte seed>",
///     "2026-01": "<base64 32-byte seed -- kept only for the overlap window>"
///   }
/// }
/// ```
///
/// Rotation: add the new kid, flip `active_kid` to it, redeploy (no
/// restart needed beyond the next read of this file -- see
/// `loom-cli`'s `LOOM_JWT_KEY_FILE`), then once every token signed with
/// the old kid has expired (at most `ACCESS_TOKEN_TTL` after the flip),
/// remove the old entry.
#[derive(Deserialize)]
struct KeyFile {
    active_kid: String,
    keys: HashMap<String, String>,
}

/// EdDSA signing/verification keys for staff access tokens (M-AUTH-4).
/// One active signing key; a verifier keyset (by `kid`) that may hold
/// additional, overlap-window-only keys.
#[derive(Clone)]
pub struct JwtKeys {
    active_kid: String,
    signing_key: SigningKey,
    verifying_keys: HashMap<String, VerifyingKey>,
    issuer: String,
    audience: String,
}

impl JwtKeys {
    /// Load the keyset from a mounted secret file (see [`KeyFile`]'s
    /// format). `issuer` is this service's `iss` value; `audience` should
    /// almost always be [`AUDIENCE`] (exposed as a parameter only so
    /// tests can exercise the mismatch-is-rejected path without a second
    /// constructor).
    pub fn from_key_file(
        path: impl AsRef<Path>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, JwtKeyError> {
        let path = path.as_ref();
        let data = std::fs::read_to_string(path)
            .map_err(|err| JwtKeyError(format!("reading {}: {err}", path.display())))?;
        let file: KeyFile = serde_json::from_str(&data)
            .map_err(|err| JwtKeyError(format!("parsing {}: {err}", path.display())))?;

        let mut seeds = Vec::with_capacity(file.keys.len());
        for (kid, encoded) in file.keys {
            let bytes = STANDARD
                .decode(&encoded)
                .map_err(|err| JwtKeyError(format!("key {kid:?}: not valid base64: {err}")))?;
            let seed: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
                JwtKeyError(format!(
                    "key {kid:?}: expected a 32-byte Ed25519 seed, got {} bytes",
                    bytes.len()
                ))
            })?;
            seeds.push((kid, seed));
        }

        Self::from_keyset(file.active_kid, seeds, issuer, audience)
    }

    /// Build a keyset directly from `(kid, seed)` pairs -- the primitive
    /// [`Self::from_key_file`] delegates to, and what tests use to set up
    /// a rotation scenario without a temp file.
    pub fn from_keyset(
        active_kid: impl Into<String>,
        seeds: impl IntoIterator<Item = (String, [u8; 32])>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, JwtKeyError> {
        let active_kid = active_kid.into();
        let mut verifying_keys = HashMap::new();
        let mut signing_key = None;
        for (kid, seed) in seeds {
            let sk = SigningKey::from_bytes(&seed);
            let vk = sk.verifying_key();
            if kid == active_kid {
                signing_key = Some(sk);
            }
            verifying_keys.insert(kid, vk);
        }
        let signing_key = signing_key.ok_or_else(|| {
            JwtKeyError(format!(
                "active_kid {active_kid:?} has no matching entry in `keys`"
            ))
        })?;

        Ok(Self {
            active_kid,
            signing_key,
            verifying_keys,
            issuer: issuer.into(),
            audience: audience.into(),
        })
    }

    /// A single-key keyset (no rotation in progress). Mainly for tests;
    /// production always goes through [`Self::from_key_file`] since an
    /// operator rotating keys needs the overlap window a one-key keyset
    /// can't provide.
    pub fn single(
        seed: [u8; 32],
        kid: impl Into<String>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        let kid = kid.into();
        Self::from_keyset(kid.clone(), [(kid, seed)], issuer, audience)
            .expect("a single well-formed seed can't fail keyset construction")
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn encode(&self, claims: &AccessClaims) -> Result<String, JwtError> {
        let header = Header {
            alg: "EdDSA".to_string(),
            kid: self.active_kid.clone(),
            typ: "JWT".to_string(),
        };
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| JwtError)?);
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|_| JwtError)?);
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature = self.signing_key.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
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
        if header.alg != "EdDSA" {
            // Pinned algorithm: no negotiation, so neither `alg: none`
            // nor a (now entirely hypothetical, since there's no shared
            // secret to confuse it with) HS256 token verifies.
            return Err(JwtError);
        }

        let Some(verifying_key) = self.verifying_keys.get(&header.kid) else {
            // Unknown `kid`: either a stale/attacker-chosen id, or a key
            // that has already rolled out of the overlap window.
            return Err(JwtError);
        };

        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| JwtError)?;
        let signature_bytes: [u8; 64] = signature_bytes.try_into().map_err(|_| JwtError)?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| JwtError)?;

        let claims_bytes = URL_SAFE_NO_PAD.decode(claims_b64).map_err(|_| JwtError)?;
        let claims: AccessClaims = serde_json::from_slice(&claims_bytes).map_err(|_| JwtError)?;

        if claims.iss != self.issuer {
            return Err(JwtError);
        }
        if claims.aud != self.audience {
            return Err(JwtError);
        }

        let now = OffsetDateTime::now_utc().unix_timestamp();
        if claims.exp <= now {
            return Err(JwtError);
        }
        if claims.nbf > now + NBF_SKEW_SECS {
            return Err(JwtError);
        }

        Ok(claims)
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

    const ISSUER: &str = "https://build.loommud.com/";

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn keys() -> JwtKeys {
        JwtKeys::single(seed(1), "test-kid", ISSUER, AUDIENCE)
    }

    fn sample_claims() -> AccessClaims {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        AccessClaims {
            sub: "legolas".to_string(),
            tier: 3,
            scopes: scopes_for_tier(3),
            iss: ISSUER.to_string(),
            aud: AUDIENCE.to_string(),
            iat: now,
            nbf: now,
            exp: now + 600,
            sid: "sid-1".to_string(),
            amr: vec!["pwd".to_string()],
            mfa_at: None,
        }
    }

    #[test]
    fn round_trips() {
        let keys = keys();
        let token = keys.encode(&sample_claims()).unwrap();
        let decoded = keys.decode(&token).unwrap();
        assert_eq!(decoded, sample_claims());
    }

    #[test]
    fn rejects_a_token_signed_with_a_different_key() {
        let keys = JwtKeys::single(seed(1), "test-kid", ISSUER, AUDIENCE);
        let attacker_keys = JwtKeys::single(seed(2), "test-kid", ISSUER, AUDIENCE);
        let token = attacker_keys.encode(&sample_claims()).unwrap();
        assert!(keys.decode(&token).is_err());
    }

    #[test]
    fn rejects_an_expired_token() {
        let keys = keys();
        let mut claims = sample_claims();
        claims.exp = OffsetDateTime::now_utc().unix_timestamp() - 1;
        let token = keys.encode(&claims).unwrap();
        assert!(keys.decode(&token).is_err());
    }

    /// Acceptance: "future `nbf` rejected".
    #[test]
    fn rejects_a_token_not_yet_valid_beyond_the_allowed_skew() {
        let keys = keys();
        let mut claims = sample_claims();
        claims.nbf = OffsetDateTime::now_utc().unix_timestamp() + 3600;
        let token = keys.encode(&claims).unwrap();
        assert!(keys.decode(&token).is_err());
    }

    /// A small, within-skew `nbf` (clock drift between issuer and
    /// verifier) is still accepted.
    #[test]
    fn accepts_a_token_within_the_allowed_nbf_skew() {
        let keys = keys();
        let mut claims = sample_claims();
        claims.nbf = OffsetDateTime::now_utc().unix_timestamp() + (NBF_SKEW_SECS - 1);
        let token = keys.encode(&claims).unwrap();
        assert!(keys.decode(&token).is_ok());
    }

    /// Acceptance: "wrong `aud`/`iss` rejected".
    #[test]
    fn rejects_a_token_with_the_wrong_issuer() {
        let keys = keys();
        let mut claims = sample_claims();
        claims.iss = "https://attacker.example/".to_string();
        let token = keys.encode(&claims).unwrap();
        assert!(keys.decode(&token).is_err());
    }

    #[test]
    fn rejects_a_token_with_the_wrong_audience() {
        let keys = keys();
        let mut claims = sample_claims();
        claims.aud = "some-other-api".to_string();
        let token = keys.encode(&claims).unwrap();
        assert!(keys.decode(&token).is_err());
    }

    /// Acceptance: "unknown `kid` rejected".
    #[test]
    fn rejects_an_unknown_kid() {
        let keys = keys();
        let token = keys.encode(&sample_claims()).unwrap();
        // Swap in a `kid` this keyset never had.
        let mut parts = token.split('.');
        let _header_b64 = parts.next().unwrap();
        let claims_b64 = parts.next().unwrap();
        let signature_b64 = parts.next().unwrap();
        let forged_header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&Header {
                alg: "EdDSA".to_string(),
                kid: "no-such-kid".to_string(),
                typ: "JWT".to_string(),
            })
            .unwrap(),
        );
        let forged = format!("{forged_header}.{claims_b64}.{signature_b64}");
        assert!(keys.decode(&forged).is_err());
    }

    /// Acceptance: "HS256 token rejected" -- the algorithm is pinned to
    /// `EdDSA`, full stop.
    #[test]
    fn rejects_an_hs256_token() {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        let keys = keys();
        let claims = sample_claims();
        let header_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(
                &serde_json::json!({"alg": "HS256", "kid": "test-kid", "typ": "JWT"}),
            )
            .unwrap(),
        );
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header_b64}.{claims_b64}");
        // Even a signature the verifier *could* check (if it still spoke
        // HS256, which it doesn't) is irrelevant: `alg` is checked first.
        let mut mac = Hmac::<Sha256>::new_from_slice(b"any-key-at-all").unwrap();
        mac.update(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let forged = format!("{signing_input}.{signature_b64}");
        assert!(keys.decode(&forged).is_err());
    }

    #[test]
    fn rejects_alg_none_forgery() {
        let keys = keys();
        let claims = sample_claims();
        let header_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(
                &serde_json::json!({"alg": "none", "kid": "test-kid", "typ": "JWT"}),
            )
            .unwrap(),
        );
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let forged = format!("{header_b64}.{claims_b64}.");
        assert!(keys.decode(&forged).is_err());
    }

    #[test]
    fn rejects_malformed_tokens() {
        let keys = keys();
        for bad in ["", "a.b", "a.b.c.d", "not-base64!.not-base64!.not-base64!"] {
            assert!(keys.decode(bad).is_err(), "expected {bad:?} to be rejected");
        }
    }

    /// Acceptance: "rotation (old kid still verifies during overlap)".
    #[test]
    fn rotation_keeps_the_old_kid_verifiable_during_the_overlap_window() {
        // The old server: only the (soon-to-be-retired) key is active.
        let old_keys = JwtKeys::from_keyset(
            "2026-01",
            [("2026-01".to_string(), seed(1))],
            ISSUER,
            AUDIENCE,
        )
        .unwrap();
        let old_token = old_keys.encode(&sample_claims()).unwrap();

        // The rotated server: a new active key, but the old one is kept
        // in the verifier keyset for the overlap window.
        let rotated_keys = JwtKeys::from_keyset(
            "2026-02",
            [
                ("2026-02".to_string(), seed(2)),
                ("2026-01".to_string(), seed(1)),
            ],
            ISSUER,
            AUDIENCE,
        )
        .unwrap();

        // A token signed before the rotation (old kid) still verifies...
        assert_eq!(rotated_keys.decode(&old_token).unwrap(), sample_claims());
        // ...and a freshly issued token uses (and verifies against) the
        // new active key.
        let new_token = rotated_keys.encode(&sample_claims()).unwrap();
        assert_eq!(rotated_keys.decode(&new_token).unwrap(), sample_claims());

        // Once the old key is dropped from the keyset entirely (overlap
        // window over), the old token no longer verifies.
        let retired_keys = JwtKeys::from_keyset(
            "2026-02",
            [("2026-02".to_string(), seed(2))],
            ISSUER,
            AUDIENCE,
        )
        .unwrap();
        assert!(retired_keys.decode(&old_token).is_err());
    }

    #[test]
    fn from_key_file_loads_a_keyset_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwt-keys.json");
        let seed_b64 = STANDARD.encode(seed(7));
        std::fs::write(
            &path,
            format!(r#"{{"active_kid":"k1","keys":{{"k1":"{seed_b64}"}}}}"#),
        )
        .unwrap();

        let keys = JwtKeys::from_key_file(&path, ISSUER, AUDIENCE).unwrap();
        let token = keys.encode(&sample_claims()).unwrap();
        assert_eq!(keys.decode(&token).unwrap(), sample_claims());
    }

    #[test]
    fn from_key_file_rejects_an_active_kid_missing_from_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwt-keys.json");
        let seed_b64 = STANDARD.encode(seed(7));
        std::fs::write(
            &path,
            format!(r#"{{"active_kid":"missing","keys":{{"k1":"{seed_b64}"}}}}"#),
        )
        .unwrap();

        assert!(JwtKeys::from_key_file(&path, ISSUER, AUDIENCE).is_err());
    }
}
