// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! RS256 App JWT minting (D-B3.11): `{alg: RS256, typ: JWT}` header,
//! `{iat, exp, iss}` claims per GitHub's App auth docs. Signing is pure
//! Rust (RustCrypto `rsa` + `sha2`), not OpenSSL/`ring` -- see the
//! crate's `Cargo.toml` comment for why.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::rand_core::OsRng;
use serde::Serialize;
use sha2::Sha256;
use signature::{RandomizedSigner, SignatureEncoding};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtError {
    /// The PEM parsed as neither PKCS#1 nor PKCS#8.
    BadKey(String),
    /// `app_id` was not ASCII/plain enough to go in a claim as a string.
    BadAppId,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::BadKey(e) => write!(f, "bad GitHub App private key: {e}"),
            JwtError::BadAppId => write!(f, "bad GitHub App id"),
        }
    }
}

#[derive(Serialize)]
struct Claims<'a> {
    iat: i64,
    exp: i64,
    iss: &'a str,
}

/// Parses a GitHub App private key PEM, accepting either the PKCS#1
/// (the PKCS#1 "RSA PRIVATE KEY" PEM header, what GitHub's UI hands out)
/// or PKCS#8 (the plain "PRIVATE KEY" PEM header) encoding.
pub fn load_private_key(pem: &str) -> Result<RsaPrivateKey, JwtError> {
    RsaPrivateKey::from_pkcs1_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(pem))
        .map_err(|e| JwtError::BadKey(e.to_string()))
}

/// Mints a GitHub App JWT (RS256) good for 9 minutes, backdated 60 s for
/// clock skew (GitHub's documented recipe; the hard cap is 10 minutes).
pub fn mint(app_id: &str, key: &RsaPrivateKey, now: SystemTime) -> Result<String, JwtError> {
    if app_id.is_empty() {
        return Err(JwtError::BadAppId);
    }
    let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let claims = Claims {
        iat: now_secs - 60,
        exp: now_secs + 9 * 60,
        iss: app_id,
    };
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims serialize"));
    let signing_input = format!("{header}.{payload}");

    let signing_key = SigningKey::<Sha256>::new(key.clone());
    // RUSTSEC-2023-0071 ("Marvin Attack") mitigation: sign with blinding
    // (`RandomizedSigner` + `OsRng`), not the unblinded `Signer::sign`
    // path, per CTO review (OBI-191). PKCS#1 v1.5 signatures are
    // otherwise deterministic -- blinding changes only the computation,
    // never the output -- so this does not change what a verifier sees.
    let sig = signing_key.sign_with_rng(&mut OsRng, signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    Ok(format!("{signing_input}.{sig_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;

    fn test_key() -> RsaPrivateKey {
        // A small key (fast to generate) is fine: we only exercise
        // parsing/signing shape, not real GitHub traffic.
        RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("keygen")
    }

    #[test]
    fn loads_pkcs1_and_pkcs8_pem() {
        let key = test_key();
        let pkcs1 = key.to_pkcs1_pem(Default::default()).unwrap();
        let pkcs8 = key.to_pkcs8_pem(Default::default()).unwrap();
        assert!(load_private_key(&pkcs1).is_ok());
        assert!(load_private_key(&pkcs8).is_ok());
    }

    #[test]
    fn rejects_garbage_pem() {
        assert!(load_private_key("not a key").is_err());
    }

    #[test]
    fn jwt_has_three_segments_and_rs256_header() {
        let key = test_key();
        let jwt = mint("12345", &key, SystemTime::now()).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        assert_eq!(header, br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(claims["iss"], "12345");
        assert!(claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap() <= 10 * 60);
    }

    #[test]
    fn jwt_claims_backdate_iat_for_clock_skew() {
        let key = test_key();
        let now = SystemTime::now();
        let jwt = mint("1", &key, now).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        let now_secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        assert_eq!(claims["iat"], now_secs - 60);
        assert_eq!(claims["exp"], now_secs + 9 * 60);
    }

    #[test]
    fn empty_app_id_is_rejected() {
        let key = test_key();
        assert_eq!(mint("", &key, SystemTime::now()), Err(JwtError::BadAppId));
    }

    /// The signature must actually verify against the public key -- not
    /// just "be 256 bytes" -- or a malformed signer could pass every
    /// other test here while GitHub rejects every token mint.
    #[test]
    fn jwt_signature_verifies() {
        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;

        let key = test_key();
        let jwt = mint("42", &key, SystemTime::now()).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).unwrap();
        let verifying_key = VerifyingKey::<Sha256>::new(key.to_public_key());
        verifying_key
            .verify(signing_input.as_bytes(), &sig)
            .expect("signature verifies against the public key");
    }
}
