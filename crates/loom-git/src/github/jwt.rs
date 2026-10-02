// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! RS256 App JWT minting (D-B3.11): `{alg: RS256, typ: JWT}` header,
//! `{iat, exp, iss}` claims per GitHub's App auth docs. Signing is
//! `ring::signature::RsaKeyPair` (RSA_PKCS1_SHA256) -- the same crypto
//! backend `github::tls_transport`'s production HTTPS transport to
//! `https://api.github.com` uses via `rustls` (OBI-215), not RustCrypto
//! `rsa` (RUSTSEC-2023-0071, the Marvin timing side channel, no fix
//! upstream). `ring` only parses PKCS#8 DER, so a PKCS#1 PEM is
//! re-wrapped as a PKCS#8 `PrivateKeyInfo` first -- pure ASN.1
//! restructuring (`pkcs1`/`pkcs8`/`der`, format crates with no RSA
//! arithmetic of their own, not `rsa` itself), never a cryptographic
//! operation on the key material.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use der::Encode;
use ring::rand::SystemRandom;
use ring::signature::{self, RsaKeyPair};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtError {
    /// The PEM parsed as neither PKCS#1 nor PKCS#8, or `ring` rejected
    /// the resulting DER (wrong key type, bad modulus size, etc.).
    BadKey(String),
    /// `app_id` was not ASCII/plain enough to go in a claim as a string.
    BadAppId,
    /// `ring`'s RSA signing failed (an internal `ring` error; not a
    /// "bad key" condition, since `load_private_key` already validated
    /// the key).
    SignFailed,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::BadKey(e) => write!(f, "bad GitHub App private key: {e}"),
            JwtError::BadAppId => write!(f, "bad GitHub App id"),
            JwtError::SignFailed => write!(f, "RS256 signing failed"),
        }
    }
}

#[derive(Serialize)]
struct Claims<'a> {
    iat: i64,
    exp: i64,
    iss: &'a str,
}

/// Wraps PKCS#1 DER (`rsaEncryption`, OID 1.2.840.113549.1.1.1) as a
/// PKCS#8 `PrivateKeyInfo` DER document -- exactly the envelope
/// `ring::signature::RsaKeyPair::from_pkcs8` requires and GitHub's own
/// PKCS#1 PEM is missing. No RSA math: this only rearranges bytes
/// already present in the PKCS#1 encoding into the PKCS#8 ASN.1 shape.
fn pkcs1_der_to_pkcs8_der(pkcs1_der: &[u8]) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    let algorithm = pkcs8::AlgorithmIdentifierRef {
        oid: pkcs1::ALGORITHM_OID,
        parameters: Some(der::asn1::AnyRef::from(der::asn1::Null)),
    };
    pkcs8::PrivateKeyInfo::new(algorithm, pkcs1_der)
        .to_der()
        .map(Zeroizing::new)
        .map_err(|e| JwtError::BadKey(format!("pkcs1->pkcs8 wrap: {e}")))
}

/// Parses a GitHub App private key PEM, accepting either the PKCS#1
/// (the PKCS#1 "RSA PRIVATE KEY" PEM header, what GitHub's UI hands out)
/// or PKCS#8 (the plain "PRIVATE KEY" PEM header) encoding, and returns
/// a `ring` RSA key pair ready to sign.
pub fn load_private_key(pem: &str) -> Result<RsaKeyPair, JwtError> {
    let (label, der_bytes) = pem_rfc7468::decode_vec(pem.as_bytes())
        .map_err(|e| JwtError::BadKey(format!("not a PEM document: {e}")))?;
    let der_bytes = Zeroizing::new(der_bytes);
    let pkcs8_der = match label {
        "PRIVATE KEY" => der_bytes,
        "RSA PRIVATE KEY" => pkcs1_der_to_pkcs8_der(&der_bytes)?,
        other => return Err(JwtError::BadKey(format!("unsupported PEM label {other:?}"))),
    };
    RsaKeyPair::from_pkcs8(&pkcs8_der).map_err(|e| JwtError::BadKey(e.to_string()))
}

/// Mints a GitHub App JWT (RS256) good for 9 minutes, backdated 60 s for
/// clock skew (GitHub's documented recipe; the hard cap is 10 minutes).
pub fn mint(app_id: &str, key: &RsaKeyPair, now: SystemTime) -> Result<String, JwtError> {
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

    let rng = SystemRandom::new();
    let mut sig = vec![0u8; key.public().modulus_len()];
    key.sign(
        &signature::RSA_PKCS1_SHA256,
        &rng,
        signing_input.as_bytes(),
        &mut sig,
    )
    .map_err(|_| JwtError::SignFailed)?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig);

    Ok(format!("{signing_input}.{sig_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway 2048-bit test fixture (generated once, offline, never
    // used for anything but these unit tests -- not a real GitHub App
    // key). Both PEM encodings below are the *same* key, so tests can
    // cross-check parsing and the PKCS#1-wrap path against each other.
    const TEST_KEY_PKCS1_PEM: &str = include_str!("testdata/test_key.pkcs1.pem");
    const TEST_KEY_PKCS8_PEM: &str = include_str!("testdata/test_key.pkcs8.pem");

    #[test]
    fn loads_pkcs1_and_pkcs8_pem() {
        assert!(load_private_key(TEST_KEY_PKCS1_PEM).is_ok());
        assert!(load_private_key(TEST_KEY_PKCS8_PEM).is_ok());
    }

    #[test]
    fn rejects_garbage_pem() {
        assert!(load_private_key("not a key").is_err());
    }

    #[test]
    fn pkcs1_and_pkcs8_pems_are_the_same_key() {
        // Same modulus (public key bytes) either way in: the PKCS#1
        // wrap-to-PKCS#8 path must not silently load a different key.
        let from_pkcs1 = load_private_key(TEST_KEY_PKCS1_PEM).unwrap();
        let from_pkcs8 = load_private_key(TEST_KEY_PKCS8_PEM).unwrap();
        assert_eq!(from_pkcs1.public().as_ref(), from_pkcs8.public().as_ref());
    }

    #[test]
    fn jwt_has_three_segments_and_rs256_header() {
        let key = load_private_key(TEST_KEY_PKCS8_PEM).unwrap();
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
        let key = load_private_key(TEST_KEY_PKCS8_PEM).unwrap();
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
        let key = load_private_key(TEST_KEY_PKCS8_PEM).unwrap();
        assert_eq!(mint("", &key, SystemTime::now()), Err(JwtError::BadAppId));
    }

    /// The signature must actually verify against the public key -- not
    /// just "be N bytes" -- or a malformed signer could pass every
    /// other test here while GitHub rejects every token mint. Verifies
    /// via `ring`'s own RSA verifier against the DER-encoded public key
    /// `RsaKeyPair::public()` exposes (the modulus/exponent pair, not a
    /// trusted-on-faith byte count) -- an independent code path
    /// (verification, not signing) over the same key material.
    #[test]
    fn jwt_signature_verifies() {
        let key = load_private_key(TEST_KEY_PKCS8_PEM).unwrap();
        let jwt = mint("42", &key, SystemTime::now()).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();

        let public_key = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            key.public().as_ref(),
        );
        public_key
            .verify(signing_input.as_bytes(), &sig_bytes)
            .expect("signature verifies against the public key");
    }

    /// A flipped signature byte must not verify -- guards against a
    /// verifier that accepts anything the right length.
    #[test]
    fn tampered_signature_does_not_verify() {
        let key = load_private_key(TEST_KEY_PKCS8_PEM).unwrap();
        let jwt = mint("42", &key, SystemTime::now()).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let mut sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        sig_bytes[0] ^= 0xFF;

        let public_key = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            key.public().as_ref(),
        );
        assert!(
            public_key
                .verify(signing_input.as_bytes(), &sig_bytes)
                .is_err()
        );
    }
}
