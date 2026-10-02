// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Encryption at rest for TOTP secrets (OBI-199, design threat-model-
//! phase2.md §6.1 M-AUTH-8: "Store the secret **encrypted**
//! (XChaCha20-Poly1305 or AES-GCM) under a key from the secret file, not
//! in plaintext in Postgres.").
//!
//! Postgres (`staff.totp_secret_enc`) only ever holds the ciphertext blob
//! this module produces: a 24-byte random nonce, the XChaCha20-Poly1305
//! ciphertext, and its 16-byte tag, concatenated. The 32-byte key lives
//! only in `loom-http`'s process memory, read once at boot from
//! `LOOM_TOTP_ENC_KEY` (same "secret file, not a default" shape as
//! `LOOM_JWT_SECRET` -- see `loom-cli::totp_enc_key_from_env`).
//!
//! Each secret is additionally bound (as AEAD associated data) to the
//! owning uid, so a ciphertext blob copied between two `staff` rows (a
//! corrupted backup restore, a buggy migration, ...) fails to decrypt
//! rather than silently decrypting as some *other* uid's secret.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::Rng;

const NONCE_LEN: usize = 24;

#[derive(Clone)]
pub struct TotpCipher {
    cipher: XChaCha20Poly1305,
}

impl TotpCipher {
    /// `key` must be exactly 32 bytes of high-entropy data (generated, not
    /// human-chosen -- `openssl rand -hex 32`), same expectation as the JWT
    /// signing secret.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key.into()),
        }
    }

    /// Encrypt `plaintext` (a base32 TOTP secret), AAD-bound to `uid`.
    /// Returns `nonce || ciphertext || tag`.
    pub fn encrypt(&self, uid: &str, plaintext: &str) -> Vec<u8> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext.as_bytes(),
                    aad: uid.as_bytes(),
                },
            )
            .expect("XChaCha20-Poly1305 encryption does not fail for in-memory plaintext");
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Decrypt a blob produced by [`Self::encrypt`] for the same `uid`.
    /// `None` on any failure (wrong key, wrong uid, truncated/corrupt
    /// blob) -- never a panic, since this runs against whatever bytes
    /// Postgres happens to hold.
    pub fn decrypt(&self, uid: &str, blob: &[u8]) -> Option<String> {
        if blob.len() < NONCE_LEN {
            return None;
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce_bytes).ok()?;
        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad: uid.as_bytes(),
                },
            )
            .ok()?;
        String::from_utf8(plaintext).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> TotpCipher {
        TotpCipher::new(&[7u8; 32])
    }

    #[test]
    fn round_trips() {
        let c = cipher();
        let blob = c.encrypt("gandalf", "JBSWY3DPEHPK3PXP");
        assert_eq!(
            c.decrypt("gandalf", &blob).as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
    }

    #[test]
    fn ciphertext_never_contains_the_plaintext() {
        let c = cipher();
        let secret = "JBSWY3DPEHPK3PXP";
        let blob = c.encrypt("gandalf", secret);
        let as_text = String::from_utf8_lossy(&blob);
        assert!(!as_text.contains(secret));
    }

    #[test]
    fn wrong_uid_fails_to_decrypt() {
        let c = cipher();
        let blob = c.encrypt("gandalf", "JBSWY3DPEHPK3PXP");
        assert_eq!(c.decrypt("saruman", &blob), None);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let blob = cipher().encrypt("gandalf", "JBSWY3DPEHPK3PXP");
        let other = TotpCipher::new(&[9u8; 32]);
        assert_eq!(other.decrypt("gandalf", &blob), None);
    }

    #[test]
    fn corrupt_blob_never_panics() {
        let c = cipher();
        assert_eq!(c.decrypt("gandalf", b"too-short"), None);
        assert_eq!(c.decrypt("gandalf", &[0u8; 40]), None);
    }
}
