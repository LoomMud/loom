// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! TOTP enrolment/verification (RFC 6238, OBI-174). SHA-1, 6 digits, 30s
//! step, skew 1 -- the parameters every mainstream authenticator app
//! (Google Authenticator, 1Password, Authy, ...) expects; see `totp-rs`'s
//! own module docs on why SHA-1 is the interoperable choice even though
//! the library supports SHA-256/512.

use totp_rs::{Algorithm, Builder, Secret, Totp};

/// A freshly generated, not-yet-confirmed TOTP secret plus the `otpauth://`
/// URI an authenticator app's "scan a QR code" flow expects. `secret_base32`
/// is what gets handed to [`crate::auth::StaffDirectory::totp_enroll`].
#[derive(Debug)]
pub struct TotpEnrollment {
    pub secret_base32: String,
    pub otpauth_url: String,
}

fn build_totp(secret_base32: &str, account_name: &str) -> Result<Totp, totp_rs::TotpError> {
    let secret = Secret::try_from_base32(secret_base32)
        .map_err(|_| totp_rs::TotpError::SecretTooShort { bits: 0 })?;
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some("Loom"))
        .with_account_name(account_name)
        .build()
}

/// Generate a new random secret for `uid` and build its enrolment payload.
/// Does not persist anything -- callers still need
/// [`crate::auth::StaffDirectory::totp_enroll`].
pub fn generate_totp_secret(uid: &str) -> TotpEnrollment {
    let secret = Secret::generate();
    let secret_base32 = secret.to_base32();
    let totp = build_totp(&secret_base32, uid).expect("a freshly generated secret always builds");
    TotpEnrollment {
        otpauth_url: totp.to_url().expect("a short otpauth url always encodes"),
        secret_base32,
    }
}

/// Build a [`Totp`] from an already-enrolled base32 secret, for tests and
/// anywhere that wants to generate a code from a known secret.
pub fn totp_for_secret(secret_base32: &str, account_name: &str) -> Option<Totp> {
    build_totp(secret_base32, account_name).ok()
}

/// Verify a user-submitted 6-digit code against an enrolled base32 secret
/// and return the RFC 6238 time-step it matched (the skew window means
/// more than one step can validate the *signature*, but only one is ever
/// returned -- `totp-rs`'s own doc on [`totp_rs::Totp::check`] is explicit
/// that replay prevention across repeated use of the same step is the
/// caller's job, which is what [`crate::auth::StaffDirectory::totp_consume_step`]
/// does (OBI-195 review fix 4)). `None` for any parse failure (malformed
/// secret, non-numeric code, ...) or a code that matches no step in the
/// skew window -- never a panic, since this runs on every login attempt,
/// including ones an attacker controls the input to.
pub fn totp_step_for_code(secret_base32: &str, code: &str) -> Option<u64> {
    let totp = totp_for_secret(secret_base32, "")?;
    totp.check_current(code)
}

/// Verify a user-submitted 6-digit code against an enrolled base32 secret,
/// ignoring which step matched. Used only where there is no uid to track
/// anti-replay state against (i.e. nowhere in the auth service itself --
/// see [`totp_step_for_code`] -- but kept for tests and any future
/// call site that only cares about RFC 6238 validity).
pub fn verify_totp_code(secret_base32: &str, code: &str) -> bool {
    totp_step_for_code(secret_base32, code).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_round_trips_through_verification() {
        let enrollment = generate_totp_secret("legolas");
        assert!(enrollment.otpauth_url.starts_with("otpauth://totp/"));

        let totp = totp_for_secret(&enrollment.secret_base32, "legolas").unwrap();
        let code = totp.generate_current().to_string();
        assert!(verify_totp_code(&enrollment.secret_base32, &code));
    }

    #[test]
    fn wrong_code_is_rejected() {
        let enrollment = generate_totp_secret("legolas");
        assert!(!verify_totp_code(&enrollment.secret_base32, "000000"));
    }

    #[test]
    fn garbage_secret_never_panics() {
        assert!(!verify_totp_code("not-base32!!", "123456"));
    }
}
