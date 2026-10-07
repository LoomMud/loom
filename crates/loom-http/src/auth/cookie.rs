// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The `__Host-loom_rt` refresh-token cookie (OBI-198, D-TM2) and the
//! Origin + `X-Loom-Auth` CSRF guard for the two routes that read it
//! (M-AUTH-6). No general-purpose cookie-jar dependency: the `Cookie`
//! header this module ever needs to parse is exactly one cookie this
//! service itself set, so a few lines of manual parsing beat pulling in
//! `axum-extra` for it.

use axum::http::HeaderMap;
use axum::http::header::{HeaderName, HeaderValue};

/// `__Host-` is a browser-enforced prefix (RFC 6265bis): a cookie named
/// this way is only ever accepted/sent over HTTPS, with no `Domain`
/// attribute, and `Path=/` -- exactly the "can't be set by a sibling
/// subdomain or a plain-HTTP MITM" property D-TM2 wants, enforced by the
/// browser itself rather than just convention here.
pub const REFRESH_COOKIE_NAME: &str = "__Host-loom_rt";

/// The custom header M-AUTH-6 requires on `/auth/refresh` and
/// `/auth/logout`: a cross-site `<form>` or `fetch` with `mode:
/// "no-cors"` cannot set an arbitrary header, so requiring this one
/// forces a CORS preflight that this service never answers with an
/// `Access-Control-Allow-*` header for any other origin -- the preflight
/// simply fails closed for anyone not on the staff-origin allowlist.
pub const STAFF_AUTH_HEADER: &str = "x-loom-auth";
const STAFF_AUTH_HEADER_VALUE: &str = "1";

/// Build a `Set-Cookie` header value carrying `refresh_token`, valid for
/// `max_age_secs` seconds (clamped to >= 0; a caller wanting to clear the
/// cookie should use [`clear_cookie_header`] instead, which is more
/// explicit about intent than `max_age_secs: 0`).
pub fn set_cookie_header(refresh_token: &str, max_age_secs: i64) -> HeaderValue {
    let max_age = max_age_secs.max(0);
    let value = format!(
        "{REFRESH_COOKIE_NAME}={refresh_token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}"
    );
    HeaderValue::from_str(&value).expect("cookie header value is ASCII-safe by construction")
}

/// Build a `Set-Cookie` header value that clears the refresh cookie
/// (logout, or a failed refresh so the browser doesn't keep sending a
/// dead token): empty value, `Max-Age=0`.
pub fn clear_cookie_header() -> HeaderValue {
    HeaderValue::from_static(
        "__Host-loom_rt=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
    )
}

pub fn set_cookie_name() -> HeaderName {
    axum::http::header::SET_COOKIE
}

/// Extract the refresh-token cookie's value from the request's `Cookie`
/// header, if present. `None` for a missing `Cookie` header or one that
/// doesn't carry this cookie -- callers treat both the same as "no
/// session presented". A cookie fragment with no `=` (a stray flag-style
/// cookie some other code set) is skipped, not treated as "stop
/// looking" -- our cookie can be anywhere in the header, not just first.
pub fn refresh_token_from_cookies(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        if name == REFRESH_COOKIE_NAME {
            return Some(value.to_string());
        }
    }
    None
}

/// M-AUTH-6: `/auth/refresh` and `/auth/logout` require `Origin` to be
/// exactly one of `allowed_origins` (scheme + host + port, no path, no
/// trailing slash -- i.e. the literal value a browser sends in the
/// `Origin` header) **and** `X-Loom-Auth: 1`. Neither check alone is
/// sufficient: `Origin` can be absent from same-origin requests sent by
/// non-browser clients (so it's not phishing-proof on its own against a
/// tool that fabricates headers), and the custom header alone doesn't
/// stop a same-origin-looking fetch from a malicious subdomain -- the
/// pair of checks is what the threat model asks for.
pub fn staff_csrf_guard_passes(headers: &HeaderMap, allowed_origins: &[String]) -> bool {
    let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    if !allowed_origins.iter().any(|allowed| allowed == origin) {
        return false;
    }
    headers.get(STAFF_AUTH_HEADER).and_then(|v| v.to_str().ok()) == Some(STAFF_AUTH_HEADER_VALUE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(origin: Option<&str>, x_loom_auth: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(origin) = origin {
            headers.insert(axum::http::header::ORIGIN, origin.parse().unwrap());
        }
        if let Some(value) = x_loom_auth {
            headers.insert(STAFF_AUTH_HEADER, value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn passes_only_with_an_allowed_origin_and_the_header() {
        let allowed = vec!["https://staff.loom.example".to_string()];
        assert!(staff_csrf_guard_passes(
            &headers(Some("https://staff.loom.example"), Some("1")),
            &allowed
        ));
    }

    #[test]
    fn fails_for_a_cross_origin_request() {
        let allowed = vec!["https://staff.loom.example".to_string()];
        assert!(!staff_csrf_guard_passes(
            &headers(Some("https://evil.example"), Some("1")),
            &allowed
        ));
    }

    #[test]
    fn fails_without_the_custom_header() {
        let allowed = vec!["https://staff.loom.example".to_string()];
        assert!(!staff_csrf_guard_passes(
            &headers(Some("https://staff.loom.example"), None),
            &allowed
        ));
    }

    #[test]
    fn fails_with_no_origin_header_at_all() {
        let allowed = vec!["https://staff.loom.example".to_string()];
        assert!(!staff_csrf_guard_passes(
            &headers(None, Some("1")),
            &allowed
        ));
    }

    #[test]
    fn extracts_the_refresh_cookie_among_others() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "other=ignored; __Host-loom_rt=abc123; another=also-ignored"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            refresh_token_from_cookies(&headers).as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn extracts_the_refresh_cookie_past_a_stray_flag_style_cookie() {
        // A cookie fragment with no `=` must not short-circuit the scan
        // (OBI-198 re-review should-fix).
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "some_flag; __Host-loom_rt=abc123".parse().unwrap(),
        );
        assert_eq!(
            refresh_token_from_cookies(&headers).as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn missing_cookie_header_yields_none() {
        assert_eq!(refresh_token_from_cookies(&HeaderMap::new()), None);
    }
}
