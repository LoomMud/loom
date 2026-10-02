// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Client IP resolution for rate limiting and audit (OBI-200, design
//! threat model §6.1, M-AUTH-1).
//!
//! ## The port-8080 invariant
//!
//! [`client_ip`] trusts `X-Forwarded-For` **unconditionally** -- it does
//! not check a trusted-proxy allowlist or a hop count. That is only safe
//! because of an invariant that must hold for the whole lifetime of this
//! process: **the TCP port `loom-http` listens on is reachable from
//! Caddy alone.** In every deployed environment (compose, staging) that
//! port is not published to the host network or the internet (see
//! `docs/threat-model-phase2.md` §6.1 TB1 and `loom-gitops/staging/
//! compose.yaml`) -- Caddy is the only process that can ever open a TCP
//! connection to it, so Caddy is the only process that can ever set this
//! header on a request this function sees. A client cannot "forge" XFF
//! here in the sense that matters for the rate limiter: it can only ever
//! supply the one hop Caddy itself adds (Caddy's `reverse_proxy`
//! overwrites/appends, it does not blindly forward a client-supplied
//! value), so the header always carries Caddy's own value for the
//! connecting client's address.
//!
//! **If this ever changes** -- the port is exposed directly, a second
//! load balancer is added in front of Caddy, or this binary starts
//! listening on a publicly reachable interface without a proxy in front
//! of it -- this function must change too (verified `trusted_proxies` /
//! hop-count checking, like Caddy itself does), or any client can spoof
//! its IP and walk straight through the per-IP rate limiter.
//!
//! Falls back to the TCP peer address (`ConnectInfo`) when the header is
//! absent or unparseable, which is what every connection looks like
//! without Caddy in front of it (direct `loom-cli` use in dev/tests).

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;

const FORWARDED_FOR_HEADER: &str = "x-forwarded-for";

/// Resolve the address a login/TOTP attempt should be rate-limited and
/// audited under: the leftmost `X-Forwarded-For` entry (the original
/// client, per the port-8080 invariant documented above), or the TCP
/// peer address if the header is missing/unparseable.
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<IpAddr> {
    if let Some(value) = headers.get(FORWARDED_FOR_HEADER)
        && let Ok(value) = value.to_str()
        && let Some(first) = value.split(',').next()
        && let Ok(ip) = first.trim().parse::<IpAddr>()
    {
        return Some(ip);
    }
    peer.map(|addr| addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(xff: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_FOR_HEADER, xff.parse().unwrap());
        headers
    }

    #[test]
    fn prefers_the_leftmost_xff_entry() {
        let headers = headers_with("203.0.113.9, 10.0.0.1");
        assert_eq!(
            client_ip(&headers, None),
            Some("203.0.113.9".parse().unwrap())
        );
    }

    #[test]
    fn falls_back_to_the_peer_address_without_xff() {
        let headers = HeaderMap::new();
        let peer: SocketAddr = "198.51.100.5:4321".parse().unwrap();
        assert_eq!(
            client_ip(&headers, Some(peer)),
            Some("198.51.100.5".parse().unwrap())
        );
    }

    #[test]
    fn falls_back_to_the_peer_address_on_an_unparseable_header() {
        let headers = headers_with("not-an-ip");
        let peer: SocketAddr = "198.51.100.6:4321".parse().unwrap();
        assert_eq!(
            client_ip(&headers, Some(peer)),
            Some("198.51.100.6".parse().unwrap())
        );
    }

    #[test]
    fn no_header_and_no_peer_is_none() {
        let headers = HeaderMap::new();
        assert_eq!(client_ip(&headers, None), None);
    }
}
