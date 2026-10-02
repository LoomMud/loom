// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Optional end-of-run scrape of `loom-http`'s `/metrics` (OBI-177), so a
//! committed report can carry the server's own Prometheus counters
//! alongside the bot-side latency that E1.1 is actually measured against.
//!
//! Deliberately a raw HTTP/1.1 GET over `tokio::net::TcpStream`, not a new
//! `reqwest`/`hyper` dependency: this is a single best-effort loopback
//! request against a known-plain-text endpoint, not a general HTTP client.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Scrapes `url` (`http://host:port/path`) and returns the response body as
/// text. Only plain `http://` URLs are supported.
pub async fn scrape(url: &str) -> Result<String, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "only http:// URLs are supported".to_string())?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };

    let mut stream = TcpStream::connect(authority)
        .await
        .map_err(|e| format!("connect {authority}: {e}"))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("read: {e}"))?;
    let text = String::from_utf8_lossy(&buf);

    let (status_line, rest) = text
        .split_once("\r\n")
        .ok_or_else(|| "malformed response (no status line)".to_string())?;
    if !status_line.contains(" 200 ") {
        return Err(format!("unexpected status: {status_line}"));
    }
    let body = rest
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(rest);
    Ok(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn scrapes_body_from_a_200_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await.unwrap();
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nloom_players 150\n",
            )
            .await
            .unwrap();
        });

        let body = scrape(&format!("http://{addr}/metrics")).await.unwrap();
        assert_eq!(body, "loom_players 150\n");
    }

    #[tokio::test]
    async fn non_200_status_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await.unwrap();
            sock.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n")
                .await
                .unwrap();
        });

        let err = scrape(&format!("http://{addr}/metrics")).await.unwrap_err();
        assert!(err.contains("404"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn rejects_non_http_urls() {
        let err = scrape("https://example.com/metrics").await.unwrap_err();
        assert!(err.contains("http://"));
    }
}
