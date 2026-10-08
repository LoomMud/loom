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

/// Every `loom_runtime_errors_total{program="..."} <count>` group in a
/// scraped `/metrics` body, biggest first (OBI-324).
///
/// The counter is the driver's own record of an *uncaught* Weft error that
/// escaped a top-level execution (`crate::errors`' M-ERR-1 rule: the label
/// is the innermost frame's declaring program), so a non-zero count means a
/// live object threw during a real player-facing command -- not a slow
/// command, a thrown one. The E1.1 latency numbers cannot see that at all,
/// which is why the report carries this separately and `--fail-on-runtime-
/// errors` can gate on it.
///
/// Deliberately tolerant: a scrape of a server that never recorded an error
/// renders an empty body, a missing counter means zero errors (not a parse
/// failure), and anything unparseable on a `loom_runtime_errors_total` line
/// is skipped rather than panicking the harness.
pub fn runtime_errors(body: &str) -> Vec<(String, u64)> {
    let mut groups: Vec<(String, u64)> = body
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let rest = line
                .strip_prefix("loom_runtime_errors_total")?
                // Our series always carry the `program` label. Requiring the
                // `{` here also rejects the exposition format's companion
                // series (`loom_runtime_errors_total_created`, `_sum`), which
                // are not error counts.
                .strip_prefix('{')?;
            // `{program="/std/player"} 150` -- the label set may one day
            // carry more labels, so read the `program="..."` value out of
            // it rather than assuming it is the only one.
            let (labels, value) = rest.split_once('}')?;
            let program = labels
                .split(',')
                .find_map(|pair| pair.trim().strip_prefix("program=\""))?
                .trim_end_matches('"')
                .to_string();
            let count = value.split_whitespace().next()?.parse::<f64>().ok()?;
            Some((program, count as u64))
        })
        .collect();
    groups.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    groups
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

    /// The exact two lines every `loadtest-e1-1` report carried from
    /// OBI-324's filing until the fix: one `/std/player` error per player.
    #[test]
    fn parses_the_runtime_error_groups_a_real_scrape_carries() {
        let body = "# TYPE loom_runtime_errors_total counter\n\
                    loom_runtime_errors_total{program=\"/std/player\"} 150\n\n";
        assert_eq!(runtime_errors(body), vec![("/std/player".into(), 150)]);
    }

    /// No counter (a server that recorded nothing renders an empty body,
    /// and a healthy scrape carries other metrics) means zero errors, not a
    /// parse error -- the gate must not fire on "nothing to read".
    #[test]
    fn a_scrape_without_the_counter_is_zero_errors() {
        assert!(runtime_errors("").is_empty());
        assert!(runtime_errors("loom_players 150\n# TYPE x counter\n").is_empty());
    }

    /// Multiple programs are reported worst-first, an extra label on the
    /// series does not hide it, and a garbage sample value is skipped.
    #[test]
    fn sorts_by_count_then_program_and_skips_unparseable_lines() {
        let body = "loom_runtime_errors_total{program=\"/std/item\"} 2\n\
                    loom_runtime_errors_total{program=\"/domains/valley/npc\"} 41\n\
                    loom_runtime_errors_total{program=\"/secure/master\",tier=\"0\"} 7\n\
                    loom_runtime_errors_total{program=\"/broken\"} not-a-number\n";
        assert_eq!(
            runtime_errors(body),
            vec![
                ("/domains/valley/npc".into(), 41),
                ("/secure/master".into(), 7),
                ("/std/item".into(), 2),
            ]
        );
    }
}
