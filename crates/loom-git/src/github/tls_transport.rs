// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The production [`super::HttpClient`] transport (D-B3.11, OBI-215):
//! `rustls` with the `ring` crypto provider (the same backend
//! `github::jwt` signs with), over a hand-rolled minimal HTTP/1.1 client
//! -- not `ureq`'s own `tls` feature, because that feature's bundled
//! root store (the `webpki-roots` crate) ships under
//! CDLA-Permissive-2.0, a data licence this workspace's OSI-only licence
//! gate does not allow (`deny.toml`, OBI-44). `rustls-native-certs`'
//! platform root store has no such issue, so this client dials straight
//! `rustls` + `std::net::TcpStream`.
//!
//! The requests this crate makes are narrow by design (GET/POST a small
//! JSON body to a fixed, trusted host, no redirects, no cookies, no
//! connection pooling), which is what keeps hand-rolling HTTP/1.1
//! reasonable here instead of pulling in a general-purpose HTTP stack.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::ServerName;

use super::{HttpClient, HttpError, HttpResponse, find_subslice};

/// Read/write/connect timeout (matches [`super::UreqClient`]'s).
const TIMEOUT: Duration = Duration::from_secs(10);

/// Hard cap on response header bytes (status line + headers, up to and
/// including the terminating blank line) -- a well-behaved GitHub API
/// response is a few hundred bytes of headers; anything past 64 KiB is
/// either a misbehaving peer or an attempt to exhaust memory on an
/// unbounded read.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Hard cap on response body bytes. The GitHub REST responses this
/// crate parses (installation tokens, PR-create results) are tiny; 8
/// MiB is generous headroom while still bounding a slow or malicious
/// peer's ability to make this client buffer an unbounded body.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// A minimal HTTP/1.1-over-`rustls` client. Build one with
/// [`RustlsHttpClient::default`] for the real platform root store
/// (production), or [`RustlsHttpClient::with_root_store`] to pin a
/// specific trust root (tests).
pub struct RustlsHttpClient {
    config: Arc<ClientConfig>,
}

impl Default for RustlsHttpClient {
    /// Trusts the platform's native certificate store
    /// (`rustls-native-certs`) -- what a real deployment needs to reach
    /// `https://api.github.com`.
    fn default() -> Self {
        let mut roots = RootCertStore::empty();
        let loaded = rustls_native_certs::load_native_certs();
        for cert in loaded.certs {
            // A handful of platform cert stores carry certificates
            // `rustls`'s (intentionally strict) parser rejects; skipping
            // those entries matches `rustls-native-certs`' own documented
            // guidance and still leaves every other root usable.
            let _ = roots.add(cert);
        }
        for err in loaded.errors {
            tracing::warn!(error = %err, "skipped unreadable native certificate");
        }
        Self::with_root_store(roots)
    }
}

impl RustlsHttpClient {
    /// Builds a client trusting exactly `roots` -- the test seam (a
    /// loopback TLS server's self-signed certificate as its own root),
    /// never used in production.
    pub fn with_root_store(roots: RootCertStore) -> Self {
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            config: Arc::new(config),
        }
    }

    fn request(
        &self,
        method: &str,
        url: &str,
        bearer: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, HttpError> {
        let parsed = url::Url::parse(url).map_err(|e| HttpError(format!("bad URL {url}: {e}")))?;
        if parsed.scheme() != "https" {
            return Err(HttpError(format!(
                "refusing non-https URL: {url} (scheme {:?})",
                parsed.scheme()
            )));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| HttpError(format!("URL has no host: {url}")))?
            .to_string();
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| HttpError(format!("URL has no resolvable port: {url}")))?;
        let path = {
            let mut p = parsed.path().to_string();
            if let Some(q) = parsed.query() {
                p.push('?');
                p.push_str(q);
            }
            p
        };

        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| HttpError(format!("bad TLS server name {host}: {e}")))?;
        let conn = ClientConnection::new(self.config.clone(), server_name)
            .map_err(|e| HttpError(format!("TLS setup: {e}")))?;
        let sock = connect_with_timeout(&host, port, TIMEOUT)?;
        sock.set_read_timeout(Some(TIMEOUT))
            .map_err(|e| HttpError(e.to_string()))?;
        sock.set_write_timeout(Some(TIMEOUT))
            .map_err(|e| HttpError(e.to_string()))?;
        let mut tls = StreamOwned::new(conn, sock);

        let mut request = format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Authorization: Bearer {bearer}\r\n\
             Accept: application/vnd.github+json\r\n\
             X-GitHub-Api-Version: 2022-11-28\r\n\
             User-Agent: loom-git\r\n\
             Connection: close\r\n"
        );
        if let Some(body) = body {
            request.push_str("Content-Type: application/json\r\n");
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        request.push_str("\r\n");

        tls.write_all(request.as_bytes())
            .map_err(|e| HttpError(format!("write request: {e}")))?;
        if let Some(body) = body {
            tls.write_all(body)
                .map_err(|e| HttpError(format!("write body: {e}")))?;
        }

        read_response(&mut tls)
    }
}

impl HttpClient for RustlsHttpClient {
    fn post(&self, url: &str, bearer: &str, body: &[u8]) -> Result<HttpResponse, HttpError> {
        self.request("POST", url, bearer, Some(body))
    }

    fn get(&self, url: &str, bearer: &str) -> Result<HttpResponse, HttpError> {
        self.request("GET", url, bearer, None)
    }
}

/// Resolves `host:port` and connects with a bounded per-address timeout,
/// trying each resolved address in turn -- plain `TcpStream::connect`
/// has no timeout at all and can hang far past [`TIMEOUT`] against an
/// unresponsive or firewalled address.
fn connect_with_timeout(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, HttpError> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| HttpError(format!("resolve {host}:{port}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(HttpError(format!("no addresses for {host}:{port}")));
    }
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(sock) => return Ok(sock),
            Err(e) => last_err = Some(e),
        }
    }
    Err(HttpError(format!(
        "connect {host}:{port}: {}",
        last_err.expect("at least one address was tried")
    )))
}

/// Reads an HTTP/1.1 response: status line, headers (just far enough to
/// find `Content-Length` or `Transfer-Encoding: chunked`), and the body.
/// Falls back to "read until the server closes the connection" when
/// neither header is present -- safe here because every request sends
/// `Connection: close`.
fn read_response(stream: &mut impl Read) -> Result<HttpResponse, HttpError> {
    let mut buf = Vec::new();
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() >= MAX_HEADER_BYTES {
            return Err(HttpError(format!(
                "response headers exceeded {MAX_HEADER_BYTES} bytes without a terminating blank line"
            )));
        }
        let mut chunk = [0u8; 4096];
        let n = stream
            .read(&mut chunk)
            .map_err(|e| HttpError(format!("read response headers: {e}")))?;
        if n == 0 {
            return Err(HttpError(
                "connection closed before headers completed".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let header_text = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| HttpError(format!("unparseable status line: {status_line:?}")))?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        if let Some(v) = case_insensitive_strip_prefix(line, "content-length:") {
            content_length = v.trim().parse().ok();
        } else if let Some(v) = case_insensitive_strip_prefix(line, "transfer-encoding:") {
            chunked = v.trim().eq_ignore_ascii_case("chunked");
        }
    }

    let mut body = buf.split_off(header_end);
    if chunked {
        // The raw chunked bytes are read until the peer closes the
        // connection (every request here sends `Connection: close`);
        // an early close -- including one that surfaces as
        // `UnexpectedEof` rather than a clean TCP close -- is tolerated
        // here because `dechunk` below only succeeds if it finds a
        // well-formed terminating zero-size chunk, so a truncated
        // stream still surfaces as an error, just from `dechunk`
        // instead of the read.
        read_rest_to_end(stream, &mut body, MAX_BODY_BYTES)?;
        body = dechunk(&body)?;
    } else if let Some(len) = content_length {
        if len > MAX_BODY_BYTES {
            return Err(HttpError(format!(
                "response Content-Length {len} exceeds the {MAX_BODY_BYTES}-byte cap"
            )));
        }
        read_exact_body(stream, &mut body, len)?;
    } else {
        // No length information at all: the only way to know the body
        // is complete is the peer closing the connection, so an
        // `UnexpectedEof`-as-close is tolerated here too, same as the
        // chunked path.
        read_rest_to_end(stream, &mut body, MAX_BODY_BYTES)?;
    }

    Ok(HttpResponse { status, body })
}

/// Reads until `buf` holds exactly `len` bytes, treating *any* early
/// close -- a clean `Ok(0)` or an `UnexpectedEof` I/O error -- as a
/// truncated response and returning an error, since `Content-Length`
/// makes the expected size unambiguous (unlike the chunked/no-length
/// paths, where [`read_rest_to_end`] tolerates an EOF-shaped close as
/// the end-of-body signal).
fn read_exact_body(stream: &mut impl Read, buf: &mut Vec<u8>, len: usize) -> Result<(), HttpError> {
    buf.reserve(len.saturating_sub(buf.len()));
    while buf.len() < len {
        let mut chunk = [0u8; 4096];
        let want = (len - buf.len()).min(chunk.len());
        let read_result = stream.read(&mut chunk[..want]);
        let n = match read_result {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(HttpError(format!(
                    "response body truncated: expected {len} bytes, connection closed after {}",
                    buf.len()
                )));
            }
            Err(e) => return Err(HttpError(format!("read response body: {e}"))),
        };
        if n == 0 {
            return Err(HttpError(format!(
                "response body truncated: expected {len} bytes, connection closed after {}",
                buf.len()
            )));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(())
}

/// Reads until the peer closes the connection or `buf` reaches `cap`
/// bytes, whichever comes first. An `UnexpectedEof` arriving instead of
/// a clean `Ok(0)` is treated the same as a clean close here: a client
/// that sent `Connection: close` has no length to check completeness
/// against anyway, so this is only ever called from paths where the
/// caller independently verifies the body is complete (chunked
/// framing's terminating zero-size chunk) or where there was never any
/// length to be truncated against in the first place.
fn read_rest_to_end(
    stream: &mut impl Read,
    buf: &mut Vec<u8>,
    cap: usize,
) -> Result<(), HttpError> {
    let mut chunk = [0u8; 4096];
    loop {
        if buf.len() >= cap {
            return Err(HttpError(format!(
                "response body exceeded the {cap}-byte cap"
            )));
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            // `close_notify` arriving as a transport-level EOF-like error is
            // a normal, successful close for a client that asked for
            // `Connection: close`, not a transport failure.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(HttpError(format!("read response body: {e}"))),
        }
    }
}

fn dechunk(input: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    let mut rest = input;
    loop {
        let line_end = find_subslice(rest, b"\r\n")
            .ok_or_else(|| HttpError("truncated chunked body (no size line)".into()))?;
        let size_line = String::from_utf8_lossy(&rest[..line_end]);
        let size_str = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|e| HttpError(format!("bad chunk size {size_str:?}: {e}")))?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size + 2 {
            return Err(HttpError("truncated chunked body (short chunk)".into()));
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..]; // skip the chunk's trailing CRLF
    }
    Ok(out)
}

fn case_insensitive_strip_prefix<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    if line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&line[prefix.len()..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    use std::net::TcpListener;

    const TEST_CERT_PEM: &[u8] = include_bytes!("testdata/test_tls_cert.pem");
    const TEST_KEY_PEM: &[u8] = include_bytes!("testdata/test_tls_key.pem");

    /// A loopback TLS server trusting only the test fixture's own
    /// self-signed certificate -- so `RustlsHttpClient` exercises a real
    /// TLS 1.2/1.3 handshake, not just the plain-HTTP path `UreqClient`'s
    /// tests use, without depending on the network or a real CA.
    fn spawn_tls_server(
        mut respond: impl FnMut(&str) -> (u16, &'static str, Vec<u8>) + Send + 'static,
    ) -> (String, RootCertStore) {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(TEST_CERT_PEM)
            .collect::<Result<_, _>>()
            .unwrap();
        let key =
            rustls_pki_types::PrivateKeyDer::from_pem_slice(TEST_KEY_PEM).expect("test key PEM");

        let mut trust_roots = RootCertStore::empty();
        for cert in &certs {
            trust_roots.add(cert.clone()).unwrap();
        }

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("valid test server cert/key");
        let server_config = Arc::new(server_config);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let sock = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let conn = match rustls::ServerConnection::new(server_config.clone()) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let mut tls = StreamOwned::new(conn, sock);

                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let header_end = loop {
                    if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                        break pos + 4;
                    }
                    match tls.read(&mut chunk) {
                        Ok(0) | Err(_) => break 0,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };
                if header_end == 0 {
                    continue;
                }
                let req_text = String::from_utf8_lossy(&buf[..header_end]).into_owned();
                let path = req_text
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("")
                    .to_string();
                let (status, status_text, body) = respond(&path);
                let resp = format!(
                    "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes());
                let _ = tls.write_all(&body);
            }
        });
        (addr.to_string(), trust_roots)
    }

    #[test]
    fn https_get_round_trips_status_and_body() {
        let (addr, roots) = spawn_tls_server(|_path| (200, "OK", br#"{"ok":true}"#.to_vec()));
        let client = RustlsHttpClient::with_root_store(roots);
        let resp = client
            .get(
                &format!(
                    "https://localhost:{}/hello",
                    addr.rsplit(':').next().unwrap()
                ),
                "tok",
            )
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, br#"{"ok":true}"#);
    }

    #[test]
    fn https_post_sends_body_and_bearer_and_reports_path() {
        let seen_path = Arc::new(std::sync::Mutex::new(String::new()));
        let seen_path_clone = seen_path.clone();
        let (addr, roots) = spawn_tls_server(move |path| {
            *seen_path_clone.lock().unwrap() = path.to_string();
            (201, "Created", br#"{"created":true}"#.to_vec())
        });
        let client = RustlsHttpClient::with_root_store(roots);
        let port = addr.rsplit(':').next().unwrap();
        let resp = client
            .post(
                &format!("https://localhost:{port}/repos/x/y/pulls"),
                "my-jwt",
                br#"{"title":"t"}"#,
            )
            .unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(resp.body, br#"{"created":true}"#);
        assert_eq!(*seen_path.lock().unwrap(), "/repos/x/y/pulls");
    }

    #[test]
    fn non_2xx_status_is_still_a_parsed_response_not_an_error() {
        let (addr, roots) =
            spawn_tls_server(|_path| (401, "Unauthorized", br#"{"message":"bad creds"}"#.to_vec()));
        let client = RustlsHttpClient::with_root_store(roots);
        let port = addr.rsplit(':').next().unwrap();
        let resp = client
            .get(&format!("https://localhost:{port}/x"), "tok")
            .unwrap();
        assert_eq!(resp.status, 401);
        assert!(String::from_utf8_lossy(&resp.body).contains("bad creds"));
    }

    #[test]
    fn untrusted_server_certificate_is_rejected() {
        // A client with an *empty* trust store must not accept the test
        // server's self-signed certificate -- the whole point of pinning
        // `with_root_store` in the other tests.
        let (addr, _roots) = spawn_tls_server(|_path| (200, "OK", b"{}".to_vec()));
        let client = RustlsHttpClient::with_root_store(RootCertStore::empty());
        let port = addr.rsplit(':').next().unwrap();
        assert!(
            client
                .get(&format!("https://localhost:{port}/x"), "tok")
                .is_err()
        );
    }

    #[test]
    fn dechunk_handles_multiple_chunks_and_trailer() {
        let chunked = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(dechunk(chunked).unwrap(), b"Wikipedia");
    }

    #[test]
    fn non_https_url_is_rejected_before_any_connection_is_attempted() {
        // No network I/O should happen at all for a rejected scheme --
        // this doesn't even need a running server.
        let client = RustlsHttpClient::with_root_store(RootCertStore::empty());
        let err = client
            .get("http://localhost:1/x", "tok")
            .expect_err("plain-http URL must be rejected");
        assert!(err.0.contains("non-https"), "got: {}", err.0);
    }

    #[test]
    fn content_length_early_close_is_an_error_not_a_silent_truncation() {
        // Full headers claiming a 100-byte body, but the connection
        // supplies only 5 bytes before EOF -- must surface as an error,
        // not a silently short-truncated `Ok` response.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhello";
        let err =
            read_response(&mut std::io::Cursor::new(&raw[..])).expect_err("must be truncated");
        assert!(err.0.contains("truncated"), "got: {}", err.0);
    }

    #[test]
    fn content_length_above_cap_is_rejected_up_front() {
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let err = read_response(&mut std::io::Cursor::new(raw.as_bytes()))
            .expect_err("oversized Content-Length must be rejected");
        assert!(err.0.contains("exceeds"), "got: {}", err.0);
    }

    #[test]
    fn content_length_body_delivered_in_full_is_accepted() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let resp = read_response(&mut std::io::Cursor::new(&raw[..])).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello");
    }

    #[test]
    fn oversized_header_section_is_rejected() {
        // No `\r\n\r\n` terminator anywhere, well past `MAX_HEADER_BYTES`.
        let raw = vec![b'a'; MAX_HEADER_BYTES + 1];
        let err = read_response(&mut std::io::Cursor::new(&raw[..]))
            .expect_err("oversized unterminated headers must be rejected");
        assert!(err.0.contains("headers"), "got: {}", err.0);
    }

    #[test]
    fn oversized_unbounded_body_is_rejected() {
        // No Content-Length, no chunked encoding: body is read until the
        // cap, which this input exceeds without ever closing.
        let mut raw = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        raw.extend(std::iter::repeat_n(b'x', MAX_BODY_BYTES + 1));
        let err = read_response(&mut std::io::Cursor::new(&raw[..]))
            .expect_err("oversized unbounded body must be rejected");
        assert!(err.0.contains("cap"), "got: {}", err.0);
    }
}
