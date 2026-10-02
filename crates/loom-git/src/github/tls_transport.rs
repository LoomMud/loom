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
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::ServerName;

use super::{HttpClient, HttpError, HttpResponse};

/// Read/write/connect timeout (matches [`super::UreqClient`]'s).
const TIMEOUT: Duration = Duration::from_secs(10);

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
        let sock = TcpStream::connect((host.as_str(), port))
            .map_err(|e| HttpError(format!("connect {host}:{port}: {e}")))?;
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
        read_rest_to_end(stream, &mut body)?;
        body = dechunk(&body)?;
    } else if let Some(len) = content_length {
        while body.len() < len {
            let mut chunk = [0u8; 4096];
            let n = stream
                .read(&mut chunk)
                .map_err(|e| HttpError(format!("read response body: {e}")))?;
            if n == 0 {
                break; // server closed early; return what we have
            }
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(len);
    } else {
        read_rest_to_end(stream, &mut body)?;
    }

    Ok(HttpResponse { status, body })
}

fn read_rest_to_end(stream: &mut impl Read, buf: &mut Vec<u8>) -> Result<(), HttpError> {
    let mut chunk = [0u8; 4096];
    loop {
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

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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
}
