// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oberfield

//! Shared plumbing for the loopback fake GitHub servers every `loom-git`
//! test uses (OBI-350).
//!
//! Each fake used to do **one `read()` per connection** and answer from
//! whatever that read returned. A GitHub POST is a request line plus a
//! ~250-byte RSA JWT in `Authorization` plus a JSON body, which is
//! routinely more than one MSS, so TCP hands it over in two segments: the
//! fake saw the headers (enough to look right), answered, and stopped
//! reading -- leaving the body unread in its own receive queue. Unread
//! data at close time is what makes the kernel answer the client's FIN
//! with an **RST**, and `ureq` turns that into an io error, which
//! `GitHubAppClient` maps to [`crate::github::GitHubAppError::Transport`].
//! So a test that wanted to prove a *payload* failure (`BadResponse`) got
//! a *connection* failure instead -- intermittently, on a runner busy
//! enough to schedule the fake between the two segments. That is the
//! `unparseable_body_is_a_clear_error` flake.
//!
//! The rule this module encodes: **serve a complete request, then close
//! gracefully.** Read until the header block terminator, then until
//! `Content-Length` bytes of body have arrived; write the response;
//! `shutdown(Write)` and drain to the client's FIN. Everything is bounded
//! (read timeout, byte caps) so a misbehaving or silent client costs one
//! dropped connection instead of a wedged accept loop.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

/// How long to wait for the next segment of a request before giving up on
/// that connection.
///
/// This is patience the *fake* owes a client whose request is still in
/// flight. Under the old single-threaded accept loop it was also a tax every
/// other connection paid -- a stalled client cost the whole suite this much
/// queue time -- which is why it was 2 s. It is now per connection
/// ([`crate::github::fake_server`], OBI-351), so an honest two-segment POST
/// (headers, then a body the scheduler has not handed over yet) is never
/// answered as if it were malformed, and a stalled client costs only its own
/// connection.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for the client's remaining bytes / FIN after the
/// response has been written.
const DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// Ceiling on the bytes read for one request (and on the bytes drained
/// after the response), so no client can make the fake spin or allocate
/// without limit.
const MAX_BYTES: usize = 1 << 20;

/// One complete HTTP/1.1 request as the fake served it.
#[derive(Debug, Clone)]
pub struct FakeRequest {
    /// The whole request exactly as served: header block, the `\r\n\r\n`
    /// terminator, then the body. Tests assert on this to prove nothing
    /// was lost.
    pub raw: String,
    /// `POST` / `GET`.
    pub method: String,
    /// The request target from the request line.
    pub path: String,
    /// The bytes after the header block terminator (`""` when the request
    /// declares no body).
    pub body: String,
}

/// Read one complete request off `stream`, with the default patience
/// ([`READ_TIMEOUT`]).
///
/// Returns `None` if the client hangs up, stalls past the patience window,
/// or exceeds [`MAX_BYTES`] before the request is complete. A caller that
/// stops reading here still owes the client an answer -- see
/// [`crate::github::fake_server::FakeHttpServer`] (OBI-351), which answers
/// `400` and records the drop instead of closing in silence.
pub fn read_request(stream: &mut TcpStream) -> Option<FakeRequest> {
    read_request_within(stream, READ_TIMEOUT)
}

/// [`read_request`] with an explicit patience window, for the tests that
/// need to watch the fake give up on a stalled client without waiting out
/// [`READ_TIMEOUT`] (a test that races a constant is a coin flip).
pub fn read_request_within(stream: &mut TcpStream, patience: Duration) -> Option<FakeRequest> {
    let _ = stream.set_read_timeout(Some(patience));
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];

    // 1. The header block: keep reading until the blank line, not until
    //    the kernel happens to have something to hand us.
    let headers_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() >= MAX_BYTES {
            return None;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };

    // 2. The body: `Content-Length` bytes, however many segments they
    //    arrive in. Truncating here is the bug this module exists to fix.
    let head = String::from_utf8_lossy(&buf[..headers_end - 4]).into_owned();
    let content_length = content_length_of(&head);
    while buf.len() < headers_end + content_length && buf.len() < MAX_BYTES {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }

    let body = String::from_utf8_lossy(&buf[headers_end.min(buf.len())..]).into_owned();
    let mut request_line = head.lines().next().unwrap_or("").split_whitespace();
    Some(FakeRequest {
        raw: format!("{head}\r\n\r\n{body}"),
        method: request_line.next().unwrap_or("").to_string(),
        path: request_line.next().unwrap_or("").to_string(),
        body,
    })
}

/// Write `body` as an HTTP/1.1 response with `status`, then close the way
/// a real server does. The closing half matters as much as the reading
/// half: see the module docs.
pub fn respond(stream: &mut TcpStream, status: u16, body: &str) {
    let status_text = status_text(status);
    let resp = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    );
    if stream.write_all(resp.as_bytes()).is_err() {
        return;
    }
    if stream.write_all(body.as_bytes()).is_err() {
        return;
    }
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Write);
    // Drain to the client's FIN. Anything still in flight (or still queued
    // unread on our side) is what would earn the client an RST instead of a
    // clean close; the bound means a client that never closes costs one
    // timeout, not a hung suite.
    let _ = stream.set_read_timeout(Some(DRAIN_TIMEOUT));
    let mut sink = [0u8; 1024];
    let mut drained = 0usize;
    while drained < MAX_BYTES {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

/// The reason phrase for the handful of statuses these fakes hand back.
/// Nothing in the crate asserts on these strings -- `GitHubAppClient`
/// looks at the status *code* -- but keeping them real makes a captured
/// exchange readable.
fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn content_length_of(head: &str) -> usize {
    head.lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        // A repeated `Content-Length` is only legal when the values agree,
        // so taking the last one is enough for a test fake.
        .last()
        .unwrap_or(0)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// A listener that reads one request per connection and records what the
    /// reader returned, so the reader can be tested directly (with no
    /// `GitHubAppClient` in the way).
    ///
    /// `patience` is the reader's own deadline: `None` means the fake's normal
    /// patience ([`read_request`], the wrapper every real fake server runs),
    /// and the one test that proves the reader *gives up* passes a window of its
    /// own so it neither waits 10 s nor hopes.
    fn spawn_recorder(
        patience: Option<Duration>,
    ) -> (String, Arc<Mutex<Vec<Option<FakeRequest>>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let served: Arc<Mutex<Vec<Option<FakeRequest>>>> = Arc::new(Mutex::new(Vec::new()));
        let served_clone = served.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let req = match patience {
                    Some(patience) => read_request_within(&mut stream, patience),
                    None => read_request(&mut stream),
                };
                let body = req
                    .as_ref()
                    .map(|r| format!("path={} body={}", r.path, r.body))
                    .unwrap_or_else(|| "none".to_string());
                served_clone.lock().unwrap().push(req);
                respond(&mut stream, 201, &body);
            }
        });
        (addr, served)
    }

    fn connect(addr: &str) -> TcpStream {
        let stream = TcpStream::connect(addr).unwrap();
        // Keep separate writes in separate segments (no Nagle), and bound
        // the read so a broken fake fails an assertion instead of hanging.
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
    }

    fn served_once(served: &Arc<Mutex<Vec<Option<FakeRequest>>>>) -> FakeRequest {
        let guard = served.lock().unwrap();
        match guard.as_slice() {
            [Some(req)] => req.clone(),
            other => panic!("expected exactly one served request, got {other:?}"),
        }
    }

    #[test]
    fn reader_waits_for_a_body_that_arrives_as_a_second_segment() {
        let (addr, served) = spawn_recorder(None);
        let mut stream = connect(&addr);
        stream
            .write_all(b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\n")
            .unwrap();
        stream.flush().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        stream.write_all(b"hello").unwrap();

        let mut resp = String::new();
        // `read_to_string` ends at the fake's FIN. An RST here is exactly
        // the symptom OBI-350 was filed for, so this unwrap is an
        // assertion, not a convenience.
        stream.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("201 Created"), "response was {resp:?}");

        let req = served_once(&served);
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/x");
        assert_eq!(req.body, "hello");
        assert_eq!(
            req.raw,
            "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"
        );
    }

    #[test]
    fn reader_serves_a_request_split_across_three_segments() {
        let (addr, served) = spawn_recorder(None);
        let mut stream = connect(&addr);
        for part in [
            "POST /repos/a/b/pulls HTTP/1.1\r\nContent-Length: 17\r\n",
            "Content-Type: application/json\r\n\r\n{\"title\":",
            "\"thing\"}",
        ] {
            stream.write_all(part.as_bytes()).unwrap();
            stream.flush().unwrap();
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        assert_eq!(served_once(&served).body, r#"{"title":"thing"}"#);
    }

    #[test]
    fn reader_treats_a_get_with_no_body_as_complete() {
        let (addr, served) = spawn_recorder(None);
        let mut stream = connect(&addr);
        stream.write_all(b"GET /y HTTP/1.1\r\n\r\n").unwrap();
        stream.flush().unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        let req = served_once(&served);
        assert_eq!(req.path, "/y");
        assert_eq!(req.body, "");
        assert!(req.raw.ends_with("\r\n\r\n"), "raw was {:?}", req.raw);
    }

    #[test]
    fn reader_gives_up_on_a_client_that_never_finishes_the_headers() {
        // The bound is the point: a client that sends no `\r\n\r\n` must
        // not keep the fake reading forever. The fake's patience is set
        // *here*, and the deadline below is that patience plus a wide
        // margin, so the test measures the bound instead of racing it.
        const PATIENCE: Duration = Duration::from_millis(200);
        let (addr, served) = spawn_recorder(Some(PATIENCE));
        let mut stream = connect(&addr);
        stream.write_all(b"GET /z HTTP/1.1\r\n").unwrap();
        stream.flush().unwrap();

        let deadline = std::time::Instant::now() + PATIENCE + Duration::from_secs(5);
        while served.lock().unwrap().is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "the reader never gave up on a stalled request"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            served.lock().unwrap()[0].is_none(),
            "a stalled request must read as no request at all"
        );
    }

    #[test]
    fn content_length_is_case_insensitive_and_optional() {
        assert_eq!(
            content_length_of("POST /x HTTP/1.1\r\ncontent-length: 7"),
            7
        );
        assert_eq!(
            content_length_of("POST /x HTTP/1.1\r\nContent-Length: 7"),
            7
        );
        assert_eq!(content_length_of("GET /x HTTP/1.1\r\nAccept: */*"), 0);
        assert_eq!(content_length_of("GET /x HTTP/1.1\r\nX-Weird: 3"), 0);
    }
}
