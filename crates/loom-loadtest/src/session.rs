// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! A single bot's telnet connection: connect, negotiate, send lines, and
//! wait for a pattern (usually the `<HP/MAXHPhp> ` prompt) in the decoded
//! text stream. Mirrors `warp/tests/smoke.py`'s `Client`, in Rust, plus an
//! optional artificial read delay for the slow-reader cohort (R4 OBI-40).

use std::time::Duration;

use regex::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::telnet::{TelnetClientCodec, initial_negotiation};

#[derive(Debug)]
pub enum SessionError {
    Disconnected,
    Timeout,
    Io(std::io::Error),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Disconnected => write!(f, "connection closed"),
            SessionError::Timeout => write!(f, "timed out waiting for pattern"),
            SessionError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<std::io::Error> for SessionError {
    fn from(e: std::io::Error) -> Self {
        SessionError::Io(e)
    }
}

pub struct Session {
    stream: TcpStream,
    codec: TelnetClientCodec,
    buf: String,
    read_buf: [u8; 4096],
    /// Slow-reader cohort (R4 OBI-40): delay applied before each socket
    /// read while waiting for a response, so the server's per-connection
    /// output queue backs up (exercises `loom-net`'s bounded-queue
    /// backpressure / slow-client disconnect).
    pub read_delay: Option<Duration>,
}

impl Session {
    pub async fn connect(addr: &str, client_name: &str) -> Result<Self, SessionError> {
        let mut stream = TcpStream::connect(addr).await?;
        stream.write_all(&initial_negotiation(80, 24)).await?;
        Ok(Self {
            stream,
            codec: TelnetClientCodec::new(client_name),
            buf: String::new(),
            read_buf: [0_u8; 4096],
            read_delay: None,
        })
    }

    pub async fn send_line(&mut self, line: &str) -> Result<(), SessionError> {
        let mut out = line.as_bytes().to_vec();
        out.extend_from_slice(b"\r\n");
        self.stream.write_all(&out).await?;
        Ok(())
    }

    /// Waits for `pattern` in the accumulated (IAC-stripped) text, reading
    /// more off the socket as needed, and drains the buffer up to the end
    /// of the match on success (so the next `expect` starts clean).
    pub async fn expect(
        &mut self,
        pattern: &Regex,
        timeout: Duration,
    ) -> Result<String, SessionError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(m) = pattern.find(&self.buf) {
                let matched = m.as_str().to_string();
                self.buf.drain(..m.end());
                return Ok(matched);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SessionError::Timeout);
            }
            if let Some(delay) = self.read_delay {
                tokio::time::sleep(delay.min(remaining)).await;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SessionError::Timeout);
            }
            let n =
                match tokio::time::timeout(remaining, self.stream.read(&mut self.read_buf)).await {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return Err(SessionError::Io(e)),
                    Err(_) => return Err(SessionError::Timeout),
                };
            if n == 0 {
                return Err(SessionError::Disconnected);
            }
            let (text, response) = self.codec.feed(&self.read_buf[..n]);
            if !response.is_empty() {
                self.stream.write_all(&response).await?;
            }
            self.buf.push_str(&String::from_utf8_lossy(&text));
        }
    }

    pub async fn close(mut self) {
        let _ = self.stream.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn connect_send_and_expect_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0_u8; 256];
            // Read the client's negotiation offer, then the "look" line.
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                if buf[..n].ends_with(b"look\r\n") {
                    break;
                }
            }
            sock.write_all(b"Entrance Hall\r\n<10/10hp> ")
                .await
                .unwrap();
        });

        let mut session = Session::connect(&addr.to_string(), "botaaa").await.unwrap();
        session.send_line("look").await.unwrap();
        let prompt = Regex::new(r"<\d+/\d+hp> $").unwrap();
        let matched = session
            .expect(&prompt, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(matched, "<10/10hp> ");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn disconnect_is_reported() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = sock.shutdown().await;
        });
        let mut session = Session::connect(&addr.to_string(), "botaaa").await.unwrap();
        let prompt = Regex::new(r"<\d+/\d+hp> $").unwrap();
        let err = session
            .expect(&prompt, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(
            matches!(err, SessionError::Disconnected | SessionError::Io(_)),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn timeout_when_pattern_never_arrives() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"no prompt here").await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let mut session = Session::connect(&addr.to_string(), "botaaa").await.unwrap();
        let prompt = Regex::new(r"<\d+/\d+hp> $").unwrap();
        let err = session
            .expect(&prompt, Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(matches!(err, SessionError::Timeout));
    }
}
