// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! One socket reader, shared by every `loom-cli` integration test that talks to a
//! real `loom serve` child (OBI-355).
//!
//! Each test file used to carry its own copy of `read_until_contains`. Five copies
//! drifted into the same bug: they read the child's socket with `read_line`, which
//! validates UTF-8, while `loom serve` speaks **telnet** on that socket. The
//! connection preamble is IAC negotiation, and `drain_telnet_preamble` in each test
//! consumes a hard-coded **12 bytes** of it. 12 is the opening option offer in
//! `loom-net/src/telnet.rs` (`IAC DO NAWS`, `IAC DO TTYPE`, `IAC WILL GMCP`,
//! `IAC WILL MSSP` -- three bytes each). It stops being the whole preamble the moment
//! the server also wants something in that first flush: `set_echo` adds `IAC WILL
//! ECHO`, the TTYPE cycle adds `IAC SB TTYPE SEND IAC SE`, an MSSP push is longer
//! still. Whatever overflows 12 bytes then sits in the socket, `read_line` rejects it
//! with `ErrorKind::InvalidData` ("stream did not contain valid UTF-8"), the
//! helpers' catch-all arm panics, and a test about copyover or heartbeat timing goes
//! red because the child said something binary. That is
//! `reclaim_and_readopt_round_trip_keeps_the_connection_alive` failing CI twice on
//! heads whose own code was fine.
//!
//! The contract here is the one OBI-351 set for loom-git's fake servers, applied to
//! this side of the socket: **the harness may not invent a failure, and when it does
//! fail the message has to say what it saw.** So everything below reads bytes, keeps
//! a lossy transcript, and treats encoding as not its business. Framing is unchanged
//! -- a full read still blocks on a newline, so a needle never sees a line
//! half-consumed under it.
//!
//! Included by each test crate with `#[path]`; its own behaviour is proven in
//! `tests/read_until_harness.rs`.
//!
//! Deliberately *not* modelled here: a telnet client that answers negotiation, or one
//! that parses IAC out of the transcript before matching. The tests only ever
//! substring-match text, so swallowing the binary is enough, and a fake codec would be
//! a second implementation to keep in sync with `loom-net`. How much binary telnet
//! these tests should model is OBI-355's open design question for review; the
//! leftover-bytes path above is what keeps that choice from costing us red CI in the
//! meantime.

#![allow(dead_code)] // included by `#[path]` into several test binaries, each using a subset

use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// The length of `loom serve`'s opening telnet option offer, which every test connection
/// has to get past before there is any text on the wire (see the module docs).
const PREAMBLE_BYTES: usize = 12;

/// One read attempt against the child's socket, as data rather than as a panic.
#[derive(Debug)]
pub enum Chunk {
    /// Whatever the socket delivered, lossy-decoded and CRLF-normalised. Ends with
    /// `\n` unless the read timed out with a partial line in hand -- callers that need
    /// whole lines check for the newline instead of assuming it.
    Data(String),
    /// The child closed the connection. A real product event, so it is never confused
    /// with a harness problem.
    Closed,
    /// Nothing arrived before the socket's read timeout. That is the harness's own
    /// patience, not the child answering wrongly.
    Idle,
    /// The socket failed for a reason that is not "nothing yet" (`ConnectionReset`,
    /// a short read, whatever). Carries the OS error text so the caller's message can
    /// name the failure that actually occurred.
    Failed(String),
}

/// Read one chunk from the child's socket without ever failing on encoding.
///
/// Bytes that arrived before a timeout are returned (in `Chunk::Data`), not dropped:
/// the `read_line` version lost exactly the line a test was waiting for whenever a
/// timeout landed mid-line.
pub fn read_one(reader: &mut BufReader<TcpStream>) -> Chunk {
    let mut buf: Vec<u8> = Vec::new();
    match reader.read_until(b'\n', &mut buf) {
        Ok(0) => Chunk::Closed,
        Ok(_) => Chunk::Data(lossy(&buf)),
        // A read timeout is the harness's patience running out, not the child
        // answering wrongly.
        Err(err) if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
            if buf.is_empty() {
                Chunk::Idle
            } else {
                Chunk::Data(lossy(&buf))
            }
        }
        Err(err) => Chunk::Failed(err.to_string()),
    }
}

/// Read from `reader` until the transcript contains `needle`, or `timeout` expires.
///
/// Returns the whole transcript seen so far, which is what callers assert against.
///
/// Non-UTF-8 bytes become the replacement character instead of aborting the test:
/// they are the child's telnet negotiation, not a protocol answer. Every give-up path
/// says which failure it was and prints the transcript it saw.
pub fn read_until_contains(
    reader: &mut BufReader<TcpStream>,
    needle: &str,
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    let mut transcript = String::new();

    loop {
        if transcript.contains(needle) {
            return transcript;
        }
        if Instant::now() > deadline {
            panic!(
                "timed out after {timeout:?} waiting for `{needle}`. Transcript so far:\n{transcript}"
            );
        }

        match read_one(reader) {
            Chunk::Data(chunk) => transcript.push_str(&chunk),
            Chunk::Closed => panic!(
                "connection closed while waiting for `{needle}`. Transcript so far:\n{transcript}"
            ),
            Chunk::Idle => {}
            Chunk::Failed(err) => panic!(
                "socket read failed while waiting for `{needle}`: {err}\nTranscript so far:\n{transcript}"
            ),
        }
    }
}

/// `loom serve` opens every connection with startup telnet option negotiation
/// (OBI-26: `DO NAWS`, `DO TTYPE`, `WILL GMCP`, `WILL MSSP` -- `PREAMBLE_BYTES` of it,
/// none of it valid UTF-8 on its own) before any text protocol shows up on the wire.
/// These tests don't speak telnet back, so they drop that fixed-size preamble and let
/// anything the server adds to the same flush fall through to [`read_until_contains`],
/// which is byte-based and can swallow it.
///
/// Takes any `Read` so a caller can drain through a `BufReader` instead of the raw
/// socket: OBI-302 triage found that reading the fd directly skips whatever the
/// `BufReader` had already buffered, which desyncs every read after it.
///
/// `context` names the point in the test (`"before sending SIGTERM"`), so a preamble
/// failure says where it happened and what bytes it did get instead of `expect`'s
/// bare `UnexpectedEof`.
pub fn drain_telnet_preamble<R: Read>(src: &mut R, context: &str) {
    let mut bytes = [0_u8; PREAMBLE_BYTES];
    let mut got = 0;

    while got < PREAMBLE_BYTES {
        match src.read(&mut bytes[got..]) {
            Ok(0) => panic!(
                "harness: connection closed {context} after {got} of {PREAMBLE_BYTES} telnet \
                 preamble bytes; bytes read: {:02x?}",
                &bytes[..got]
            ),
            Ok(n) => got += n,
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => panic!(
                "harness: socket read failed {context} while reading the {PREAMBLE_BYTES}-byte \
                 telnet negotiation preamble after {got} bytes: {err}; bytes read: {:02x?}",
                &bytes[..got]
            ),
        }
    }
}

/// Bytes as text, CRLF normalised, never an error. An undecodable byte means "the
/// child put a negotiation sequence here", which a `contains(needle)` assertion can
/// ignore; it does not mean the connection or the driver is broken.
fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace("\r\n", "\n")
}
