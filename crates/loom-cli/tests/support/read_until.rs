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
//! fail the message has to say what it saw.** So this reads bytes, keeps a lossy
//! transcript, and treats encoding as not its business. Framing is unchanged -- it
//! still blocks on a newline, so a needle never sees a line half-consumed under it.
//!
//! Included by each test crate with `#[path]`; its own behaviour is proven in
//! `tests/read_until_harness.rs`.

use std::io::{BufRead, BufReader, ErrorKind};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Read from `reader` until the transcript contains `needle`, or `timeout` expires.
///
/// Returns the whole transcript seen so far, which is what callers assert against.
///
/// Non-UTF-8 bytes become the replacement character instead of aborting the test:
/// they are the child's telnet negotiation, not a protocol answer. Bytes that
/// arrived before a read timeout are kept too -- `read_until` hands them back in its
/// buffer even on the error path, and the old `read_line` version dropped them, which
/// is how a test loses the very line it was waiting for.
pub fn read_until_contains(
    reader: &mut BufReader<TcpStream>,
    needle: &str,
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    let mut transcript = String::new();

    loop {
        if Instant::now() > deadline {
            panic!(
                "timed out after {timeout:?} waiting for `{needle}`. Transcript so far:\n{transcript}"
            );
        }

        let mut chunk: Vec<u8> = Vec::new();
        let outcome = reader.read_until(b'\n', &mut chunk);
        // Whatever the socket delivered belongs in the transcript, clean read or not.
        transcript.push_str(&lossy(&chunk));

        match outcome {
            Ok(0) => panic!(
                "connection closed while waiting for `{needle}`. Transcript so far:\n{transcript}"
            ),
            Ok(_) => {
                if transcript.contains(needle) {
                    return transcript;
                }
            }
            // A read timeout is the harness's patience running out, not the child
            // answering wrongly: keep looping, and let the deadline write the report.
            Err(err) if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                if transcript.contains(needle) {
                    return transcript;
                }
            }
            Err(err) => panic!(
                "socket read failed while waiting for `{needle}`: {err}\nTranscript so far:\n{transcript}"
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
