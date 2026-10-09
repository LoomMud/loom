// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-355: the shared `loom-cli` socket reader must not turn the child's telnet
//! negotiation into a test failure, and must name the failure when it does give up.
//!
//! Covers all three shapes the integration tests use it in: `read_until_contains`
//! (needle over a transcript), `read_one` (one chunk, for callers with their own
//! framing), and `drain_telnet_preamble` (the fixed handshake skip) -- including the
//! two composed, the way `connect_with_retry` then a first read uses them.
//!
//! These are loopback, deterministic, and use no sleeps: every byte the "child" side
//! writes is written before the reader is allowed to block, and the only clock
//! involved is the helper's own patience, which these tests never race.

#[path = "support/read_until.rs"]
mod read_until;

use read_until::{Chunk, drain_telnet_preamble, read_one, read_until_contains};
use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// What a server adds to the opening flush once it wants more than the four options
/// the tests' 12-byte drain knows about: `IAC WILL ECHO`, a `IAC SB CHARSET SEND
/// IAC SE` query, and a `IAC SB TTYPE SEND IAC SE` query.
const OVERFLOW_NEGOTIATION: [u8; 15] = [
    0xff, 0xfb, 0x01, 0xff, 0xfa, 0x2a, 0x01, 0xff, 0xf0, 0xff, 0xfa, 0x18, 0x01, 0xff, 0xf0,
];

/// Negotiation landing *inside* a line: `IAC SB TTYPE IS "dumb" IAC SE`, the shape a
/// codec flushes between two writes of the prompt text it was already sending.
const SPLIT_LINE_NEGOTIATION: [u8; 10] =
    [0xff, 0xfa, 0x18, 0x00, b'd', b'u', b'm', b'b', 0xff, 0xf0];

/// The documented 12-byte offer `TelnetCodec::start()` makes (`IAC DO NAWS`, `IAC DO
/// TTYPE`, `IAC WILL GMCP`, `IAC WILL MSSP`) followed by 6 more bytes the drain knows
/// nothing about: an `IAC SB TTYPE SEND IAC SE` query in the same flush.
const PREAMBLE_PLUS_SPILLOVER: [u8; 18] = [
    0xff, 0xfd, 0x1f, 0xff, 0xfd, 0x18, 0xff, 0xfb, 0xc9, 0xff, 0xfb, 0x46, 0xff, 0xfa, 0x18, 0x01,
    0xff, 0xf0,
];

/// A loopback pair standing in for the `loom serve` socket: the returned reader is
/// the test's side, the returned stream writes the child's bytes.
fn socket_pair() -> (BufReader<TcpStream>, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let client = TcpStream::connect(addr).expect("connect loopback");
    let (child_side, _) = listener.accept().expect("accept loopback");
    // A wedged harness must fail the test rather than hang the suite.
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    client.set_nodelay(true).expect("nodelay");
    (BufReader::new(client), child_side)
}

/// What cost CI two green `rust` jobs: IAC negotiation that the tests' hard-coded
/// 12-byte `drain_telnet_preamble` did not consume, arriving ahead of the line the
/// test wants. `read_line` called that `InvalidData` and panicked.
#[test]
fn telnet_bytes_before_a_line_do_not_fail_the_read() {
    let (mut reader, mut child_side) = socket_pair();

    // More negotiation than the 12-byte drain knows about, ahead of the line the test
    // is waiting for.
    child_side
        .write_all(&OVERFLOW_NEGOTIATION)
        .expect("write negotiation");
    child_side
        .write_all(b"Exits: north.\r\n")
        .expect("write prompt");

    let transcript = read_until_contains(&mut reader, "Exits:", Duration::from_secs(2));

    assert!(
        transcript.contains("Exits: north."),
        "the prompt must survive binary bytes in front of it, got: {transcript:?}"
    );
}

/// Negotiation interleaved *inside* a line: the transcript is the concatenation of
/// everything read, so a needle split by an IAC sequence is still found.
#[test]
fn telnet_bytes_splitting_a_line_do_not_hide_the_needle() {
    let (mut reader, mut child_side) = socket_pair();

    child_side
        .write_all(b"Welcome to ")
        .expect("write first half");
    child_side
        .write_all(&SPLIT_LINE_NEGOTIATION) // IAC SB TTYPE IS "dumb" IAC SE
        .expect("write negotiation");
    child_side
        .write_all(b"the mud.\n")
        .expect("write second half");

    let transcript = read_until_contains(&mut reader, "the mud.", Duration::from_secs(2));
    assert!(transcript.contains("the mud."), "got: {transcript:?}");
}

/// The second half of the contract: when the harness does give up, the message names
/// the failure mode and shows the bytes it saw. A generic panic is how this class of
/// bug got misread as a product defect.
#[test]
fn giving_up_reports_which_failure_it_was() {
    let (mut reader, mut child_side) = socket_pair();
    child_side
        .write_all(b"Login: ")
        .expect("write partial line");
    drop(child_side); // EOF with the needle never arriving.

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        read_until_contains(&mut reader, "Welcome.", Duration::from_millis(500))
    }))
    .expect_err("a closed connection that never says `Welcome.` must fail");

    let message = panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_string()))
        .unwrap_or_else(|| format!("{panic:?}"));

    assert!(
        message.contains("connection closed while waiting for `Welcome.`"),
        "must name the failure mode, got: {message}"
    );
    assert!(
        message.contains("Login:"),
        "must show what it did read, got: {message}"
    );
}

/// The two halves of the harness composed the way a real test uses them: drop the
/// fixed preamble, then read text. A server that adds one more option to its opening
/// flush -- the thing that actually broke CI -- must cost nothing but a replacement
/// character in the transcript.
#[test]
fn a_preamble_longer_than_the_drain_still_leaves_the_line_readable() {
    let (mut reader, mut child_side) = socket_pair();

    // 12 bytes' worth of the documented offer, then 6 more the tests' drain knows
    // nothing about.
    child_side
        .write_all(&PREAMBLE_PLUS_SPILLOVER)
        .expect("write preamble");
    child_side
        .write_all(b"Exits: north.\r\n")
        .expect("write prompt");

    drain_telnet_preamble(&mut reader, "on connecting to the server");

    let transcript = read_until_contains(&mut reader, "Exits:", Duration::from_secs(2));
    assert!(
        transcript.contains("Exits: north."),
        "the negotiation bytes past the drain must not hide the prompt, got: {transcript:?}"
    );
}

/// `drain_telnet_preamble` is a harness step, so when it can't complete it has to say
/// so in those terms -- how far it got and what it saw -- rather than `expect`'s bare
/// `UnexpectedEof`, which is how a short handshake reads like a driver bug.
#[test]
fn a_short_preamble_reports_a_harness_shortfall_with_the_bytes_it_got() {
    let (mut reader, mut child_side) = socket_pair();
    child_side
        .write_all(&[0xff, 0xfd, 0x1f, 0xff, 0xfd, 0x18]) // 6 of 12, then EOF
        .expect("write half a preamble");
    drop(child_side);

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drain_telnet_preamble(&mut reader, "on connecting to the server")
    }))
    .expect_err("a connection that closes mid-preamble must fail the harness step");

    let message = panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_string()))
        .unwrap_or_else(|| format!("{panic:?}"));

    assert!(
        message.contains("harness: connection closed") && message.contains("6 of 12"),
        "must name the shortfall, got: {message}"
    );
    assert!(
        message.contains("ff, fd, 1f, ff, fd, 18"),
        "must show the negotiation bytes it did read, got: {message}"
    );
}

/// The other half of "lossless": bytes that arrive and then make the reader wait for
/// the rest of the line must survive the timeout. `read_line` had already pulled them
/// into the `BufReader` and returned an error, so a retry could report a timeout for a
/// line it was sitting on.
#[test]
fn a_partial_line_survives_a_read_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let client = TcpStream::connect(addr).expect("connect loopback");
    let (mut child_side, _) = listener.accept().expect("accept loopback");
    client
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("set read timeout");
    client.set_nodelay(true).expect("nodelay");
    let mut reader = BufReader::new(client);

    child_side.write_all(b"Exits:").expect("write partial line");

    // Blocks for the socket's 100 ms, then hands the bytes back instead of dropping
    // them with the timeout.
    match read_one(&mut reader) {
        Chunk::Data(chunk) => assert_eq!(chunk, "Exits:"),
        other => panic!("a timeout with bytes in hand must keep them, got {other:?}"),
    }

    match read_one(&mut reader) {
        Chunk::Idle => {}
        other => panic!("an empty timeout must read as Idle, got {other:?}"),
    }

    child_side
        .write_all(b" north.\n")
        .expect("write line ending");
    match read_one(&mut reader) {
        Chunk::Data(chunk) => assert_eq!(chunk, " north.\n"),
        other => panic!("the rest of the line must arrive, got {other:?}"),
    }
}

/// Negative control for this whole file: the fixtures above have to be bytes a
/// UTF-8-validating read would choke on, or the tests that feed them prove nothing.
/// `read_line` panics on `InvalidData` for exactly these bytes -- that is the OBI-355
/// failure -- so if one of them is ever "cleaned up" into plain ASCII this test says
/// the regression it guards has quietly gone uncovered.
#[test]
fn the_negotiation_fixtures_are_not_valid_utf8() {
    for (name, bytes) in [
        ("overflow negotiation", OVERFLOW_NEGOTIATION.as_slice()),
        ("split-line negotiation", SPLIT_LINE_NEGOTIATION.as_slice()),
        ("preamble spillover", PREAMBLE_PLUS_SPILLOVER.as_slice()),
    ] {
        assert!(
            std::str::from_utf8(bytes).is_err(),
            "{name} must stay undecodable as UTF-8: a reader that only had to survive text \
             would not need the byte-based read OBI-355 is about"
        );
    }
}
