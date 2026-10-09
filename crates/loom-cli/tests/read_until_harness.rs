// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-355: the shared `loom-cli` socket reader must not turn the child's telnet
//! negotiation into a test failure, and must name the failure when it does give up.
//!
//! These are loopback, deterministic, and use no sleeps: every byte the "child" side
//! writes is written before the reader is allowed to block, and the only clock
//! involved is the helper's own patience, which these tests never race.

#[path = "support/read_until.rs"]
mod read_until;

use read_until::read_until_contains;
use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

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

    // IAC WILL ECHO, then IAC SB CHARSET "UTF-8" ... IAC SE -- 12 bytes is not enough.
    child_side
        .write_all(&[
            0xff, 0xf1, 0x01, 0xff, 0xfa, 0x24, 0x01, b'U', b'S', b'B', 0xff, 0xf0, 0xff, 0xfb,
            0x03,
        ])
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
        .write_all(&[0xff, 0xfb, 0x18, 0x01, 0x50, 0x00, 0x18]) // IAC SB ... IAC SE
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
