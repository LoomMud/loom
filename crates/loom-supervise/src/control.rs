// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The application-level message protocol spoken over `loom supervise`'s
//! control `UnixStream`, *after* the initial fd handoff (design §7.5;
//! tracked under OBI-184). The earlier handoff handshake
//! (`loom-cli`'s `spawn_and_handoff`/`acquire_listeners`) is a one-shot
//! "ready byte, then `SCM_RIGHTS`" exchange and is not part of this
//! module -- this module is specifically for messages exchanged *while
//! the child is already up and serving*, which the handoff protocol
//! never needed because it only ever ran once, at startup, with nothing
//! else happening concurrently.
//!
//! **This slice wires the plumbing, not the copyover itself:** a
//! [`ControlMessage::CopyoverRequested`] sent to a running child is
//! acknowledged ([`ControlMessage::CopyoverAck`]) but today triggers no
//! actual reclaim/snapshot/handoff -- that is a separate, not-yet-built
//! follow-up (see `loom-cli`'s own doc comments on where this is called
//! from). What this slice *does* prove: the control socket survives past
//! the initial handoff on both ends, and the supervisor can reach an
//! already-running child over it.
//!
//! Framing: one tag byte, then (for the variants that carry a payload
//! today) a `u32` little-endian length prefix and that many UTF-8 bytes
//! -- deliberately not `serde`/`bincode` for a two-field, rarely-changing
//! protocol between two processes built from the same source tree (the
//! same reasoning [`crate::fdpass`]'s module doc gives for its own
//! minimal wire format).

use std::io::{self, Read, Write};

const TAG_COPYOVER_REQUESTED: u8 = 1;
const TAG_COPYOVER_ACK: u8 = 2;
const TAG_COPYOVER_NACK: u8 = 3;

/// The longest payload (e.g. a version string) this protocol will read
/// before refusing the message -- a sanity bound against a corrupt
/// stream or a non-peer process somehow writing to this fd, not an
/// expected-to-be-reached limit (a version string is a handful of
/// bytes).
const MAX_PAYLOAD_BYTES: u32 = 4096;

/// One message in `loom supervise`'s post-handoff control protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    /// Supervisor -> child: "the desired version has changed to
    /// `version`". Carries the detected version so the child (and,
    /// eventually, whatever copyover logic runs in response) knows what
    /// it's being asked to hand off to, without a second round trip.
    CopyoverRequested { version: String },
    /// Child -> supervisor: "request received". Today this is sent
    /// unconditionally and immediately -- see this module's doc comment
    /// for why that's the honest scope of this slice.
    CopyoverAck,
    /// Child -> supervisor: "request received, but refused". Not sent by
    /// anything yet (no rejection condition exists until the actual
    /// copyover logic lands), but part of the wire protocol from the
    /// start so adding a real rejection reason later doesn't need a
    /// framing change.
    CopyoverNack { reason: String },
}

/// Write one [`ControlMessage`] to `writer`.
///
/// # Errors
/// Any `io::Error` from the underlying writes (e.g. the peer process
/// has exited and the socket is now broken).
pub fn write_message(writer: &mut impl Write, message: &ControlMessage) -> io::Result<()> {
    match message {
        ControlMessage::CopyoverRequested { version } => {
            writer.write_all(&[TAG_COPYOVER_REQUESTED])?;
            write_payload(writer, version)
        }
        ControlMessage::CopyoverAck => writer.write_all(&[TAG_COPYOVER_ACK]),
        ControlMessage::CopyoverNack { reason } => {
            writer.write_all(&[TAG_COPYOVER_NACK])?;
            write_payload(writer, reason)
        }
    }
}

fn write_payload(writer: &mut impl Write, payload: &str) -> io::Result<()> {
    let bytes = payload.as_bytes();
    let len = u32::try_from(bytes.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("control message payload too large ({} bytes)", bytes.len()),
        )
    })?;
    // CTO review (OBI-259 nit): refuse here too, not just on the read
    // side -- without this, a too-large payload (e.g. an absurdly long
    // version string from an operator-editable file) would reach the
    // peer, get rejected there as `InvalidData`, and poison the control
    // channel over something the *sender* could have refused outright
    // with a clear `InvalidInput` instead.
    if len > MAX_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("control message payload length {len} exceeds {MAX_PAYLOAD_BYTES}"),
        ));
    }
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(bytes)
}

/// Read one [`ControlMessage`] from `reader`, blocking until a full
/// message (or EOF/an error) arrives.
///
/// # Errors
/// An `io::Error` with kind [`io::ErrorKind::UnexpectedEof`] if the
/// stream closes mid-message (including cleanly at the very start, e.g.
/// the peer exited -- callers should treat that the same as any other
/// "the other end is gone" condition, not panic), [`io::ErrorKind::
/// InvalidData`] for an unrecognised tag byte or an oversized payload
/// length (see [`MAX_PAYLOAD_BYTES`]), or any other `io::Error` from the
/// underlying reads.
pub fn read_message(reader: &mut impl Read) -> io::Result<ControlMessage> {
    let mut tag = [0u8; 1];
    reader.read_exact(&mut tag)?;
    match tag[0] {
        TAG_COPYOVER_REQUESTED => Ok(ControlMessage::CopyoverRequested {
            version: read_payload(reader)?,
        }),
        TAG_COPYOVER_ACK => Ok(ControlMessage::CopyoverAck),
        TAG_COPYOVER_NACK => Ok(ControlMessage::CopyoverNack {
            reason: read_payload(reader)?,
        }),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("control: unknown message tag {other}"),
        )),
    }
}

fn read_payload(reader: &mut impl Read) -> io::Result<String> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes);
    if len > MAX_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("control: payload length {len} exceeds {MAX_PAYLOAD_BYTES}"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf)?;
    String::from_utf8(buf)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("control: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn round_trip(message: ControlMessage) {
        let (mut a, mut b) = UnixStream::pair().expect("UnixStream::pair");
        write_message(&mut a, &message).expect("write_message");
        let got = read_message(&mut b).expect("read_message");
        assert_eq!(got, message);
    }

    #[test]
    fn copyover_requested_round_trips() {
        round_trip(ControlMessage::CopyoverRequested {
            version: "v2.0.0".to_string(),
        });
    }

    #[test]
    fn copyover_ack_round_trips() {
        round_trip(ControlMessage::CopyoverAck);
    }

    #[test]
    fn copyover_nack_round_trips() {
        round_trip(ControlMessage::CopyoverNack {
            reason: "standby not ready".to_string(),
        });
    }

    #[test]
    fn empty_string_payload_round_trips() {
        round_trip(ControlMessage::CopyoverRequested {
            version: String::new(),
        });
    }

    #[test]
    fn eof_before_any_byte_is_unexpected_eof() {
        let (a, b) = UnixStream::pair().expect("UnixStream::pair");
        drop(a);
        let mut b = b;
        let err = read_message(&mut b).expect_err("reading from a closed peer must error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn eof_mid_payload_is_unexpected_eof() {
        let (mut a, mut b) = UnixStream::pair().expect("UnixStream::pair");
        // A tag + length prefix claiming more payload than actually
        // follows before the sender closes its end.
        a.write_all(&[TAG_COPYOVER_REQUESTED]).unwrap();
        a.write_all(&10u32.to_le_bytes()).unwrap();
        a.write_all(b"abc").unwrap();
        drop(a);
        let err = read_message(&mut b).expect_err("truncated payload must error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn unknown_tag_is_invalid_data() {
        let (mut a, mut b) = UnixStream::pair().expect("UnixStream::pair");
        a.write_all(&[255]).unwrap();
        drop(a);
        let err = read_message(&mut b).expect_err("unknown tag must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn oversized_payload_length_is_refused_without_allocating_it() {
        let (mut a, mut b) = UnixStream::pair().expect("UnixStream::pair");
        a.write_all(&[TAG_COPYOVER_REQUESTED]).unwrap();
        a.write_all(&(MAX_PAYLOAD_BYTES + 1).to_le_bytes()).unwrap();
        drop(a);
        let err = read_message(&mut b).expect_err("an oversized length must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn non_utf8_payload_is_invalid_data() {
        let (mut a, mut b) = UnixStream::pair().expect("UnixStream::pair");
        a.write_all(&[TAG_COPYOVER_REQUESTED]).unwrap();
        a.write_all(&2u32.to_le_bytes()).unwrap();
        a.write_all(&[0xFF, 0xFE]).unwrap();
        drop(a);
        let err = read_message(&mut b).expect_err("non-UTF-8 payload must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A payload over [`MAX_PAYLOAD_BYTES`] is refused by the *writer*
    /// too, not just the reader (CTO review, OBI-259 nit) -- an
    /// oversized string should fail clearly at the sender, instead of
    /// reaching the peer and getting rejected there, which (per the
    /// supervisor's own poisoning rule) would tear down the whole
    /// control channel over a message that should never have been sent.
    #[test]
    fn write_message_refuses_an_oversized_payload() {
        let (mut a, _b) = UnixStream::pair().expect("UnixStream::pair");
        let oversized = "x".repeat(MAX_PAYLOAD_BYTES as usize + 1);
        let err = write_message(
            &mut a,
            &ControlMessage::CopyoverRequested { version: oversized },
        )
        .expect_err("an oversized payload must be refused before writing anything");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// CTO review (OBI-259): pins the error kind the supervisor's
    /// control-socket round trip will actually see when a child stops
    /// answering (`SIGSTOP`, a wedged responder thread, ...) -- a read
    /// timeout, not a hang. This is the primitive the supervisor-side
    /// fix builds on; it does not itself exercise `loom-cli`'s
    /// `run_one_child_attempt` (a real stalled-child scenario needs a
    /// real second process, better suited to an integration test if one
    /// is ever added).
    #[test]
    fn read_message_times_out_against_a_silent_peer() {
        let (a, mut b) = UnixStream::pair().expect("UnixStream::pair");
        b.set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .expect("set_read_timeout");
        // `a` is kept alive (not dropped) so this is a real "peer is
        // connected but silent" timeout, not an EOF-from-a-closed-peer
        // case (already covered by `eof_before_any_byte_is_unexpected_eof`).
        let err = read_message(&mut b).expect_err("a silent peer must time out, not hang");
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "expected WouldBlock or TimedOut, got {:?}",
            err.kind()
        );
        drop(a);
    }
}
