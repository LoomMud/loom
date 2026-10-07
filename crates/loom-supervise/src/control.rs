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

// Tags are append-only from here on (N2, CTO re-review OBI-273): once a
// tag has shipped in a released binary, its number and meaning must
// never change or be reused for something else, even across a protocol
// revision. The old side of a hand-off runs the *previous* binary by
// definition, so an old binary that doesn't know a new tag reads it as
// "unknown message tag" (`InvalidData`, see `read_message`'s `other =>`
// arm) -- the supervisor must treat that (or a `CopyoverNack`) from the
// old process as "fall back to a cold restart", not retry the same
// hand-off (see `lib.rs`'s "not yet implemented" list for where that
// fallback is tracked). New variants always get the next unused number;
// never renumber or repurpose an existing one.
const TAG_COPYOVER_REQUESTED: u8 = 1;
const TAG_COPYOVER_ACK: u8 = 2;
const TAG_COPYOVER_NACK: u8 = 3;
const TAG_HANDOFF_READY: u8 = 4;
const TAG_HANDOFF_GO: u8 = 5;
const TAG_HANDOFF_ABORT: u8 = 6;
const TAG_HANDOFF_RUNNING: u8 = 7;
const TAG_HANDOFF_OFFER: u8 = 8;
const TAG_HANDOFF_COMMIT: u8 = 9;

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

    /// Old process -> supervisor -> standby: the forward hand-off
    /// message (design doc §4/§5; CTO re-review OBI-273, blocker B1).
    /// The old process sends this to the supervisor once it has
    /// reclaimed its connections and taken the snapshot; the supervisor
    /// relays it on to the standby (the relay itself is not yet wired --
    /// see `lib.rs`'s "not yet implemented" list). `conn_ids` is paired
    /// 1:1 in list order with the `fdpass::send_fds`/`recv_fds` call that
    /// carries this hand-off's fds on each hop (old process -> supervisor,
    /// then supervisor -> standby) -- this is what closes the fd<->
    /// `ConnId` desync gap OBI-227's review flagged against `fdpass`'s
    /// original fd-only framing. `snapshot_path` is the supervisor-owned
    /// file the snapshot bytes live in (§4: a world snapshot can be
    /// arbitrarily large, too big for this protocol's own
    /// `MAX_PAYLOAD_BYTES`-bounded inline payloads); `snapshot_len` and
    /// `snapshot_hash` are what the standby checks *before* calling
    /// `World::load_snapshot` (amendment A5), so a truncated or corrupted
    /// file fails fast with a clear error here instead of a confusing
    /// panic/mismatch deep inside `loom-vm`.
    HandoffOffer {
        conn_ids: Vec<u64>,
        snapshot_path: String,
        snapshot_len: u64,
        snapshot_hash: [u8; 32],
    },

    /// Standby -> supervisor, phase 1 complete (design doc §5 step 3,
    /// OBI-184 plan rev 2 / CTO amendment A1): the snapshot is loaded and
    /// every `conn_id` from the matching `HandoffOffer` is registered as
    /// an adopted connection, but **not yet polled/read** -- the standby
    /// has touched no socket I/O at this point. A bare ack: `HandoffOffer`
    /// (not this message) is what carries `conn_ids`, paired with the
    /// `fdpass` call that moved the fds (CTO re-review OBI-273, blocker
    /// B1 -- an earlier revision had this message carry its own
    /// `conn_ids` the wrong direction to close the fd<->`ConnId` desync
    /// gap; it would only ever have echoed what the supervisor already
    /// sent).
    HandoffReady,

    /// Supervisor -> standby: the decision point has been reached (the
    /// standby's `HandoffReady` arrived within the phase deadline) --
    /// proceed to phase 2: `reconnect_all`, start reading the adopted
    /// conns, start accepting new connections. Per amendment A1, the
    /// supervisor sends this (and the matching `HandoffCommit` to the
    /// old process, queued right behind it at the same decision instant)
    /// before the standby does any socket I/O at all -- never the other
    /// way around.
    HandoffGo,

    /// Supervisor -> old (active) process: the decision point was
    /// reached (see `HandoffGo`'s doc) -- drop every parked connection
    /// (closing this process's copy of each fd; the standby's copy, from
    /// the same `fdpass::send_fds` call, is unaffected) and exit. Queued
    /// right behind `HandoffGo` at the same decision instant (CTO
    /// re-review OBI-273, blocker B2 -- a previous revision had no
    /// message for this and referenced a nonexistent `CopyoverCommitted`
    /// variant in `HandoffGo`'s doc instead).
    HandoffCommit,

    /// Supervisor -> old (active) process: the hand-off failed or timed
    /// out before the decision point (or the standby never answered) --
    /// resume as the active process. Per amendment A1, the supervisor
    /// only ever sends this *after* it has SIGKILLed and reaped the
    /// standby, so a `HandoffAbort` recipient can safely re-adopt its
    /// parked connections (PR #111's reclaim/readopt code path) knowing
    /// no other process is already live on the same fds.
    HandoffAbort,

    /// Standby -> supervisor: phase 2 is complete (`reconnect_all` ran,
    /// now accepting). Bookkeeping/observability only, per amendment A1 --
    /// by the time this arrives the supervisor has already committed (it
    /// sent `HandoffGo` to the standby and `HandoffCommit` to the old
    /// process at the same decision instant), so this ack does not gate
    /// anything further. Renamed from `HandoffCommitted` (CTO re-review
    /// OBI-273, blocker B2): that name differed from `HandoffCommit`
    /// above by two letters while going the opposite direction, which is
    /// easy to mix up.
    HandoffRunning,
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
        ControlMessage::HandoffOffer {
            conn_ids,
            snapshot_path,
            snapshot_len,
            snapshot_hash,
        } => {
            writer.write_all(&[TAG_HANDOFF_OFFER])?;
            write_conn_ids(writer, conn_ids)?;
            write_payload(writer, snapshot_path)?;
            writer.write_all(&snapshot_len.to_le_bytes())?;
            writer.write_all(snapshot_hash)
        }
        ControlMessage::HandoffReady => writer.write_all(&[TAG_HANDOFF_READY]),
        ControlMessage::HandoffGo => writer.write_all(&[TAG_HANDOFF_GO]),
        ControlMessage::HandoffCommit => writer.write_all(&[TAG_HANDOFF_COMMIT]),
        ControlMessage::HandoffAbort => writer.write_all(&[TAG_HANDOFF_ABORT]),
        ControlMessage::HandoffRunning => writer.write_all(&[TAG_HANDOFF_RUNNING]),
    }
}

/// The most `conn_id`s a single [`ControlMessage::HandoffOffer`] will
/// carry -- a sanity bound mirroring [`MAX_PAYLOAD_BYTES`]'s role for
/// string payloads, not an expected-to-be-reached limit (Phase 2 scale
/// is nowhere near this many simultaneous live connections).
const MAX_CONN_IDS: u32 = 65536;

fn write_conn_ids(writer: &mut impl Write, conn_ids: &[u64]) -> io::Result<()> {
    let count = u32::try_from(conn_ids.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "control message conn_id list too large ({} entries)",
                conn_ids.len()
            ),
        )
    })?;
    if count > MAX_CONN_IDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("control message conn_id count {count} exceeds {MAX_CONN_IDS}"),
        ));
    }
    writer.write_all(&count.to_le_bytes())?;
    for conn_id in conn_ids {
        writer.write_all(&conn_id.to_le_bytes())?;
    }
    Ok(())
}

fn read_conn_ids(reader: &mut impl Read) -> io::Result<Vec<u64>> {
    let mut count_bytes = [0u8; 4];
    reader.read_exact(&mut count_bytes)?;
    let count = u32::from_le_bytes(count_bytes);
    if count > MAX_CONN_IDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("control: conn_id count {count} exceeds {MAX_CONN_IDS}"),
        ));
    }
    let mut conn_ids = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        conn_ids.push(u64::from_le_bytes(buf));
    }
    Ok(conn_ids)
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
        TAG_HANDOFF_OFFER => {
            let conn_ids = read_conn_ids(reader)?;
            let snapshot_path = read_payload(reader)?;
            let mut len_bytes = [0u8; 8];
            reader.read_exact(&mut len_bytes)?;
            let snapshot_len = u64::from_le_bytes(len_bytes);
            let mut snapshot_hash = [0u8; 32];
            reader.read_exact(&mut snapshot_hash)?;
            Ok(ControlMessage::HandoffOffer {
                conn_ids,
                snapshot_path,
                snapshot_len,
                snapshot_hash,
            })
        }
        TAG_HANDOFF_READY => Ok(ControlMessage::HandoffReady),
        TAG_HANDOFF_GO => Ok(ControlMessage::HandoffGo),
        TAG_HANDOFF_COMMIT => Ok(ControlMessage::HandoffCommit),
        TAG_HANDOFF_ABORT => Ok(ControlMessage::HandoffAbort),
        TAG_HANDOFF_RUNNING => Ok(ControlMessage::HandoffRunning),
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
    fn handoff_offer_round_trips_with_conn_ids() {
        round_trip(ControlMessage::HandoffOffer {
            conn_ids: vec![1, 2, 3, 42],
            snapshot_path: "/var/lib/loom/copyover/snap-abc123".to_string(),
            snapshot_len: 12345,
            snapshot_hash: [7u8; 32],
        });
    }

    #[test]
    fn handoff_offer_round_trips_with_no_conn_ids() {
        round_trip(ControlMessage::HandoffOffer {
            conn_ids: vec![],
            snapshot_path: String::new(),
            snapshot_len: 0,
            snapshot_hash: [0u8; 32],
        });
    }

    #[test]
    fn handoff_ready_round_trips() {
        round_trip(ControlMessage::HandoffReady);
    }

    #[test]
    fn handoff_go_round_trips() {
        round_trip(ControlMessage::HandoffGo);
    }

    #[test]
    fn handoff_commit_round_trips() {
        round_trip(ControlMessage::HandoffCommit);
    }

    #[test]
    fn handoff_abort_round_trips() {
        round_trip(ControlMessage::HandoffAbort);
    }

    #[test]
    fn handoff_running_round_trips() {
        round_trip(ControlMessage::HandoffRunning);
    }

    /// Pins the exact ordering contract `HandoffOffer`'s own doc comment
    /// promises: `conn_ids` round-trips in the order given, since the
    /// receiver pairs it 1:1 by list position against `fdpass::recv_fds`'s
    /// own order-preserving result, not a reordered/sorted copy.
    #[test]
    fn handoff_offer_preserves_conn_id_order() {
        let (mut a, mut b) = UnixStream::pair().expect("UnixStream::pair");
        let conn_ids = vec![9, 1, 5, 3];
        write_message(
            &mut a,
            &ControlMessage::HandoffOffer {
                conn_ids: conn_ids.clone(),
                snapshot_path: "/tmp/snap".to_string(),
                snapshot_len: 1,
                snapshot_hash: [1u8; 32],
            },
        )
        .unwrap();
        match read_message(&mut b).unwrap() {
            ControlMessage::HandoffOffer { conn_ids: got, .. } => assert_eq!(got, conn_ids),
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn oversized_conn_id_count_is_refused_on_read_without_allocating_it() {
        let (mut a, mut b) = UnixStream::pair().expect("UnixStream::pair");
        a.write_all(&[TAG_HANDOFF_OFFER]).unwrap();
        a.write_all(&(MAX_CONN_IDS + 1).to_le_bytes()).unwrap();
        drop(a);
        let err = read_message(&mut b).expect_err("an oversized conn_id count must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
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
