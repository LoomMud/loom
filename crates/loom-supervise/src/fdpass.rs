// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `AF_UNIX` + `SCM_RIGHTS` file-descriptor passing (design §7.5 step 2,
//! §9.2): the mechanism the supervisor uses to hand its listening sockets
//! (and, later, any already-connected client sockets) to a standby driver
//! process during a copyover without either process ever closing them.
//!
//! There is no safe std API for ancillary data (`sendmsg`/`recvmsg` with a
//! `cmsg` of type `SCM_RIGHTS`), so this module is the one place in the
//! crate that calls into `libc` directly. Every `unsafe` block here is
//! small, has a single reason documented next to it, and is exercised by
//! this module's own tests (a real `UnixStream` pair, not a mock) --
//! nothing above this module ever constructs a `msghdr`/`cmsghdr` itself.
//!
//! The wire format is intentionally minimal: one `sendmsg` call carries a
//! single regular byte payload (`send_fds`'s `tag`, a small fixed-size
//! marker so the receiver can sanity-check it got the message it expected,
//! not an empty/garbage one -- some platforms refuse a zero-length `iov`
//! together with ancillary data) plus zero or more `RawFd`s packed into
//! one `SCM_RIGHTS` control message. Callers needing to pass several
//! *kinds* of socket (telnet listener, HTTP listener, ...) send them as
//! one batch with [`send_fds`]/[`recv_fds`] and rely on a fixed, agreed
//! order -- there is no self-describing framing here, by design: the
//! supervisor and the driver it spawns are always built from the same
//! source tree and agree on the order out of band (`fdpass` itself has no
//! opinion on what the fds mean).
//!
//! `recv_fds`'s error handling (CTO review, OBI-184/OBI-225) follows one
//! rule throughout: **take ownership of every fd the kernel hands back
//! before validating anything else.** The kernel installs `SCM_RIGHTS`
//! fds into this process's descriptor table the instant `recvmsg`
//! returns, whether or not the rest of the message turns out to be
//! malformed -- so any validation-then-maybe-wrap ordering leaks fds on
//! every rejected-message path. Every fd is wrapped in an `OwnedFd`
//! first; a later validation failure then just drops the `Vec`, which
//! closes them normally.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

/// Marker payload sent alongside every `SCM_RIGHTS` control message (see
/// the module doc for why a non-empty payload is required). Not a
/// protocol version -- just enough bytes that `sendmsg`/`recvmsg` has a
/// real `iov` to work with.
const TAG: &[u8; 4] = b"FDS\0";

/// The most fds a single [`send_fds`]/[`recv_fds`] call will carry.
///
/// This is the Linux kernel's own `SCM_MAX_FD` (`include/net/scm.h`), not
/// a number `fdpass` picked -- 253, not a round 256 (CTO review,
/// OBI-184/OBI-225: the original 256 would pass `send_fds`'s own bound
/// check and then fail with `EINVAL` from `sendmsg` itself for 254-256
/// fds, a confusing place to find out about a kernel limit). Today's
/// copyover hands off two listening sockets; even with every in-flight
/// client socket handed off individually in a later slice, a MUD at
/// Phase 2 scale is nowhere near this limit, and `recv_fds` refuses to
/// return more than this many `OwnedFd`s regardless of what a (buggy or
/// hostile) peer claims.
pub const MAX_FDS: usize = 253;

/// Send `fds` (owned-by-the-caller borrows -- this function does not take
/// ownership, mirroring `sendmsg`'s own semantics: the fds stay open and
/// owned by the sender after the call returns) to the peer on `sock` in
/// one `SCM_RIGHTS` control message.
///
/// Returns an error for more than [`MAX_FDS`] fds (a caller bug, not
/// something a peer can trigger) or if the underlying `sendmsg` fails
/// (e.g. the peer is gone).
pub fn send_fds(sock: &UnixStream, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
    if fds.len() > MAX_FDS {
        return Err(io::Error::other(format!(
            "send_fds: {} fds exceeds MAX_FDS ({MAX_FDS})",
            fds.len()
        )));
    }

    let raw_fds: Vec<RawFd> = fds.iter().map(|fd| fd.as_raw_fd()).collect();
    // SAFETY: `CMSG_SPACE` is a pure size computation (a macro-turned-
    // function in `libc`) -- it reads only its argument, has no
    // preconditions, and cannot fail.
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(raw_fds.as_slice()) as u32) };
    let mut cmsg_buf = vec![0u8; cmsg_space as usize];

    let mut iov = libc::iovec {
        iov_base: TAG.as_ptr() as *mut libc::c_void,
        iov_len: TAG.len(),
    };

    // SAFETY: `msghdr` is a plain C struct of integers/pointers; the
    // all-zero bit pattern is a valid value for it (every field is
    // explicitly set below before `sendmsg` reads it, except the ones
    // `msghdr` defines as "ignored on send" -- `msg_flags`, `msg_namelen`
    // with a null `msg_name`), so `mem::zeroed` here is not the usual
    // "zeroed is not a valid value for this type" hazard.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !raw_fds.is_empty() {
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len() as _;
    }

    // SAFETY: `msg` has a valid single-entry `iov` pointing at `TAG` (a
    // `'static` byte array, alive for the whole call) and, when `raw_fds`
    // is non-empty, a `msg_control` buffer sized by `CMSG_SPACE` for
    // exactly `raw_fds.len()` fds. `CMSG_FIRSTHDR`/`CMSG_LEN`/`CMSG_DATA`
    // are only ever called with that same buffer, and the `copy_nonoverlapping`
    // writes exactly `raw_fds.len() * size_of::<RawFd>()` bytes into the
    // space `CMSG_LEN` reserved for them.
    unsafe {
        if !raw_fds.is_empty() {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            // `cmsg` is non-null: `msg_controllen` was set from the same
            // `CMSG_SPACE` computation used to size `cmsg_buf` above.
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of_val(raw_fds.as_slice()) as u32) as _;
            std::ptr::copy_nonoverlapping(
                raw_fds.as_ptr(),
                libc::CMSG_DATA(cmsg) as *mut RawFd,
                raw_fds.len(),
            );
        }
    }

    // SAFETY: `msg` is a valid, fully-initialized `msghdr` as set up
    // above (same value both inside and outside the loop; `sendmsg` does
    // not take ownership of anything it points to). `MSG_NOSIGNAL`
    // avoids relying on the process-wide "ignore SIGPIPE" setting Rust's
    // runtime happens to install -- correct even if `fdpass` is ever
    // embedded somewhere that doesn't do that (CTO review, OBI-225). The
    // `EINTR` retry is the standard "a signal interrupted a slow
    // syscall, just try again" loop; nothing about `msg` changes between
    // attempts.
    unsafe {
        loop {
            let rc = libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL);
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            break;
        }
    }

    Ok(())
}

/// Receive up to [`MAX_FDS`] fds sent by a peer's [`send_fds`] call on
/// `sock`. Returns the fds in the order the sender passed them (the
/// kernel preserves `SCM_RIGHTS` order within one control message).
/// Every returned fd already has `FD_CLOEXEC` set (`MSG_CMSG_CLOEXEC`,
/// CTO review OBI-184/OBI-225: without it, an adopted listener is
/// inheritable into whatever subprocesses the receiving driver later
/// spawns, e.g. `loom-git`'s `git` child -- a slow/hung one of those
/// would then keep the port bound even after `loom` itself exits).
///
/// Returns an error if: the message is missing the expected [`TAG`]
/// payload (a different kind of message, or truncated); the peer closed
/// the socket (a distinct `UnexpectedEof`, not folded into the tag-
/// mismatch case -- this is what you actually see when a supervisor dies
/// mid-handshake); the kernel reports `MSG_CTRUNC` (our buffer was too
/// small for everything the peer sent -- never silently returned as a
/// partial-but-successful list); the control message claims more than
/// [`MAX_FDS`] fds; or `recvmsg` itself fails (after retrying on
/// `EINTR`).
pub fn recv_fds(sock: &UnixStream) -> io::Result<Vec<OwnedFd>> {
    let mut tag_buf = [0u8; TAG.len()];
    // SAFETY: pure size computation, see `send_fds`'s identical call.
    let cmsg_space = unsafe { libc::CMSG_SPACE((MAX_FDS * std::mem::size_of::<RawFd>()) as u32) };
    let mut cmsg_buf = vec![0u8; cmsg_space as usize];

    let mut iov = libc::iovec {
        iov_base: tag_buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: tag_buf.len(),
    };

    // SAFETY: all-zero is a valid `msghdr` bit pattern here, see
    // `send_fds`'s identical call; every field `recvmsg` reads is set
    // below before the call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as _;

    // SAFETY: `msg` points at `tag_buf` (sized exactly [`TAG`]'s length)
    // and `cmsg_buf` (sized for up to `MAX_FDS` fds by `CMSG_SPACE`,
    // matching `send_fds`'s own sizing). `MSG_CMSG_CLOEXEC` only changes
    // how the kernel installs the returned fds (close-on-exec from the
    // start, with no intervening window where a concurrent `fork`+`exec`
    // on another thread could inherit them un-marked); it does not
    // change `recvmsg`'s own safety contract. The `EINTR` retry loop
    // re-issues the identical call; `msg`/`cmsg_buf`/`tag_buf` are not
    // mutated by a failed attempt. After a successful call,
    // `msg.msg_controllen` is the kernel-written actual length, and the
    // `CMSG_FIRSTHDR`/`CMSG_NXTHDR`/`CMSG_DATA` walk below only reads
    // within it, never past it -- every fd the walk finds is immediately
    // wrapped in an `OwnedFd` (see the module doc for why that ordering,
    // not "validate first", is required).
    let (rc, collected) = unsafe {
        let rc = loop {
            let rc = libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            break rc;
        };

        let mut collected = Vec::new();
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data_len = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let count = data_len / std::mem::size_of::<RawFd>();
                let data = libc::CMSG_DATA(cmsg) as *const RawFd;
                for i in 0..count {
                    let fd = std::ptr::read_unaligned(data.add(i));
                    collected.push(OwnedFd::from_raw_fd(fd));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        (rc, collected)
    };

    // Every check below runs *after* `collected` already owns whatever
    // fds arrived, so every `return Err` here drops (closes) them
    // instead of leaking.
    if rc == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "recv_fds: peer closed the control socket",
        ));
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::other(
            "recv_fds: ancillary data truncated (MSG_CTRUNC) -- peer sent more than this buffer holds",
        ));
    }
    if rc as usize != TAG.len() || tag_buf != *TAG {
        return Err(io::Error::other(
            "recv_fds: message payload did not match the expected fdpass tag",
        ));
    }
    if collected.len() > MAX_FDS {
        return Err(io::Error::other(format!(
            "recv_fds: peer sent {} fds, exceeding MAX_FDS ({MAX_FDS})",
            collected.len()
        )));
    }

    Ok(collected)
}

#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks)] // test scaffolding; production unsafe above this module is fully documented, enforced by this lint
mod tests {
    use super::*;
    use std::io::Read;
    use std::io::Write;
    use std::os::fd::AsFd;

    /// Round-trips zero fds: the marker payload alone must still arrive
    /// intact (the "no fds this time" case `fdpass`'s callers hit when a
    /// copyover carries, say, only the telnet listener and not the HTTP
    /// one yet).
    #[test]
    fn zero_fds_round_trip() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        send_fds(&a, &[]).expect("send_fds");
        let got = recv_fds(&b).expect("recv_fds");
        assert!(got.is_empty());
    }

    /// The core case: pass one open fd (here, one end of a plain pipe)
    /// across the control socket and prove the *receiving* process's copy
    /// is a real, independent, working fd -- not just a number that
    /// happens to be reused for something else: write through the
    /// original and read back through the received copy.
    #[test]
    fn one_fd_round_trip_is_live() {
        let (ctrl_a, ctrl_b) = UnixStream::pair().expect("socketpair");
        let (pipe_r, mut pipe_w) = pipe_pair();

        send_fds(&ctrl_a, &[pipe_r.as_fd()]).expect("send_fds");
        let received = recv_fds(&ctrl_b).expect("recv_fds");
        assert_eq!(received.len(), 1);

        pipe_w
            .write_all(b"hello")
            .expect("write to original pipe fd");
        drop(pipe_w);

        // Read through the *received* copy, not the original `pipe_r`:
        // proves the kernel actually duplicated the fd into the peer
        // process's (here, same-process, different fd number) table.
        let mut received_file = std::fs::File::from(received.into_iter().next().unwrap());
        let mut buf = Vec::new();
        received_file.read_to_end(&mut buf).expect("read");
        assert_eq!(buf, b"hello");

        // The original fd is still independently usable too (SCM_RIGHTS
        // dup's, it doesn't move).
        drop(pipe_r);
    }

    /// A received fd has `FD_CLOEXEC` set (`MSG_CMSG_CLOEXEC`, CTO review
    /// OBI-184/OBI-225) -- it must not be inheritable into whatever
    /// subprocess the receiving driver later spawns.
    #[test]
    fn received_fd_is_close_on_exec() {
        let (ctrl_a, ctrl_b) = UnixStream::pair().expect("socketpair");
        let (pipe_r, _pipe_w) = pipe_pair();

        send_fds(&ctrl_a, &[pipe_r.as_fd()]).expect("send_fds");
        let received = recv_fds(&ctrl_b).expect("recv_fds");
        let fd = received[0].as_raw_fd();

        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "fcntl(F_GETFD) failed");
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "received fd must have FD_CLOEXEC set"
        );
    }

    /// Several fds in one message arrive in the order they were sent,
    /// and each is independently live (not just the first one -- CTO
    /// review OBI-225: the original version of this test only read the
    /// first fd back, which wouldn't have caught an off-by-one in the
    /// cmsg walk that dropped or mis-ordered the second).
    #[test]
    fn multiple_fds_preserve_order() {
        let (ctrl_a, ctrl_b) = UnixStream::pair().expect("socketpair");
        let (r1, mut w1) = pipe_pair();
        let (r2, mut w2) = pipe_pair();

        send_fds(&ctrl_a, &[r1.as_fd(), r2.as_fd()]).expect("send_fds");
        let mut received = recv_fds(&ctrl_b).expect("recv_fds").into_iter();
        let first = received.next().unwrap();
        let second = received.next().unwrap();
        assert!(received.next().is_none());

        w1.write_all(b"first").unwrap();
        w2.write_all(b"second").unwrap();
        drop(w1);
        drop(w2);

        let mut first_buf = Vec::new();
        std::fs::File::from(first)
            .read_to_end(&mut first_buf)
            .unwrap();
        assert_eq!(first_buf, b"first");

        let mut second_buf = Vec::new();
        std::fs::File::from(second)
            .read_to_end(&mut second_buf)
            .unwrap();
        assert_eq!(second_buf, b"second");
    }

    /// A message with the wrong (or missing) tag -- i.e. not one of ours
    /// -- is rejected rather than silently treated as "zero fds".
    #[test]
    fn wrong_tag_is_rejected() {
        let (mut a, b) = UnixStream::pair().expect("socketpair");
        // Write a plain, non-fdpass payload directly (bypassing
        // `send_fds`) to prove `recv_fds` checks the tag, not just "did a
        // message arrive".
        a.write_all(b"nope").unwrap();
        let err = recv_fds(&b).unwrap_err();
        assert!(err.to_string().contains("tag"));
    }

    /// The peer closing its end (rather than sending a badly-tagged
    /// message) is reported as a distinct EOF error, not folded into the
    /// "wrong tag" case -- CTO review OBI-225: this is the error a real
    /// caller sees when a supervisor dies mid-handshake, and it deserves
    /// its own diagnosis.
    #[test]
    fn peer_close_is_reported_as_eof_not_a_tag_mismatch() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        drop(a);
        let err = recv_fds(&b).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    fn pipe_pair() -> (OwnedFd, std::fs::File) {
        use std::os::fd::FromRawFd;
        let mut fds = [0 as RawFd; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe() failed: {}", io::Error::last_os_error());
        let r = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let w = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        (r, w)
    }
}
