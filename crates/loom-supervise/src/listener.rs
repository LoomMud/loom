// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Turning a raw, received file descriptor back into a usable
//! `std::net::TcpListener`/`UnixStream`, and the one `fcntl` helper the
//! supervisor needs before `spawn`ing a standby child (clearing
//! `FD_CLOEXEC` on the control-socket end that child must inherit --
//! every fd the standard library creates is close-on-exec by default, so
//! without this the child's end of the control `UnixStream::pair()`
//! would simply vanish at `exec`).
//!
//! Like [`crate::fdpass`], this is `unsafe`-only-here-for-a-documented-
//! reason code: `FromRawFd`/`fcntl` have no safe equivalents for "I
//! already own this fd, hand me a typed wrapper around it".

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

/// Wrap a received listening-socket fd (from [`crate::fdpass::recv_fds`])
/// as a `std::net::TcpListener`. The caller (typically `tokio::net::
/// TcpListener::from_std`, which requires non-blocking mode) is
/// responsible for anything beyond "this is now a typed, owned
/// `TcpListener`" -- this function does not itself call
/// `set_nonblocking`, so a caller handing the result straight to Tokio
/// must do that first.
///
/// # Errors
/// Never fails on its own (`From<OwnedFd>` is infallible for
/// `TcpListener`); the `Result` wrapper exists so call sites that chain
/// this with other I/O (e.g. `set_nonblocking`) can use `?` uniformly.
/// Kept as a named function rather than a bare `From` conversion so the
/// "this fd had better actually be a listening socket -- there is no
/// check here" assumption has a place to be documented once, not at
/// every call site.
pub fn adopt_tcp_listener(fd: OwnedFd) -> io::Result<std::net::TcpListener> {
    // SAFETY: `fd` is an `OwnedFd` the caller received from `recv_fds`
    // (itself validated against a kernel-delivered `SCM_RIGHTS` message,
    // see fdpass's own safety notes) -- it is a real, open, owned
    // descriptor. `From<OwnedFd>` for `TcpListener` is exactly this
    // "trust me, it's a listening socket" wrapping; there is nothing
    // additionally unsafe about the conversion itself, it is just gated
    // by this crate's blanket `unsafe_code = "warn"` because `OwnedFd`'s
    // own `From` impl is still conceptually "reinterpret this fd".
    Ok(std::net::TcpListener::from(fd))
}

/// Clear `FD_CLOEXEC` on `fd` so a subsequently `spawn`ed child inherits
/// it. Used on the child's end of a control-socket `UnixStream::pair()`
/// right before `Command::spawn` -- every other fd the supervisor holds
/// (its own listening sockets, the *other* end of the pair) keeps
/// `FD_CLOEXEC` set and is correctly *not* inherited.
pub fn clear_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid, open descriptor for the duration of this
    // call (the caller passes a `RawFd` borrowed from an `OwnedFd`/
    // `UnixStream` it still owns). `fcntl(F_GETFD)`/`fcntl(F_SETFD, ..)`
    // are the standard, non-allocating way to read-modify-write the
    // close-on-exec flag; this function does not transfer ownership of
    // `fd` or close it.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let rc = libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Wrap an inherited control-socket fd (the number a standby child was
/// told about, e.g. via a `--adopt-control-fd <n>` argument) as a
/// `UnixStream`. The fd is assumed to already be open and valid --
/// exactly the fd the supervisor's [`clear_cloexec`] + `spawn` handed
/// down; there is no portable way to double-check "is this really a
/// `AF_UNIX` socket and not, say, fd 2" from here, so a caller passing a
/// wrong number gets whatever `read`/`write`/`sendmsg` on that fd number
/// actually does (most likely a prompt I/O error, not silent corruption).
pub fn control_stream_from_raw_fd(fd: RawFd) -> UnixStream {
    // SAFETY: the contract is "the caller's own supervisor already
    // `clear_cloexec`'d and handed down exactly this fd number as the
    // standby's control socket" -- see the module/function doc above for
    // what happens if that contract is violated (an I/O error on first
    // use, not memory unsafety: `UnixStream` only ever issues normal
    // socket syscalls against this fd).
    unsafe { UnixStream::from_raw_fd(fd) }
}

/// The raw fd number behind `stream`, for logging/passing to a spawned
/// child (not ownership-transferring -- `stream` still owns and will
/// close it on `Drop`, same as [`std::os::fd::AsRawFd`] always means).
pub fn raw_fd_of(stream: &UnixStream) -> RawFd {
    stream.as_raw_fd()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn adopted_listener_accepts_connections() {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = std_listener.local_addr().unwrap();
        let owned: OwnedFd = std_listener.into();

        let adopted = adopt_tcp_listener(owned).unwrap();
        adopted.set_nonblocking(true).unwrap();

        let connector = std::net::TcpStream::connect(addr).unwrap();
        // A real client connected; prove the *adopted* listener (not the
        // original binding) is the one that sees it.
        let mut accepted = loop {
            match adopted.accept() {
                Ok((stream, _)) => break stream,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => panic!("accept failed: {err}"),
            }
        };
        let mut connector = connector;
        connector.write_all(b"hi").unwrap();
        let mut buf = [0u8; 2];
        accepted.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hi");
    }

    #[test]
    fn clear_cloexec_then_spawn_inherits_the_fd() {
        use std::process::{Command, Stdio};

        let (parent_end, child_end) = UnixStream::pair().unwrap();
        clear_cloexec(child_end.as_raw_fd()).unwrap();
        let child_fd = child_end.as_raw_fd();

        // `>&N` duplicates the already-open fd directly (unlike `>
        // /proc/self/fd/N`, which re-`open()`s the path and fails with
        // ENXIO for a socket -- sockets can be written through an
        // inherited fd number, just not reopened by path). This is the
        // simplest possible proof that `child_fd` is still open and is
        // the *same* socket in a freshly exec'd process: write through
        // it and read the bytes back on the parent's paired end.
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(format!("echo -n ok >&{child_fd}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh");
        let status = child.wait().unwrap();
        assert!(status.success(), "child exited with {status:?}");

        // `child_end` (the parent's own copy of the fd the spawned
        // process inherited) must stay open for the duration of the
        // child's run -- it stays alive here simply by still being in
        // scope; dropping it early would have no effect on the already-
        // forked child's own copy, but keeping it is the realistic shape
        // (the supervisor keeps its control-socket end open the whole
        // time the standby runs).
        let mut buf = [0u8; 2];
        let mut parent_end = parent_end;
        parent_end.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ok");
        drop(child_end);
    }
}
