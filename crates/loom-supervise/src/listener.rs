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
/// Contains no `unsafe` (`OwnedFd -> TcpListener` via `From` is a safe
/// conversion); kept as a named function rather than a bare `From` call
/// so the "this fd had better actually be a listening socket -- there is
/// no check here" assumption has a place to be documented once, not at
/// every call site.
///
/// # Errors
/// Never fails on its own today; the `Result` wrapper exists so call
/// sites that chain this with other I/O (e.g. `set_nonblocking`) can use
/// `?` uniformly, and so a future added check (e.g. `getsockopt(
/// SO_ACCEPTCONN)` to confirm the fd is actually listening) doesn't need
/// a signature change.
pub fn adopt_tcp_listener(fd: OwnedFd) -> io::Result<std::net::TcpListener> {
    Ok(std::net::TcpListener::from(fd))
}

/// Clear `FD_CLOEXEC` on `fd` so a subsequently `spawn`ed child inherits
/// it. Used on the child's end of a control-socket `UnixStream::pair()`
/// right before `Command::spawn` -- every other fd the supervisor holds
/// (its own listening sockets, the *other* end of the pair) keeps
/// `FD_CLOEXEC` set and is correctly *not* inherited.
///
/// This is race-free only because nothing else in `loom supervise`
/// spawns a process concurrently (CTO review, OBI-184/OBI-225): clearing
/// `FD_CLOEXEC` is process-wide, so any other thread that happened to
/// `fork`+`exec` between this call and the matching `Command::spawn`
/// would also inherit this fd. If `supervise` ever grows a second thing
/// that spawns processes, prefer clearing `FD_CLOEXEC` only in the
/// child, via `Command::pre_exec` immediately before `execve` (ideally
/// paired with `dup2` onto a fixed fd number, which also removes the
/// need to pass the fd number down via argv).
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
/// `UnixStream`.
///
/// Before wrapping, this rejects `fd <= 2` (stdin/stdout/stderr -- a
/// caller that passed one of those by mistake must not get a
/// `UnixStream` that closes, say, stderr on `Drop`) and confirms
/// `fstat` reports a socket (`S_IFSOCK`). Neither check can prove the fd
/// is *specifically* the control socket this process expects -- that
/// part is still the caller's contract -- but both are cheap,
/// unconditional defence in depth against the closest wrong-fd mistakes
/// (CTO review, OBI-184/OBI-225).
///
/// After adopting, re-sets `FD_CLOEXEC` (cleared by the supervisor's
/// [`clear_cloexec`] specifically so this process's own `exec` would
/// inherit it): nothing *this* process spawns afterwards (e.g.
/// `loom-git`'s `git` children) should also inherit the control socket.
///
/// # Safety
/// The caller must guarantee `fd` is a valid, open file descriptor that
/// this process uniquely owns -- no other `File`/`UnixStream`/etc.
/// wrapper anywhere in the process already owns the same number. The
/// returned `UnixStream` closes `fd` on `Drop`; a reused or still-aliased
/// number here is a double-close/use-after-close bug, which the `fd <=
/// 2`/`S_ISSOCK` checks above only narrow, not eliminate.
pub unsafe fn control_stream_from_raw_fd(fd: RawFd) -> io::Result<UnixStream> {
    if fd <= 2 {
        return Err(io::Error::other(format!(
            "control_stream_from_raw_fd: refusing fd {fd} (reserved for stdio)"
        )));
    }

    // SAFETY: `fstat` only reads kernel metadata about `fd`; it neither
    // takes ownership nor affects how `fd` may be used afterwards.
    let is_socket = unsafe {
        let mut stat: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut stat) != 0 {
            return Err(io::Error::last_os_error());
        }
        (stat.st_mode & libc::S_IFMT) == libc::S_IFSOCK
    };
    if !is_socket {
        return Err(io::Error::other(format!(
            "control_stream_from_raw_fd: fd {fd} is not a socket"
        )));
    }

    // SAFETY: the two checks above narrow, but the real guarantee is the
    // caller's contract documented on this function's own `# Safety`
    // section -- `fd` is open, owned by this process, and not aliased by
    // any other wrapper.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };

    // Best-effort: if re-setting FD_CLOEXEC fails, the stream is still
    // correctly constructed and usable -- not worth failing the whole
    // adoption over a now-redundant hardening step (the window where
    // this would matter, this process `exec`-ing again before setting
    // it, does not happen on `serve`'s path).
    let _ = set_cloexec(fd);

    Ok(stream)
}

/// Re-establish `FD_CLOEXEC` on `fd` (the inverse of [`clear_cloexec`]),
/// used by [`control_stream_from_raw_fd`] once it has adopted the fd.
fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: same contract as `clear_cloexec` -- `fd` is a valid, open
    // descriptor for the duration of this call, and this function
    // neither transfers ownership of it nor closes it.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let rc = libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The raw fd number behind `stream`, for logging/passing to a spawned
/// child (not ownership-transferring -- `stream` still owns and will
/// close it on `Drop`, same as [`std::os::fd::AsRawFd`] always means).
pub fn raw_fd_of(stream: &UnixStream) -> RawFd {
    stream.as_raw_fd()
}

#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks)] // test scaffolding; production unsafe above this module is fully documented, enforced by this lint
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
        // Use `bash`, not `sh` (Ubuntu's `/bin/sh` is dash): dash's `>&N`
        // redirection only parses single-digit fds and fails with
        // "Bad fd number" (exit 2) once other tests in the same process
        // have enough fds open that `child_fd` reaches double digits --
        // the exact flake seen under parallel `cargo test` (OBI-302).
        // Bash accepts multi-digit fds in `>&N`, so it isn't sensitive
        // to how many fds happen to be open already.
        let mut child = Command::new("bash")
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

    /// `control_stream_from_raw_fd` refuses `fd <= 2` (CTO review,
    /// OBI-225): stdio fds are always open in a test process, so this
    /// doesn't even need a crafted fd -- fd 1 (stdout) is right there.
    #[test]
    fn control_stream_from_raw_fd_refuses_stdio() {
        let err = unsafe { control_stream_from_raw_fd(1) }.unwrap_err();
        assert!(err.to_string().contains("stdio"));
    }

    /// `control_stream_from_raw_fd` refuses a non-socket fd (a plain
    /// pipe) via the `fstat`/`S_ISSOCK` check.
    #[test]
    fn control_stream_from_raw_fd_refuses_a_non_socket() {
        use std::os::fd::FromRawFd;
        let mut fds = [0 as RawFd; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        // Keep both ends owned so they close on scope exit either way.
        let _write_end = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let read_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };

        let err = unsafe { control_stream_from_raw_fd(read_end.as_raw_fd()) }.unwrap_err();
        assert!(err.to_string().contains("not a socket"));
    }

    /// The real, happy-path use: a socket fd, not stdio, adopted
    /// successfully and still independently usable afterwards.
    #[test]
    fn control_stream_from_raw_fd_adopts_a_real_socket() {
        let (a, b) = UnixStream::pair().unwrap();
        let b_fd = b.as_raw_fd();
        // `control_stream_from_raw_fd` takes ownership of the fd number;
        // leak `b`'s Rust-level ownership (not the fd itself) so the
        // adopted `UnixStream` is the only owner, matching the real
        // "inherited fd, no other wrapper in this process" contract.
        std::mem::forget(b);

        let mut adopted = unsafe { control_stream_from_raw_fd(b_fd) }.unwrap();
        let mut a = a;
        a.write_all(b"hi").unwrap();
        let mut buf = [0u8; 2];
        adopted.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hi");
    }
}
