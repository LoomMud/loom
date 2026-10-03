// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Signal plumbing between `loom supervise` and its standby child (CTO
//! review, OBI-225; tracked on OBI-184): before `supervise` can replace
//! `serve` as the container entrypoint, a `SIGTERM`/`SIGINT` delivered to
//! the supervisor must reach the child doing the actual work, rather
//! than killing the supervisor and leaving `serve`'s own graceful
//! `shutdown_signal` drain (`loom-cli`'s `shutdown_signal`) never
//! triggered. And the reverse direction matters too: if the supervisor
//! itself dies unexpectedly (crash, `SIGKILL`, OOM), the child should not
//! become an orphan nobody is tracking -- `set_death_signal_on_parent_exit`
//! asks the kernel to deliver `SIGTERM` to the child automatically when
//! its parent (the supervisor) exits, via `PR_SET_PDEATHSIG`.
//!
//! Both operations have no safe equivalent in `std`/`libc`'s safe
//! wrappers (there is no `Child::kill_with_signal`, and `PR_SET_PDEATHSIG`
//! is a raw `prctl` call), so -- like [`crate::fdpass`] and
//! [`crate::listener`] -- the `unsafe` is confined to this module, with
//! every block documented.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Send `SIGTERM` to a specific, known-live child process by pid.
///
/// # Errors
/// Returns the `io::Error` from `kill(2)` if the signal could not be
/// delivered (e.g. the pid has already been reaped).
pub fn send_sigterm(pid: u32) -> io::Result<()> {
    // SAFETY: `libc::kill` has no safe wrapper. The pid is the caller's
    // own direct child (never a wildcard/process-group target, which
    // `kill`'s pid argument supports but this function deliberately
    // does not expose), and the caller is required to hold that child's
    // `std::process::Child` handle alive (so its pid cannot have been
    // reused by an unrelated process the way a pid read from a file or
    // another process' `/proc` listing could race) for at least as long
    // as this call -- `loom-cli`'s only caller does, via the
    // `tokio::task::spawn_blocking(move || child.wait())` handle it
    // still owns when it calls this.
    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Install `PR_SET_PDEATHSIG(SIGTERM)` in the *calling* process (meant to
/// run inside a freshly-`fork`ed child, before `exec`, via
/// `std::os::unix::process::CommandExt::pre_exec`): if the parent that
/// installed this (the supervisor) exits for any reason without
/// explicitly tearing the child down first, the kernel delivers
/// `SIGTERM` to this process automatically, rather than leaving an
/// orphaned standby/active server nothing is supervising anymore.
///
/// Per `prctl(2)`, the "parent" `PR_SET_PDEATHSIG` tracks is specifically
/// the thread that called it, re-parented to whatever reaps it -- for a
/// `pre_exec` callback (which `std` always runs on the single forked
/// child thread, immediately before `execve`) that is exactly "the
/// supervisor process that spawned this child", which is the intended
/// scope here.
///
/// # Errors
/// Returns the `io::Error` from `prctl(2)` on failure. A caller using
/// this from `pre_exec` must propagate that error (returning it from the
/// closure aborts the `exec`, per `std`'s documented `pre_exec`
/// contract) rather than ignore it -- silently continuing without the
/// death-signal guarantee would be the exact orphaning this function
/// exists to prevent.
pub fn set_death_signal_on_parent_exit() -> io::Result<()> {
    // SAFETY: `prctl(PR_SET_PDEATHSIG, ...)` has no safe wrapper in
    // `libc`. This is sound to call from a `pre_exec` closure: per
    // `std::os::unix::process::CommandExt::pre_exec`'s own safety
    // contract, the closure runs after `fork` on a single-threaded
    // process image (the forked child, before `execve`), so there is no
    // concurrent access to shared state to race, and `PR_SET_PDEATHSIG`
    // itself only ever affects the calling thread/process, never memory.
    let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Register `set_death_signal_on_parent_exit` as `cmd`'s `pre_exec`
/// hook, returning `cmd` for chaining. The only reason this exists
/// (rather than every caller writing `cmd.pre_exec(set_death_signal_on_
/// parent_exit)` directly) is that `CommandExt::pre_exec` is itself an
/// `unsafe fn` -- calling it at all requires an `unsafe` block -- and
/// the workspace's lint policy (`unsafe_code = "deny"` everywhere except
/// this crate) means `loom-cli`, which actually builds the `Command`,
/// cannot write that block itself. Wrapping the call here keeps every
/// `unsafe` block in this crate confined and documented, per this
/// crate's own stated reason for existing.
pub fn die_with_parent(cmd: &mut Command) -> &mut Command {
    // SAFETY: `set_death_signal_on_parent_exit`'s own doc comment states
    // its `pre_exec`-contract requirements (single-threaded forked-
    // child-before-exec context, no shared-state access) -- `pre_exec`
    // itself guarantees exactly that context to its closure, so this
    // call satisfies it.
    unsafe { cmd.pre_exec(set_death_signal_on_parent_exit) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// A real child process, killed with `send_sigterm`, actually
    /// receives `SIGTERM` and exits accordingly -- not just "the `kill`
    /// syscall returned success", but the signal was delivered and acted
    /// on.
    #[test]
    fn send_sigterm_actually_terminates_the_child() {
        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("failed to spawn sleep");
        let pid = child.id();

        send_sigterm(pid).expect("send_sigterm failed");

        let status = child.wait().expect("wait failed");
        assert!(
            !status.success(),
            "child killed by SIGTERM should not report success"
        );
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                status.signal(),
                Some(libc::SIGTERM),
                "child should have been terminated by SIGTERM specifically"
            );
        }
    }

    /// Sending a signal to a pid that's already been reaped fails
    /// cleanly (an `io::Error`), rather than panicking or silently
    /// succeeding against a possibly-reused pid.
    #[test]
    fn send_sigterm_to_an_already_reaped_pid_errors() {
        let mut child = Command::new("true").spawn().expect("failed to spawn true");
        let pid = child.id();
        let status = child.wait().expect("wait failed");
        assert!(status.success());

        // The pid is now reaped and this test doesn't race anything else
        // for it (a fresh `sleep`/`true` child above was the only thing
        // using the pid table in this process in this window), so a
        // failure here is `ESRCH`, not a false success against a reused
        // pid.
        let result = send_sigterm(pid);
        assert!(
            result.is_err(),
            "signalling an already-reaped pid should fail"
        );
    }

    /// `set_death_signal_on_parent_exit`'s `prctl` call itself succeeds
    /// when invoked directly (not through `pre_exec`, which this test
    /// deliberately avoids): the actual "child dies when its parent
    /// exits" kernel behaviour needs a real supervisor-exits-while-
    /// child-is-running scenario (two real, separately-reaped processes)
    /// to observe, which a `fork()`-in-a-multithreaded-test-harness
    /// approach can exercise but only by taking on real flakiness risk
    /// (locks held by other threads at fork time, CI sandboxes that
    /// restrict `prctl`) for a property better proven on the real
    /// supervisor/child process pair -- exactly what E2.2-docker's
    /// staging run already needs to exercise end to end. This test's
    /// scope is narrower and unconditionally safe to run anywhere: the
    /// syscall this module's only non-`kill` `unsafe` block makes is a
    /// valid call that doesn't error.
    #[test]
    fn set_death_signal_on_parent_exit_succeeds() {
        set_death_signal_on_parent_exit().expect("prctl(PR_SET_PDEATHSIG) failed");
    }
}
