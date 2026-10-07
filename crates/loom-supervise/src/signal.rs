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
//!
//! **Important, and previously wrong in this module's own docs (CTO
//! review, OBI-251):** `PR_SET_PDEATHSIG` tracks the specific OS
//! *thread* that registered it, not the supervisor *process* as a
//! whole. See [`set_death_signal_on_parent_exit`]'s doc for the full
//! contract this imposes on callers.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Send `SIGTERM` to a specific, known-live child process by pid.
///
/// # Errors
/// Returns the `io::Error` from `kill(2)` if the signal could not be
/// delivered (e.g. the pid has already been reaped), or an
/// `InvalidInput` error without calling `kill(2)` at all if `pid` is `0`
/// or doesn't fit in `pid_t` -- `kill`'s pid argument treats `0` and
/// negative values as process-group or "every process this caller may
/// signal" broadcasts, not a single target (CTO review, OBI-251); a
/// `u32::MAX`-range value wrapping around through `as pid_t` could
/// silently land on one of those broadcast meanings too, rather than
/// erroring the way an out-of-range pid should.
pub fn send_sigterm(pid: u32) -> io::Result<()> {
    send_signal(pid, libc::SIGTERM)
}

/// Send `SIGKILL` to a specific, known-live process by pid -- an
/// unconditional, uncatchable kill, unlike [`send_sigterm`]. Exists
/// mainly for tests that need to simulate a real crash (a `SIGTERM`
/// gives the target a chance to exit 0 gracefully, which is a
/// meaningfully different scenario from an actual crash) rather than
/// for `loom supervise`'s own normal shutdown path, which always wants
/// the graceful `SIGTERM` first.
///
/// Same validation and single-known-pid contract as [`send_sigterm`]
/// -- see its doc for the full rationale.
///
/// # Errors
/// Same as [`send_sigterm`].
pub fn send_sigkill(pid: u32) -> io::Result<()> {
    send_signal(pid, libc::SIGKILL)
}

fn send_signal(pid: u32, signal: libc::c_int) -> io::Result<()> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("pid {pid} does not fit in pid_t"),
        )
    })?;
    if pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to signal non-positive pid {pid}: 0/negative kill() targets are a \
                 process-group or broadcast send, not this function's single-known-child contract"
            ),
        ));
    }

    // SAFETY: `libc::kill` has no safe wrapper. `pid` has just been
    // checked above to be strictly positive, so this is a single-target
    // signal, never a wildcard/process-group send. The caller is
    // required to hold that child's `std::process::Child` handle alive
    // (so its pid cannot have been reused by an unrelated process the
    // way a pid read from a file or another process' `/proc` listing
    // could race) for at least as long as this call.
    let ret = unsafe { libc::kill(pid, signal) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether `err` is `ESRCH` ("no such process") -- i.e. the pid
/// [`send_sigterm`] was asked to signal had already exited on its own
/// before the `kill(2)` call reached the kernel. Exposed so callers
/// outside this crate (`loom-cli`, which has no `libc` dependency of its
/// own and whose workspace lints wouldn't let it reach into `libc`
/// error-number constants directly even if it did) can treat that
/// specific, expected race as benign without matching on
/// `io::Error::raw_os_error()`'s platform-specific integer themselves.
pub fn is_no_such_process(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::ESRCH)
}

/// Install `PR_SET_PDEATHSIG(SIGTERM)` in the *calling* process (meant to
/// run inside a freshly-`fork`ed child, before `exec`, via
/// `std::os::unix::process::CommandExt::pre_exec`): if the thread that
/// installed this exits for any reason without explicitly tearing the
/// child down first, the kernel delivers `SIGTERM` to this process
/// automatically, rather than leaving an orphaned standby/active server
/// nothing is supervising anymore.
///
/// **The tracked "parent" is a specific OS *thread*, not the supervisor
/// *process* as a whole (CTO review, OBI-251 -- this module's docs
/// previously got this wrong):** per `prctl(2)`, `PR_SET_PDEATHSIG`'s
/// signal fires when the thread that called it terminates, independent
/// of whether the process containing that thread is still running.
/// `pre_exec` runs this call once, in the single-threaded forked child,
/// which registers against whichever specific thread in the supervisor
/// called `fork` (i.e. ran `Command::spawn`). **Callers must keep that
/// exact spawning thread alive for as long as the child should be
/// tracked** -- a `tokio::task::spawn_blocking` pool thread does *not*
/// satisfy this: idle blocking-pool threads can and do exit (Tokio's
/// default keep-alive is 10s), which would silently fire `PR_SET_
/// PDEATHSIG` against a supervisor that is still very much running.
/// `loom-cli`'s caller uses one dedicated, long-lived `std::thread`
/// spanning spawn through `wait()` for exactly this reason.
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

    /// `send_sigkill` actually terminates a real child with `SIGKILL`
    /// specifically, not just "some signal" -- needed as a distinct
    /// primitive from `send_sigterm` for tests that must simulate a
    /// real crash (uncatchable, no graceful-exit chance) rather than a
    /// cooperative shutdown.
    #[test]
    fn send_sigkill_actually_terminates_the_child() {
        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("failed to spawn sleep");
        let pid = child.id();

        send_sigkill(pid).expect("send_sigkill failed");

        let status = child.wait().expect("wait failed");
        assert!(
            !status.success(),
            "child killed by SIGKILL should not report success"
        );
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                status.signal(),
                Some(libc::SIGKILL),
                "child should have been terminated by SIGKILL specifically"
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

    /// Signalling pid `0` (a process-group broadcast, not a single
    /// target) is refused before `kill(2)` is ever called -- CTO review,
    /// OBI-251.
    #[test]
    fn send_sigterm_refuses_pid_zero() {
        let err = send_sigterm(0).expect_err("pid 0 must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// A `u32` pid too large to fit in `pid_t` (`i32` on Linux) must be
    /// rejected by range-checked conversion, not silently wrapped by an
    /// `as` cast into some other, possibly meaningful, `pid_t` value
    /// (CTO review, OBI-251).
    #[test]
    fn send_sigterm_refuses_a_pid_too_large_for_pid_t() {
        let err = send_sigterm(u32::MAX).expect_err("an out-of-range pid must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// `set_death_signal_on_parent_exit`'s `prctl` call itself succeeds
    /// when invoked directly (not through `pre_exec`): a narrow,
    /// unconditionally-safe-anywhere sanity check that the syscall this
    /// module's only non-`kill` `unsafe` block makes is valid and
    /// doesn't error. The full "child dies when its specific parent
    /// *thread* exits" kernel behaviour (including the spawning-thread
    /// scoping bug this module's docs previously got wrong -- CTO
    /// review, OBI-251) is proven end to end by `loom-cli`'s
    /// `sigkill_the_supervisor_still_terminates_the_child_via_pdeathsig`
    /// integration test, against the real dedicated-thread supervisor,
    /// not a unit-test-local `fork()`.
    #[test]
    fn set_death_signal_on_parent_exit_succeeds() {
        set_death_signal_on_parent_exit().expect("prctl(PR_SET_PDEATHSIG) failed");
    }
}
