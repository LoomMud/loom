// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-184 slice: `loom supervise` hands its listening sockets to a
//! standby `loom serve --adopt-control-fd <n>` child over an `SCM_RIGHTS`
//! control channel instead of letting the child bind them. This spawns
//! the real `loom` binary in `supervise` mode and proves a client can
//! connect through the socket the *supervisor* process bound and get
//! real service from the world the *child* process booted -- if the
//! hand-off were broken (wrong fd order, child never got the fds, ...)
//! the connect would simply time out, since only `supervise` binds
//! anything in this mode.
//!
//! ## Startup is a readiness barrier, not a sleep (OBI-292)
//!
//! Every test here starts with [`spawn_until_serving`], which does not
//! return until the server has *proven* it is serving: the 12-byte telnet
//! negotiation preamble has actually arrived, on a connection the test
//! then holds open. Two CI failure signatures this file used to have came
//! from not doing that.
//!
//! * `read telnet negotiation preamble: Connection reset by peer (os
//!   error 104)` -- the test connected while the supervisor was still
//!   alive, the supervisor then exited for a startup-only reason (a lost
//!   `bind` race -- see [`TEST_PORT_BAND_START`]), which closed the
//!   listener and reset the test's still-queued connection. Nothing in
//!   the CI log explained it because the supervisor's own output was
//!   piped away and thrown out.
//! * `stream did not contain valid UTF-8 (os error 526)` -- a raw telnet
//!   IAC byte landing inside a `read_line` (see [`read_until_contains`]).
//!
//! Neither is a property any test here claims to assert, so both are
//! handled where they belong: at startup. A supervisor that dies *after*
//! [`spawn_until_serving`] returns still fails its test exactly as
//! before -- that is the actual subject of OBI-184/OBI-225/OBI-251.
//!
//! Capturing that output is what surfaced a third race, in the
//! version-watch tests: `supervise` seeds its desired-version baseline
//! from the *running* build (deliberately, CTO review on OBI-256), so a
//! file already holding `v1.0.0` looked like a change on the watcher's
//! very first tick, and the resulting unsolicited copyover request ran a
//! reclaim/readopt round trip over a connection the test was still
//! introducing. [`Supervisor::start`] now declares `LOOM_RUNNING_VERSION`
//! to match the file each test seeds, so a test gets exactly the one
//! version change it asks for.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[test]
fn supervise_hands_off_listening_sockets_to_a_standby_child() {
    let mudlib = fixture("tworoom");
    // The call itself is the assertion: `loom supervise` binds, spawns the
    // standby and blocks on its ready signal before handing off, and
    // `spawn_until_serving` does not return until the child's own
    // `World`/`loom-net` stack -- not a hung/empty accept -- has written
    // the negotiation preamble on a connection held open here.
    let (mut supervisor, _telnet_bind, _stream) = spawn_until_serving(&mudlib);

    supervisor.assert_alive();
}

/// OBI-184/OBI-225: `SIGTERM` delivered to the supervisor process must
/// reach the standby child doing the actual work, not just kill the
/// supervisor and leave the child (and its listening sockets) running
/// unsupervised. Sends a real `SIGTERM` to the supervisor's pid (via
/// `loom_supervise::signal::send_sigterm`, the same function `loom
/// supervise` itself uses) and checks both halves of the contract: the
/// supervisor exits with a *successful* status (the forwarded-signal
/// path, not an error path), and the child it was supervising stops
/// serving -- proven by the telnet port refusing new connections
/// afterwards, since nothing else in this test binds it.
#[test]
fn sigterm_to_the_supervisor_is_forwarded_to_the_child_and_both_exit() {
    let mudlib = fixture("tworoom");
    let (mut supervisor, telnet_bind, _stream) = spawn_until_serving(&mudlib);

    loom_supervise::signal::send_sigterm(supervisor.child.id())
        .expect("send SIGTERM to the supervisor process");

    let status = wait_with_timeout(&mut supervisor.child, Duration::from_secs(10))
        .expect("supervisor did not exit after SIGTERM within the timeout");
    assert!(
        status.success(),
        "supervisor should exit successfully on a forwarded shutdown signal, got {status}"
    );

    // The standby child should have received the forwarded SIGTERM too
    // and shut its own listener down -- give it a brief moment (its own
    // graceful `shutdown_signal` drain) and then confirm nothing is
    // listening on the telnet port anymore.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(&telnet_bind) {
            Err(_) => break,
            Ok(_) if Instant::now() >= deadline => panic!(
                "standby child is still accepting connections after the supervisor forwarded SIGTERM"
            ),
            Ok(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// CTO review (OBI-251): the previous unit-test-local `prctl` check in
/// `loom_supervise::signal` couldn't prove the actual kernel behaviour
/// `PR_SET_PDEATHSIG` exists for, and that module's own docs previously
/// described the wrong scope for it (process, not thread). This test
/// proves the real end-to-end property against the real supervisor
/// binary: `SIGKILL`ing the supervisor (an ungraceful death it cannot
/// catch or forward anything for -- unlike the `SIGTERM` case above,
/// where the supervisor's own signal-forwarding code runs) still leaves
/// the standby child terminated, because the kernel's `PDEATHSIG`
/// delivery doesn't go through the supervisor's own code at all. This
/// is also the regression test for the OBI-251 bug itself: with the
/// previous `spawn_blocking`-pool-thread implementation, the pool
/// thread that registered `PR_SET_PDEATHSIG` could have already exited
/// well before this point, which would have fired the death signal
/// early rather than only now -- not something this specific test
/// distinguishes from "it works", but the dedicated-thread fix is what
/// makes the *timing* of this test (sending `SIGKILL` only after the
/// child is confirmed up and serving) a meaningful check at all, rather
/// than passing coincidentally.
#[test]
fn sigkill_the_supervisor_still_terminates_the_child_via_pdeathsig() {
    let mudlib = fixture("tworoom");
    let (mut supervisor, telnet_bind, _stream) = spawn_until_serving(&mudlib);

    // `Child::kill()` is `SIGKILL`, not `SIGTERM` -- the supervisor gets
    // no chance to run any of its own forwarding code.
    supervisor
        .child
        .kill()
        .expect("SIGKILL the supervisor process");
    let status = wait_with_timeout(&mut supervisor.child, Duration::from_secs(10))
        .expect("supervisor did not exit after SIGKILL within the timeout");
    assert!(
        !status.success(),
        "a SIGKILLed supervisor should not report a successful exit status"
    );

    // The kernel delivers PDEATHSIG to the child independently of
    // anything the (now-dead) supervisor's own code does -- give that a
    // moment and confirm the telnet port stops accepting.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(&telnet_bind) {
            Err(_) => break,
            Ok(_) if Instant::now() >= deadline => panic!(
                "standby child is still accepting connections after its supervisor was SIGKILLed -- PR_SET_PDEATHSIG did not fire"
            ),
            Ok(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// CTO review (OBI-184 respawn-on-crash slice, revised per OBI-253):
/// a standby child that exits without the supervisor ever having asked
/// it to (a real crash, simulated here with `SIGKILL` -- not `SIGTERM`,
/// which would let the child exit 0 gracefully instead of actually
/// crashing) is respawned against the *same* already-bound listening
/// sockets, not left down. Proves this by killing the real standby
/// child's real pid (found via `/proc`, not the supervisor's pid --
/// `send_sigterm`ing the supervisor itself is the already-covered
/// graceful-shutdown path) and then reconnecting: a stale connection
/// breaks, but the telnet port comes back up and serves a fresh
/// connection again shortly after, without the test ever restarting
/// `loom supervise` itself.
#[test]
fn standby_child_crash_is_respawned_against_the_same_listener() {
    let mudlib = fixture("tworoom");
    let (mut supervisor, telnet_bind, mut stream) = spawn_until_serving(&mudlib);

    let child_pid = find_child_pid(supervisor.child.id(), Duration::from_secs(5))
        .expect("did not find the standby child's pid under /proc");
    loom_supervise::signal::send_sigkill(child_pid).expect("SIGKILL the standby child directly");

    // The killed connection eventually observes EOF/an error -- not
    // asserted directly (timing against the exact moment of the kill is
    // racy and isn't the point of this test), just drained so it can't
    // block anything below.
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut discard = [0_u8; 64];
    use std::io::Read as _;
    let _ = stream.read(&mut discard);

    // The supervisor should respawn a fresh standby against the same
    // listener -- reconnecting (with its own generous retry budget,
    // since respawn involves another full mudlib compile) must succeed
    // again, and the supervisor process itself must still be running
    // (not have given up and exited). The read timeout here (unlike the
    // plain handoff tests above) needs to cover the crash-respawn
    // sequence's own 1s backoff plus a fresh mudlib compile, not just a
    // single already-warm child's response time (CTO review, OBI-253).
    let mut reconnected = connect_with_retry(&telnet_bind, Duration::from_secs(15));
    let mut respawned_preamble = [0_u8; TELNET_PREAMBLE_LEN];
    fill_before_deadline(
        &mut reconnected,
        &mut respawned_preamble,
        Instant::now() + Duration::from_secs(15),
        &mut supervisor,
    )
    .expect("read telnet negotiation preamble from the respawned child");

    supervisor.assert_alive();
}

/// CTO review (OBI-253): a `SIGTERM`/`SIGINT` that arrives to the
/// supervisor *during* the crash-backoff sleep between respawn attempts
/// must not be silently dropped -- a previous version of `supervise`'s
/// respawn loop created a fresh `shutdown_signal()` registration on
/// every attempt (and had no listener at all during the backoff sleep
/// itself), missing any signal delivered in that gap. `loom supervise`
/// should exit promptly (without respawning again) even when the signal
/// lands in that specific window, not just when it arrives while a
/// child is actively running.
#[test]
fn sigterm_during_crash_backoff_stops_the_supervisor_without_a_further_respawn() {
    let mudlib = fixture("tworoom");
    let (mut supervisor, telnet_bind, _stream) = spawn_until_serving(&mudlib);

    let child_pid = find_child_pid(supervisor.child.id(), Duration::from_secs(5))
        .expect("did not find the standby child's pid under /proc");
    loom_supervise::signal::send_sigkill(child_pid).expect("SIGKILL the standby child directly");

    // Right after the crash, the supervisor is in (or about to enter)
    // its 1s crash-backoff sleep -- send the shutdown signal into
    // exactly that window, not before the crash (already covered by the
    // plain SIGTERM test) and not long enough after that a respawned
    // child would already be back up.
    std::thread::sleep(Duration::from_millis(200));
    loom_supervise::signal::send_sigterm(supervisor.child.id())
        .expect("send SIGTERM to the supervisor during crash-backoff");

    let status = wait_with_timeout(&mut supervisor.child, Duration::from_secs(10))
        .expect("supervisor did not exit after a SIGTERM sent during crash-backoff");
    assert!(
        status.success(),
        "supervisor should exit successfully on a shutdown signal received during crash-backoff, got {status}"
    );

    // No further respawn should have happened -- confirm the telnet
    // port stays down rather than a new child coming up after the
    // supervisor has already (correctly) decided to exit instead.
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if TcpStream::connect(&telnet_bind).is_ok() {
            panic!(
                "a new standby child came up after the supervisor received a shutdown signal \
                 during crash-backoff -- it should have exited instead of respawning again"
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Scans `/proc` for a process whose `ppid` (field 4 of `/proc/<pid>/stat`)
/// is `parent_pid`, retrying until `timeout` since the child may not have
/// been spawned (and the control-socket handoff completed) at the exact
/// moment this is called.
fn find_child_pid(parent_pid: u32, timeout: Duration) -> Option<u32> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(pid) = scan_proc_for_child(parent_pid) {
            return Some(pid);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn scan_proc_for_child(parent_pid: u32) -> Option<u32> {
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        // Field 2 (`comm`) is parenthesized and may itself contain
        // spaces/parens, so the only reliable split point is the *last*
        // `)` -- everything after it is space-separated fixed fields,
        // and `ppid` is the first of those (field 4 overall).
        let Some(after_comm) = stat.rsplit_once(')').map(|(_, rest)| rest) else {
            continue;
        };
        let mut fields = after_comm.split_whitespace();
        let _state = fields.next();
        let Some(ppid_str) = fields.next() else {
            continue;
        };
        if ppid_str.parse::<u32>() == Ok(parent_pid) {
            return Some(pid);
        }
    }
    None
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll child process") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn connect_with_retry(addr: &str, timeout: Duration) -> TcpStream {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => return stream,
            Err(err) if Instant::now() < deadline => {
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::TimedOut
                ) {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                panic!("failed to connect to {addr}: {err}");
            }
            Err(err) => panic!("failed to connect to {addr} before timeout: {err}"),
        }
    }
}

/// OBI-184 version-watching slice: `loom supervise`, given
/// `LOOM_DESIRED_VERSION_FILE`, actually detects a change written to
/// that file while it's running -- not just "the unit-tested
/// `VersionWatcher` logic is correct in isolation", but that `supervise`
/// really reads the env var, builds a real `FileVersionSource` against
/// the real path, and its background poll task really observes a real
/// write. Detection is the only thing to assert on (no copyover is
/// triggered yet -- see `run_one_child_attempt`'s doc comment), so this
/// greps the supervisor's own log output for the change it reports.
#[test]
fn version_file_change_is_detected_and_logged() {
    let mudlib = fixture("tworoom");
    let version_dir = scratch("version-watch");
    let version_file = version_dir.join("desired-version");
    // Must match `DESIRED_VERSION_INITIAL` (what `Supervisor::start`
    // declares as this supervisor's own running version), so booting is
    // not itself a "change".
    std::fs::write(&version_file, format!("{DESIRED_VERSION_INITIAL}\n"))
        .expect("write initial desired-version");

    // Confirms the standby child is really up and serving before the
    // version file is touched, so a later failure can't be "it never
    // booted" in disguise. `line_rx` streams the supervisor's own stdout:
    // reading it directly on this thread would block waiting for more
    // output right when the test needs to also act (write the file) and
    // poll (read lines with an overall timeout), which is why it is
    // drained on a dedicated thread (`drain_pipe`).
    let (mut supervisor, _telnet_bind, _stream, line_rx) =
        spawn_until_serving_with_version_file(&mudlib, &version_file);

    std::fs::write(&version_file, "v2.0.0\n").expect("write updated desired-version");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_change = false;
    while Instant::now() < deadline {
        match line_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                if line.contains("desired version changed") && line.contains("v2.0.0") {
                    saw_change = true;
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    assert!(
        saw_change,
        "supervisor never logged detecting the desired-version file change to v2.0.0"
    );
    // Detection-only: the original child must still be the one serving
    // (no copyover was triggered), and the supervisor itself must still
    // be running.
    supervisor.assert_alive();
}

/// OBI-184 control-protocol slice: a detected version change is now
/// forwarded as a real `ControlMessage::CopyoverRequested` over the
/// control socket to the already-running child, which now takes a real
/// snapshot of its own running world (via the world thread's snapshot-
/// request channel) before acknowledging -- not yet an actual copyover
/// (see `run_one_child_attempt`'s and `run_control_responder`'s own doc
/// comments for the honest scope: no reclaim, no handoff to a standby
/// yet), but a real round trip over a control channel that stays open
/// past the initial handoff, proven end to end: the supervisor's
/// "forwarding a copyover request" log, the child's own "world snapshot
/// taken" log (with a real, nonzero byte count -- not a stand-in value),
/// and the supervisor's "child acknowledged" log (only possible if the
/// request reached the child, a real snapshot was taken, and the reply
/// came back) must all appear.
#[test]
fn version_change_is_forwarded_over_the_control_socket_and_acknowledged() {
    let mudlib = fixture("tworoom");
    let version_dir = scratch("version-watch-control");
    let version_file = version_dir.join("desired-version");
    // Must match `DESIRED_VERSION_INITIAL` (what `Supervisor::start`
    // declares as this supervisor's own running version), so booting is
    // not itself a "change".
    std::fs::write(&version_file, format!("{DESIRED_VERSION_INITIAL}\n"))
        .expect("write initial desired-version");

    let (mut supervisor, _telnet_bind, mut stream, line_rx) =
        spawn_until_serving_with_version_file(&mudlib, &version_file);

    std::fs::write(&version_file, "v2.0.0\n").expect("write updated desired-version");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_forwarded = false;
    let mut saw_snapshot_taken = false;
    let mut saw_acknowledged = false;
    while Instant::now() < deadline && !(saw_forwarded && saw_snapshot_taken && saw_acknowledged) {
        match line_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(raw_line) => {
                // `tracing_subscriber`'s `fmt` layer applies ANSI colour
                // codes unconditionally (not just when the writer is a
                // terminal), which would otherwise split a literal
                // `"snapshot_bytes="` search across escape sequences --
                // strip them once up front so every check below can use
                // plain substring/field matching.
                let line = strip_ansi(&raw_line);
                if line.contains("forwarding a copyover request") && line.contains("v2.0.0") {
                    saw_forwarded = true;
                }
                if line.contains("world snapshot taken for the copyover request")
                    && line.contains("v2.0.0")
                {
                    // `snapshot_bytes=0` would itself match a bare
                    // `.contains("snapshot_bytes")` check, so this
                    // extracts the actual field value and asserts it's
                    // nonzero -- a real `tworoom` boot has at least a
                    // master object and the connected player, so an
                    // empty/stub snapshot would be a real bug here, not
                    // a fluke of what got connected.
                    let bytes: usize = line
                        .split("snapshot_bytes=")
                        .nth(1)
                        .and_then(|rest| rest.split_whitespace().next())
                        .and_then(|num| num.parse().ok())
                        .unwrap_or_else(|| panic!("could not parse snapshot_bytes out of: {line}"));
                    assert!(
                        bytes > 0,
                        "expected a real, nonzero snapshot size, got {bytes} (line: {line})"
                    );
                    saw_snapshot_taken = true;
                }
                if line.contains("child acknowledged the copyover request")
                    && line.contains("v2.0.0")
                {
                    saw_acknowledged = true;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    assert!(
        saw_forwarded,
        "supervisor never logged forwarding the copyover request to the child"
    );
    assert!(
        saw_snapshot_taken,
        "child never logged taking a real world snapshot for the copyover request"
    );
    assert!(
        saw_acknowledged,
        "supervisor never logged the child's acknowledgement -- the control-socket round trip did not complete"
    );
    // The control-protocol round trip doesn't touch the actual telnet
    // connection -- CTO review (OBI-259 nit): assert that explicitly
    // (a timeout here is the expected/correct outcome; an immediate `Ok`
    // read of 0 bytes would mean the connection was unexpectedly closed)
    // rather than silently discarding whatever `read` returns.
    let mut post_ack = [0_u8; 1];
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    match stream.read(&mut post_ack) {
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) => {}
        // Any further application bytes (e.g. trailing telnet
        // negotiation) are fine too -- the only outcome that would mean
        // the connection broke is a clean `Ok(0)` (EOF).
        Ok(n) if n > 0 => {}
        other => panic!(
            "expected the telnet connection to still be open (a read timeout or more data), got {other:?}"
        ),
    }
    supervisor.assert_alive();
}

/// OBI-184 (copyover-trigger slice): the reclaim/readopt round trip a
/// copyover request now exercises must actually keep a live client
/// connection alive, not just *claim* to in a log line -- §7.5's own
/// acceptance bar is literally "zero disconnects". Proves it with a
/// real write *through* the reclaimed-and-readopted connection after
/// the round trip completes: if `loom-net`'s reclaim/adopt primitives
/// had actually dropped the socket (rather than reuniting and handing
/// it back), this would see a connection-reset/broken-pipe error
/// instead of a successful round trip.
#[test]
fn reclaim_and_readopt_round_trip_keeps_the_connection_alive() {
    let mudlib = fixture("tworoom");
    let version_dir = scratch("version-watch-reclaim");
    let version_file = version_dir.join("desired-version");
    // Must match `DESIRED_VERSION_INITIAL` (what `Supervisor::start`
    // declares as this supervisor's own running version), so booting is
    // not itself a "change".
    std::fs::write(&version_file, format!("{DESIRED_VERSION_INITIAL}\n"))
        .expect("write initial desired-version");

    let (mut supervisor, _telnet_bind, stream, line_rx) =
        spawn_until_serving_with_version_file(&mudlib, &version_file);
    let mut reader = std::io::BufReader::new(stream);

    // CTO review (OBI-266/B2): the real regression this test must be
    // able to catch is session state -- `NetEvent::Connected` firing on
    // readopt would log the player back in as a *fresh* character via
    // master `connect()`, not just drop the connection. Detecting that
    // needs to check what the session actually is, not just that bytes
    // came back. Establish real, specific state first: `logon()` sends
    // "Welcome to Loom!" and starts the player in the hall; move north
    // into the yard before triggering the round trip.
    read_until_contains(&mut reader, "Welcome to Loom!", Duration::from_secs(5));
    read_until_contains(&mut reader, "Exits:", Duration::from_secs(2)); // the hall's own look()
    send_line(&mut reader, "go north");
    let moved = read_until_contains(&mut reader, "Exits:", Duration::from_secs(2));
    assert!(
        moved.contains("The Yard"),
        "expected 'go north' to move into the yard, got:\n{moved}"
    );

    std::fs::write(&version_file, "v2.0.0\n").expect("write updated desired-version");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut reclaimed_count: Option<usize> = None;
    while Instant::now() < deadline && reclaimed_count.is_none() {
        match line_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(raw_line) => {
                let line = strip_ansi(&raw_line);
                if line.contains("reclaim/readopt round trip complete") && line.contains("v2.0.0") {
                    let reclaimed: usize = line
                        .split("reclaimed=")
                        .nth(1)
                        .and_then(|rest| rest.split_whitespace().next())
                        .and_then(|num| num.parse().ok())
                        .unwrap_or_else(|| panic!("could not parse reclaimed out of: {line}"));
                    reclaimed_count = Some(reclaimed);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    assert_eq!(
        reclaimed_count,
        Some(1),
        "expected exactly the one connected test client to be reclaimed and readopted"
    );

    // CTO review (OBI-266/B2): the actual assertion that would have
    // caught B1 -- `look` right after the round trip must show the
    // *same session*, still in the yard (not teleported back to the
    // hall by a fresh `logon()`), and must *not* see a second "Welcome
    // to Loom!" anywhere in the transcript (a fresh `connect()`/`logon()`
    // would send exactly that). Re-adopting does still reset the telnet
    // *codec*'s own negotiation state (a separate, already-documented
    // limitation, OBI-227's review) -- drain that fresh preamble first
    // (same fixed 12-byte shape as the very first one, since it's the
    // same `TelnetCodec::start()` call every new `run_connection` task
    // makes) so the line-based reads below see only real text.
    // OBI-302 triage: this must read through the `BufReader`, not its
    // underlying socket directly. `reader.get_mut().read_exact(..)` reads
    // from the raw fd and skips whatever the `BufReader` had already
    // buffered ahead of the last `read_line` call that found "Exits:" --
    // on a slow/loaded CI runner the fresh preamble bytes can already be
    // sitting in that internal buffer by the time we get here, so reading
    // from the raw socket instead reads *past* them into real response
    // text, desyncing every read after this one (the intermittent "stream
    // did not contain valid UTF-8" failure). `Read::read_exact` on the
    // `BufReader` itself drains its internal buffer first, then falls
    // through to the socket only for whatever's left.
    let mut fresh_preamble = [0_u8; 12];
    reader
        .read_exact(&mut fresh_preamble)
        .expect("read the fresh telnet negotiation preamble the readopt triggers");
    send_line(&mut reader, "look");
    let transcript = read_until_contains(&mut reader, "Exits:", Duration::from_secs(5));
    assert!(
        transcript.contains("The Yard"),
        "expected the reclaimed/readopted session to still be in the yard, got:\n{transcript}"
    );
    assert!(
        !transcript.contains("Welcome to Loom!"),
        "a second 'Welcome to Loom!' means the reclaim/readopt round trip re-ran logon() on a \
         fresh player instead of preserving the existing session (CTO review, OBI-266/B1), got:\n{transcript}"
    );

    supervisor.assert_alive();
}

/// Drains one pipe of the supervisor's output into its [`Supervisor::log`]
/// (and, for the version-watch spawns, a channel of the same lines) on a
/// dedicated thread. Keeps the last [`SUPERVISOR_LOG_KEEP_LINES`] lines so
/// a long-running server can't grow the buffer without bound.
///
/// The drain never stops early -- not even when the channel's receiver is
/// gone -- because a full pipe buffer would block the supervisor itself
/// writing to its own stdout.
fn drain_pipe<R: Read + Send + 'static>(
    pipe: R,
    log: Arc<Mutex<Vec<String>>>,
    lines: Option<std::sync::mpsc::Sender<String>>,
) {
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(pipe).lines().map_while(Result::ok) {
            {
                let mut buf = log.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if buf.len() >= SUPERVISOR_LOG_KEEP_LINES {
                    buf.remove(0);
                }
                buf.push(line.clone());
            }
            if let Some(sender) = &lines {
                let _ = sender.send(line);
            }
        }
    });
}

/// Spawns `loom supervise` on freshly reserved ports and does not return
/// until the standby child has proven it is really serving: the caller
/// gets back a live connection on which the telnet negotiation preamble
/// has already been read (see [`TELNET_PREAMBLE_LEN`]).
///
/// OBI-292: a supervisor that dies or goes quiet *before* ever serving is
/// a startup problem, not a result -- it gets torn down and a fresh one is
/// started on fresh ports, up to [`MAX_STARTUP_ATTEMPTS`] times. Every
/// failed attempt's own output is carried into the panic message, so the
/// reason (`failed to bind ...`, `waiting for standby ready signal: ...`)
/// is in the CI log instead of thrown away.
fn spawn_until_serving(mudlib: &Path) -> (Supervisor, String, TcpStream) {
    let (supervisor, telnet_bind, stream, _lines) = spawn_until_serving_inner(mudlib, None);
    (supervisor, telnet_bind, stream)
}

/// [`spawn_until_serving`] for the version-watch tests: also returns the
/// live stream of the supervisor's stdout lines.
fn spawn_until_serving_with_version_file(
    mudlib: &Path,
    version_file: &Path,
) -> (
    Supervisor,
    String,
    TcpStream,
    std::sync::mpsc::Receiver<String>,
) {
    let (supervisor, telnet_bind, stream, lines) =
        spawn_until_serving_inner(mudlib, Some(version_file));
    (
        supervisor,
        telnet_bind,
        stream,
        lines.expect("a version-file spawn always builds a line receiver"),
    )
}

fn spawn_until_serving_inner(
    mudlib: &Path,
    version_file: Option<&Path>,
) -> (
    Supervisor,
    String,
    TcpStream,
    Option<std::sync::mpsc::Receiver<String>>,
) {
    let mut attempts = Vec::new();
    for attempt in 1..=MAX_STARTUP_ATTEMPTS {
        let telnet_bind = bind_string(reserve_local_port());
        let http_bind = bind_string(reserve_local_port());
        let (mut supervisor, lines) =
            Supervisor::start(mudlib, &telnet_bind, &http_bind, version_file);
        match wait_until_serving(&mut supervisor, &telnet_bind) {
            Ok(stream) => return (supervisor, telnet_bind, stream, lines),
            Err(reason) => {
                let log = supervisor.captured_log();
                // `Drop` kills whatever is still running and releases both
                // ports before the next attempt binds new ones.
                drop(supervisor);
                attempts.push(format!(
                    "attempt {attempt}/{MAX_STARTUP_ATTEMPTS} on {telnet_bind}: {reason}\n\
                     --- supervisor output ---\n{log}"
                ));
            }
        }
    }
    panic!(
        "`loom supervise` never served through {MAX_STARTUP_ATTEMPTS} startup attempts:\n{}",
        attempts.join("\n===\n")
    );
}

/// Connects to `telnet_bind` and holds that one connection open until the
/// server has written the whole negotiation preamble, reporting the reason
/// it gave up rather than panicking so [`spawn_until_serving_inner`] can
/// decide whether to retry.
fn wait_until_serving(supervisor: &mut Supervisor, telnet_bind: &str) -> Result<TcpStream, String> {
    let deadline = Instant::now() + READY_BUDGET;
    // Exactly one connection for the whole attempt. Connecting *again*
    // would queue a second entry on the listener's backlog, and the child
    // accepts the oldest entry first -- so a reconnect loop can hand the
    // preamble to a socket the test already dropped and then time out on
    // the one it kept.
    let mut stream = loop {
        match TcpStream::connect(telnet_bind) {
            Ok(stream) => break stream,
            Err(err) => {
                if let Some(status) = supervisor.exited() {
                    return Err(format!(
                        "supervisor exited (status {status}) without ever listening on {telnet_bind}: {err}"
                    ));
                }
                if Instant::now() >= deadline {
                    return Err(format!("never listened on {telnet_bind}: {err}"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };
    let mut preamble = [0_u8; TELNET_PREAMBLE_LEN];
    fill_before_deadline(&mut stream, &mut preamble, deadline, supervisor)?;
    // `fill_before_deadline` polls with a short read timeout; hand the
    // caller back the 2s the tests used to get from their own preamble
    // read, so nothing downstream changes shape.
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| err.to_string())?;
    Ok(stream)
}

/// Reads until `buf` is full, or reports why it stopped. Each individual
/// read is short (`POLL_READ_TIMEOUT`) so a supervisor that dies partway
/// through the handshake -- closing the listener it dup'd to the child,
/// which resets this connection -- is reported in milliseconds rather
/// than at the deadline; the process is polled for exactly that between
/// reads.
fn fill_before_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
    supervisor: &mut Supervisor,
) -> Result<(), String> {
    const POLL_READ_TIMEOUT: Duration = Duration::from_millis(250);
    stream
        .set_read_timeout(Some(POLL_READ_TIMEOUT))
        .map_err(|err| err.to_string())?;
    let mut received = 0;
    while received < buf.len() {
        match stream.read(&mut buf[received..]) {
            Ok(0) => {
                return Err(format!(
                    "server closed the connection after {received} of {} bytes",
                    buf.len()
                ));
            }
            Ok(n) => received += n,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                // A supervisor that dies mid-handshake closes the listener
                // it dup'd to the child, which *resets* this connection --
                // poll for that here rather than waiting out the deadline
                // so a retry can start immediately.
                if let Some(status) = supervisor.exited() {
                    return Err(format!(
                        "supervisor exited (status {status}) after the test connected but before serving \
                         -- closing the listener is what resets this connection"
                    ));
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "nothing more after the startup deadline (got {received} of {} bytes)",
                        buf.len()
                    ));
                }
            }
            Err(err) => return Err(format!("read failed after {received} bytes: {err}")),
        }
    }
    Ok(())
}

/// `BufReader<TcpStream>`-based line read with a needle, tolerating
/// `\r\n`/`\n` and any leading binary noise (e.g. a fresh telnet
/// negotiation preamble after a reclaim/readopt round trip resets codec
/// state) ahead of real text -- same pattern as `net_tick.rs`'s own
/// helper of the same name, duplicated here rather than shared across
/// test binaries (each integration test file is its own crate).
///
/// OBI-292: reads bytes, not `String`s. A telnet stream is *not* text --
/// an IAC sequence landing inside one `\n`-terminated chunk used to make
/// `read_line` fail with `stream did not contain valid UTF-8 (os error
/// 526)` and take the test down for a non-ASCII byte it was never meant
/// to assert on. Lossy decoding keeps the transcript usable for substring
/// matching, which is all any caller here does with it.
fn read_until_contains(
    reader: &mut std::io::BufReader<TcpStream>,
    needle: &str,
    timeout: Duration,
) -> String {
    use std::io::BufRead;
    let deadline = Instant::now() + timeout;
    let mut transcript = String::new();
    loop {
        if Instant::now() > deadline {
            panic!("timed out waiting for `{needle}`. Transcript so far:\n{transcript}");
        }
        let mut line = Vec::new();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => panic!(
                "connection closed while waiting for `{needle}`. Transcript so far:\n{transcript}"
            ),
            Ok(_) => {
                transcript.push_str(
                    &String::from_utf8_lossy(&line)
                        .to_string()
                        .replace("\r\n", "\n"),
                );
                if transcript.contains(needle) {
                    return transcript;
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(err) => panic!("socket read failed while waiting for `{needle}`: {err}"),
        }
    }
}

fn send_line(reader: &mut std::io::BufReader<TcpStream>, line: &str) {
    let stream = reader.get_mut();
    stream
        .write_all(line.as_bytes())
        .unwrap_or_else(|err| panic!("write command `{line}` failed: {err}"));
    stream
        .write_all(b"\n")
        .unwrap_or_else(|err| panic!("write newline for `{line}` failed: {err}"));
    stream
        .flush()
        .unwrap_or_else(|err| panic!("flush command `{line}` failed: {err}"));
}

/// Strips `ESC [ ... m` ANSI SGR (colour) escape sequences --
/// `tracing_subscriber`'s `fmt` layer applies them unconditionally, not
/// just when the writer is a real terminal, so any test that wants to
/// pattern-match a log line's *fields* (as opposed to substrings that
/// happen to survive being interrupted by escape codes, like a field's
/// own value) needs this first.
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next(); // consume '['
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Start of the port band these tests allocate listener ports from.
///
/// OBI-292: this used to be `bind("127.0.0.1:0")` and read back whatever
/// port the kernel picked -- a port from the *ephemeral* range
/// (`/proc/sys/net/ipv4/ip_local_port_range`, 32768-60999 on the CI
/// runners) which was released the instant the probe handle was dropped.
/// Between that release and `loom supervise` actually binding it, anything
/// else allocating an ephemeral port can win it -- including another
/// thread in this same test binary making one of the many outbound
/// `TcpStream::connect` calls these tests do, each of which takes its
/// source port from that same range and holds it in `TIME_WAIT` for a
/// minute afterwards. The supervisor then exits on `failed to bind ...:
/// Address already in use`, and the test sees either `failed to connect
/// ... before timeout` or (if it had already connected into the listener's
/// backlog) a reset. Reproduced locally at roughly one supervisor startup
/// in thirty with the box oversubscribed, with exactly the CI signature.
///
/// Allocating from a fixed band *below* the ephemeral range takes the
/// kernel's auto-allocation -- and so every outbound connection in the job
/// -- out of the contest entirely. The probe bind in
/// [`reserve_local_port`] still confirms the port is free before handing
/// it over, and skips forward if it is not.
const TEST_PORT_BAND_START: u16 = 20_000;
/// Width of [`TEST_PORT_BAND_START`]'s band -- comfortably more than the
/// handful of ports one run of this binary needs (two per test, per
/// startup attempt).
const TEST_PORT_BAND_WIDTH: u16 = 4_000;

/// Allocates the next free port in [`TEST_PORT_BAND_START`]'s band.
///
/// The cursor is process-global and atomic, so concurrent tests in this
/// binary can never be handed the same port twice; the band is entered at
/// a pid-dependent offset so separate invocations of this binary (a CI
/// re-run, another test binary's servers) don't all reach for the same
/// port first.
fn reserve_local_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static CURSOR: AtomicU16 = AtomicU16::new(0);
    let salt = std::process::id() as u16 % TEST_PORT_BAND_WIDTH;
    for _step in 0..TEST_PORT_BAND_WIDTH {
        let index = (salt + CURSOR.fetch_add(1, Ordering::Relaxed)) % TEST_PORT_BAND_WIDTH;
        let port = TEST_PORT_BAND_START + index;
        // Probe bind, held for the length of this `if` only. Nothing the
        // kernel auto-allocates can now take this port, and no other test
        // in this process will ask for it again (the cursor already moved
        // past it). The window that remains -- an unrelated process on the
        // host binding this exact port -- is not one a test can close, so
        // startup is additionally retried (`MAX_STARTUP_ATTEMPTS`).
        let probe = std::net::TcpListener::bind(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            port,
        )));
        if probe.is_ok() {
            return port;
        }
    }
    panic!(
        "no free port in the test band {TEST_PORT_BAND_START}..{}",
        TEST_PORT_BAND_START + TEST_PORT_BAND_WIDTH
    );
}

fn bind_string(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

/// How many bytes `loom serve` writes before a client has said anything:
/// the telnet option-negotiation preamble (OBI-26: `DO NAWS`, `DO TTYPE`,
/// `WILL GMCP`, `WILL MSSP` -- 12 bytes). Receiving it is the cheapest
/// proof that the standby child booted, adopted the listening sockets the
/// supervisor bound, and is really serving *this* connection -- if the
/// hand-off were broken (wrong fd order, child never got the fds) the
/// preamble never arrives.
const TELNET_PREAMBLE_LEN: usize = 12;

/// How long one startup attempt may take before it is written off. This
/// bounds the *whole* attempt -- bind, spawn the standby, compile the
/// mudlib in debug, first bytes on the wire -- so it is a liveness check
/// on the server rather than a fixed sleep; eight tests' worth of servers
/// share one 4-core runner in CI.
const READY_BUDGET: Duration = Duration::from_secs(30);

/// How many times [`spawn_until_serving`] will tear down a supervisor that
/// died or went quiet before it ever served, and start a fresh one on
/// fresh ports.
const MAX_STARTUP_ATTEMPTS: usize = 3;

/// How many lines of a supervisor's own output to keep for post-mortem.
const SUPERVISOR_LOG_KEEP_LINES: usize = 400;

/// The version string the version-watch tests start their
/// desired-version file at (and which [`Supervisor::start`] tells the
/// supervisor is its own running version, so only the *change* each test
/// writes is a change -- see the comment at that env var's use site).
const DESIRED_VERSION_INITIAL: &str = "v1.0.0";

struct Supervisor {
    child: Child,
    /// The supervisor's stdout+stderr, kept so a failure can say *why*.
    /// OBI-292: both used to be `Stdio::null()`, which is why every CI
    /// failure in this file was undiagnosable from its log -- the one line
    /// that named the cause (`supervise: failed to bind ...: Address
    /// already in use`) was thrown away.
    log: Arc<Mutex<Vec<String>>>,
}

impl Supervisor {
    /// Spawns the real `loom` binary in `supervise` mode on the two given
    /// binds. `version_file: None` runs the plain supervisor; `Some(_)`
    /// additionally sets `LOOM_DESIRED_VERSION_FILE` and turns logging up
    /// to `info`, because the version-watch tests have nothing else
    /// observable to assert on (OBI-184's version-watching slice was
    /// detection-only for a long time: a log line was the only externally
    /// visible effect of a detected change). `tracing_subscriber::fmt`'s
    /// default `MakeWriter` is `io::stdout`, not `io::stderr` -- despite
    /// every other test in this file discarding both, so that is the first
    /// place the distinction actually mattered.
    ///
    /// Both shapes pipe stdout *and* stderr into [`Supervisor::log`] --
    /// nothing discards the server's output any more -- and the
    /// version-file shape additionally streams stdout's lines to the
    /// caller as a `Receiver<String>` (ANSI codes still in them: callers
    /// `strip_ansi`), rather than handing back the raw pipe, which the log
    /// drain now owns. Tests should not call this directly: use
    /// [`spawn_until_serving`], which is the same thing plus the readiness
    /// barrier.
    fn start(
        mudlib: &Path,
        telnet_bind: &str,
        http_bind: &str,
        version_file: Option<&Path>,
    ) -> (Self, Option<std::sync::mpsc::Receiver<String>>) {
        let loom_bin = std::env::var("CARGO_BIN_EXE_loom-cli")
            .or_else(|_| std::env::var("CARGO_BIN_EXE_loom_cli"))
            .expect("cargo binary path for loom-cli");

        let mut cmd = Command::new(loom_bin);
        cmd.arg("supervise")
            .arg("--mudlib")
            .arg(mudlib)
            .env("LOOM_TELNET_ADDR", telnet_bind)
            .env("LOOM_HTTP_ADDR", http_bind)
            .env_remove("DATABASE_URL")
            .env_remove("LOOM_SMOKE_DATABASE_URL");

        // The version-watch tests assert on log *lines* as they arrive,
        // so their stdout is streamed to a channel as well as logged;
        // a plain spawn only needs the log.
        let (line_tx, line_rx) = match version_file {
            None => {
                cmd.env("RUST_LOG", "");
                (None, None)
            }
            Some(path) => {
                cmd.env("LOOM_DESIRED_VERSION_FILE", path)
                    // OBI-292: declare this supervisor's own running
                    // version as the same string every version-watch test
                    // seeds its desired-version file with. Without it the
                    // baseline is the crate version (0.0.1, from
                    // `running_version_from_env`), so the file's *initial*
                    // content already differs from it and the very first
                    // poll -- `tokio::time::interval`'s tick 0 fires
                    // immediately, so as soon as the child is up --
                    // reports a change nobody made and triggers a
                    // reclaim/readopt round trip on a connection the test
                    // is still introducing. That is `supervise`'s
                    // documented behaviour (CTO review, OBI-256: seed from
                    // the running build's own identity, deliberately), it
                    // is simply not what these tests are trying to
                    // exercise: they want exactly one change, the one they
                    // write.
                    .env("LOOM_RUNNING_VERSION", DESIRED_VERSION_INITIAL)
                    // CTO review (OBI-256 nit): overridable rather than a
                    // fixed 5s production default, so the version tests
                    // have real slack against their own timeouts instead
                    // of racing CI's timing margin at the production
                    // cadence.
                    .env("LOOM_VERSION_POLL_INTERVAL_MS", "200")
                    .env("RUST_LOG", "loom_cli=info");
                let (tx, rx) = std::sync::mpsc::channel::<String>();
                (Some(tx), Some(rx))
            }
        };

        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn loom supervise");

        let log = Arc::new(Mutex::new(Vec::new()));
        drain_pipe(
            child.stdout.take().expect("piped stdout"),
            Arc::clone(&log),
            line_tx,
        );
        drain_pipe(
            child.stderr.take().expect("piped stderr"),
            Arc::clone(&log),
            None,
        );

        (Self { child, log }, line_rx)
    }

    /// Fails the test if the supervisor process has already exited -- the
    /// standing invariant every test here re-checks at the end, since
    /// giving up on a child that keeps crashing is a supervisor bug, not
    /// a passing test.
    fn assert_alive(&mut self) {
        if let Some(status) = self.child.try_wait().expect("poll supervisor process") {
            panic!("loom supervise exited early with status {status}");
        }
    }

    /// The supervisor's exit status if it has already exited -- unlike
    /// [`Self::assert_alive`], safe to ask while a startup attempt is
    /// still in flight, which is what makes a dead-on-arrival supervisor
    /// reportable in milliseconds instead of at the readiness deadline.
    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    fn captured_log(&self) -> String {
        let lines = self
            .log
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Stripped on the way out so the post-mortem is readable rather
        // than a wall of colour codes.
        lines
            .iter()
            .map(|line| strip_ansi(line))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        // OBI-292: a panicking test used to leave behind nothing but the
        // panic's own message. Print what the server said instead --
        // captured output only surfaces (to `cargo test`'s failure
        // report) when the test actually fails, so this is free on the
        // green path.
        if std::thread::panicking() {
            eprintln!(
                "`loom supervise` (pid {}) output before this test failed:\n{}",
                self.child.id(),
                self.captured_log()
            );
        }
        // `loom supervise` forwards SIGTERM/SIGINT to its standby child
        // (OBI-184/OBI-225) and exits once the child does -- but a test
        // that panicked before reaching that point, or one that doesn't
        // exercise the signal path at all, still needs a hard cleanup
        // so it can't leak the process (and the listening sockets) past
        // the test.
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn fixture(name: &str) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let dir = scratch(name);
    copy_dir(&src, &dir);
    dir
}

fn scratch(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "loom-supervise-handoff-{}-{name}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn copy_dir(src: &Path, dst: &Path) {
    for entry in std::fs::read_dir(src).expect("read fixture dir") {
        let entry = entry.expect("read fixture entry");
        let file_type = entry.file_type().expect("read file type");
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            std::fs::create_dir_all(&dst_path).expect("create fixture subdir");
            copy_dir(&entry.path(), &dst_path);
        } else {
            std::fs::copy(entry.path(), &dst_path).expect("copy fixture file");
        }
    }
}

/// OBI-292 regression guard for the port allocator itself: the ports a
/// test hands to `loom supervise` must come from the non-ephemeral band
/// (so the kernel can never hand one of them to an outbound connection)
/// and must be distinct within a process (so two tests in the same
/// `cargo test` run can't be told the same port). The old implementation
/// was `TcpListener::bind("127.0.0.1:0")` + drop, which satisfies neither
/// invariant and is what made CI's `EADDRINUSE` startup failures possible.
#[test]
fn reserved_test_ports_stay_in_the_non_ephemeral_band() {
    const SAMPLE: usize = 64;
    let ports: Vec<u16> = (0..SAMPLE).map(|_| reserve_local_port()).collect();
    for port in &ports {
        assert!(
            *port >= TEST_PORT_BAND_START && *port < TEST_PORT_BAND_START + TEST_PORT_BAND_WIDTH,
            "port {port} is outside the test band"
        );
        assert!(
            *port < 32_768,
            "port {port} sits in the Linux ephemeral range"
        );
    }
    let unique: std::collections::HashSet<u16> = ports.iter().copied().collect();
    assert_eq!(
        unique.len(),
        ports.len(),
        "reserve_local_port handed out the same port twice"
    );
}
