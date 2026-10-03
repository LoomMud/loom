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

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn supervise_hands_off_listening_sockets_to_a_standby_child() {
    let mudlib = fixture("tworoom");
    let telnet_port = reserve_local_port();
    let http_port = reserve_local_port();
    let telnet_bind = format!("127.0.0.1:{telnet_port}");
    let http_bind = format!("127.0.0.1:{http_port}");

    let mut supervisor = Supervisor::spawn(&mudlib, &telnet_bind, &http_bind);

    // `loom supervise` binds, then spawns the standby and blocks on its
    // ready signal before handing off -- give that its own generous
    // retry budget (compiling `tworoom` plus process spawn overhead) on
    // top of the usual connect retry.
    let mut stream = connect_with_retry(&telnet_bind, Duration::from_secs(10));
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    // Just the telnet option-negotiation preamble (OBI-26: `DO NAWS`, `DO
    // TTYPE`, `WILL GMCP`, `WILL MSSP` -- 12 bytes) is enough: proves the
    // standby child's `World`/`loom-net` stack is really the one serving
    // this connection, not a hung/empty accept.
    let mut preamble = [0_u8; 12];
    stream
        .read_exact(&mut preamble)
        .expect("read telnet negotiation preamble from the handed-off socket");

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
    let telnet_port = reserve_local_port();
    let http_port = reserve_local_port();
    let telnet_bind = format!("127.0.0.1:{telnet_port}");
    let http_bind = format!("127.0.0.1:{http_port}");

    let mut supervisor = Supervisor::spawn(&mudlib, &telnet_bind, &http_bind);

    let mut stream = connect_with_retry(&telnet_bind, Duration::from_secs(10));
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut preamble = [0_u8; 12];
    stream
        .read_exact(&mut preamble)
        .expect("read telnet negotiation preamble before sending SIGTERM");

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
    let telnet_port = reserve_local_port();
    let http_port = reserve_local_port();
    let telnet_bind = format!("127.0.0.1:{telnet_port}");
    let http_bind = format!("127.0.0.1:{http_port}");

    let mut supervisor = Supervisor::spawn(&mudlib, &telnet_bind, &http_bind);

    let mut stream = connect_with_retry(&telnet_bind, Duration::from_secs(10));
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut preamble = [0_u8; 12];
    stream
        .read_exact(&mut preamble)
        .expect("read telnet negotiation preamble before SIGKILLing the supervisor");

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
    let telnet_port = reserve_local_port();
    let http_port = reserve_local_port();
    let telnet_bind = format!("127.0.0.1:{telnet_port}");
    let http_bind = format!("127.0.0.1:{http_port}");

    let mut supervisor = Supervisor::spawn(&mudlib, &telnet_bind, &http_bind);

    let mut stream = connect_with_retry(&telnet_bind, Duration::from_secs(10));
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut preamble = [0_u8; 12];
    stream
        .read_exact(&mut preamble)
        .expect("read telnet negotiation preamble before crashing the child");

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
    reconnected
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    reconnected
        .read_exact(&mut preamble)
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
    let telnet_port = reserve_local_port();
    let http_port = reserve_local_port();
    let telnet_bind = format!("127.0.0.1:{telnet_port}");
    let http_bind = format!("127.0.0.1:{http_port}");

    let mut supervisor = Supervisor::spawn(&mudlib, &telnet_bind, &http_bind);

    let mut stream = connect_with_retry(&telnet_bind, Duration::from_secs(10));
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut preamble = [0_u8; 12];
    stream
        .read_exact(&mut preamble)
        .expect("read telnet negotiation preamble before crashing the child");

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
    let telnet_port = reserve_local_port();
    let http_port = reserve_local_port();
    let telnet_bind = format!("127.0.0.1:{telnet_port}");
    let http_bind = format!("127.0.0.1:{http_port}");

    let version_dir = scratch("version-watch");
    let version_file = version_dir.join("desired-version");
    std::fs::write(&version_file, "v1.0.0\n").expect("write initial desired-version");

    let (mut supervisor, stdout) =
        Supervisor::spawn_with_version_file(&mudlib, &telnet_bind, &http_bind, &version_file);

    // Confirm the standby child is really up before touching the
    // version file, so a later failure can't be "it never booted" in
    // disguise.
    let mut stream = connect_with_retry(&telnet_bind, Duration::from_secs(10));
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut preamble = [0_u8; 12];
    stream
        .read_exact(&mut preamble)
        .expect("read telnet negotiation preamble before changing the version file");

    // A background thread drains stdout into a channel, since reading
    // it directly on this thread would block waiting for more output
    // right when the test needs to also act (write the file) and poll
    // (read lines with an overall timeout).
    let (line_tx, line_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });

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
    let telnet_port = reserve_local_port();
    let http_port = reserve_local_port();
    let telnet_bind = format!("127.0.0.1:{telnet_port}");
    let http_bind = format!("127.0.0.1:{http_port}");

    let version_dir = scratch("version-watch-control");
    let version_file = version_dir.join("desired-version");
    std::fs::write(&version_file, "v1.0.0\n").expect("write initial desired-version");

    let (mut supervisor, stdout) =
        Supervisor::spawn_with_version_file(&mudlib, &telnet_bind, &http_bind, &version_file);

    let mut stream = connect_with_retry(&telnet_bind, Duration::from_secs(10));
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut preamble = [0_u8; 12];
    stream
        .read_exact(&mut preamble)
        .expect("read telnet negotiation preamble before changing the version file");

    let (line_tx, line_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });

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
    let telnet_port = reserve_local_port();
    let http_port = reserve_local_port();
    let telnet_bind = format!("127.0.0.1:{telnet_port}");
    let http_bind = format!("127.0.0.1:{http_port}");

    let version_dir = scratch("version-watch-reclaim");
    let version_file = version_dir.join("desired-version");
    std::fs::write(&version_file, "v1.0.0\n").expect("write initial desired-version");

    let (mut supervisor, stdout) =
        Supervisor::spawn_with_version_file(&mudlib, &telnet_bind, &http_bind, &version_file);

    let mut stream = connect_with_retry(&telnet_bind, Duration::from_secs(10));
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut preamble = [0_u8; 12];
    stream
        .read_exact(&mut preamble)
        .expect("read telnet negotiation preamble before changing the version file");

    let (line_tx, line_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });

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

    // The strongest possible proof the connection survived: write
    // through it *after* the round trip and read a real response.
    // Re-adopting resets telnet negotiation state (a documented
    // limitation, OBI-227's review), so the first bytes back are a
    // fresh negotiation preamble, not an echo of what was sent -- that's
    // fine and expected; what matters is that *something* comes back at
    // all, which only happens if the connection is still genuinely
    // live end to end.
    stream
        .write_all(b"look\r\n")
        .expect("write after the reclaim/readopt round trip must not error (broken pipe/reset)");
    let mut post_round_trip = [0_u8; 12];
    stream
        .read_exact(&mut post_round_trip)
        .expect("read after the reclaim/readopt round trip must not error (connection reset/EOF)");

    supervisor.assert_alive();
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

fn reserve_local_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("read local addr").port()
}

struct Supervisor {
    child: Child,
}

impl Supervisor {
    fn spawn(mudlib: &Path, telnet_bind: &str, http_bind: &str) -> Self {
        let loom_bin = std::env::var("CARGO_BIN_EXE_loom-cli")
            .or_else(|_| std::env::var("CARGO_BIN_EXE_loom_cli"))
            .expect("cargo binary path for loom-cli");

        let child = Command::new(loom_bin)
            .arg("supervise")
            .arg("--mudlib")
            .arg(mudlib)
            .env("LOOM_TELNET_ADDR", telnet_bind)
            .env("LOOM_HTTP_ADDR", http_bind)
            .env_remove("DATABASE_URL")
            .env_remove("LOOM_SMOKE_DATABASE_URL")
            .env("RUST_LOG", "")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn loom supervise");

        Self { child }
    }

    /// Like [`Self::spawn`], but with `LOOM_DESIRED_VERSION_FILE` set
    /// and `stdout` piped (not discarded) with logging turned up to
    /// `info` -- needed by the version-watch test, which has nothing
    /// else observable to assert on (OBI-184's version-watching slice
    /// is detection-only: a log line is the only externally visible
    /// effect of a detected change today). `tracing_subscriber::fmt`'s
    /// default `MakeWriter` is `io::stdout`, not `io::stderr` -- despite
    /// every other test in this file discarding both, so this is the
    /// first one where the distinction actually matters. Returns the
    /// piped stdout handle alongside the `Supervisor` so the caller can
    /// read it.
    fn spawn_with_version_file(
        mudlib: &Path,
        telnet_bind: &str,
        http_bind: &str,
        version_file: &Path,
    ) -> (Self, std::process::ChildStdout) {
        let loom_bin = std::env::var("CARGO_BIN_EXE_loom-cli")
            .or_else(|_| std::env::var("CARGO_BIN_EXE_loom_cli"))
            .expect("cargo binary path for loom-cli");

        let mut child = Command::new(loom_bin)
            .arg("supervise")
            .arg("--mudlib")
            .arg(mudlib)
            .env("LOOM_TELNET_ADDR", telnet_bind)
            .env("LOOM_HTTP_ADDR", http_bind)
            .env("LOOM_DESIRED_VERSION_FILE", version_file)
            // CTO review (OBI-256 nit): overridable rather than a fixed
            // 5s production default, so this test has real slack
            // against its own timeout instead of racing CI's timing
            // margin at the production cadence.
            .env("LOOM_VERSION_POLL_INTERVAL_MS", "200")
            .env_remove("DATABASE_URL")
            .env_remove("LOOM_SMOKE_DATABASE_URL")
            .env("RUST_LOG", "loom_cli=info")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn loom supervise");

        let stdout = child.stdout.take().expect("piped stdout");
        (Self { child }, stdout)
    }

    fn assert_alive(&mut self) {
        if let Some(status) = self.child.try_wait().expect("poll supervisor process") {
            panic!("loom supervise exited early with status {status}");
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
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
