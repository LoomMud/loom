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

use std::io::Read;
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

/// CTO review (OBI-184 respawn-on-crash slice): a standby child that
/// exits without the supervisor ever having asked it to (a crash, here
/// simulated by killing it directly rather than through the supervisor)
/// is respawned against the *same* already-bound listening sockets, not
/// left down. Proves this by killing the real standby child's real pid
/// (found via `/proc`, not the supervisor's pid -- `send_sigterm`ing the
/// supervisor itself is the already-covered graceful-shutdown path) and
/// then reconnecting: a stale connection breaks, but the telnet port
/// comes back up and serves a fresh connection again shortly after,
/// without the test ever restarting `loom supervise` itself.
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
    loom_supervise::signal::send_sigterm(child_pid).expect("kill the standby child directly");

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
    // (not have given up and exited).
    let mut reconnected = connect_with_retry(&telnet_bind, Duration::from_secs(15));
    reconnected
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    reconnected
        .read_exact(&mut preamble)
        .expect("read telnet negotiation preamble from the respawned child");

    supervisor.assert_alive();
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
