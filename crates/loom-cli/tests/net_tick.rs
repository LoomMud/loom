// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `serve()` drives `World::tick()` from a real 100 ms `NetEvent::Tick`
//! timer (spec r5 N2, OBI-82): boot the `tworoom` fixture as a real
//! subprocess, schedule a `call_out(f, 3)`, and let the timer (not a test
//! harness clock) advance the world. `f` must run exactly once, after (not
//! before) the 3rd world tick.

use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

#[path = "support/read_until.rs"]
mod read_until;

use read_until::{Chunk, drain_telnet_preamble, read_one, read_until_contains};

/// `WORLD_TICK_INTERVAL` in `loom-cli/src/main.rs`; kept in sync by eye
/// (not `pub`, so not importable) since this is a black-box process test.
const WORLD_TICK_MS: u64 = 100;

#[test]
fn call_out_fires_exactly_once_after_three_world_ticks() {
    let mudlib = fixture("tworoom");
    let port = reserve_local_port();
    let bind = format!("127.0.0.1:{port}");

    let mut server = LoomServer::spawn(&mudlib, &bind);
    let stream = connect_with_retry(&bind, Duration::from_secs(5));
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set read timeout");
    let mut reader = BufReader::new(stream);

    // logon() greets and looks around; drain it before scheduling.
    let _ = read_until_contains(&mut reader, "Exits:", Duration::from_secs(5));

    send_line(&mut reader, "sched3"); // call_out("pong", 3)
    let scheduled_at = Instant::now();
    let scheduled = read_until_contains(&mut reader, "scheduled ", Duration::from_secs(2));
    assert!(scheduled.contains("scheduled 0"), "{scheduled}");

    // A 3-world-tick delay is at least ~2 ticks away no matter where in the
    // current tick period it was scheduled (it could have been scheduled
    // an instant before a tick boundary, in which case it is due after only
    // a little over 2 further ticks): well under that, nothing should have
    // arrived yet.
    assert_no_output_within(&mut reader, Duration::from_millis(WORLD_TICK_MS));

    // Comfortably past the 3rd world tick (300 ms from *scheduling*, not
    // from server boot -- the tick counter keeps running from boot, so
    // `call_out`'s delay is relative to whatever tick it happened to be
    // scheduled on) but with generous CI slack.
    let after = read_until_contains(&mut reader, "pong 0", Duration::from_secs(3));
    assert!(after.contains("pong 0\n"), "{after}");
    let fired_after = scheduled_at.elapsed();
    assert!(
        fired_after >= Duration::from_millis(WORLD_TICK_MS),
        "pong fired suspiciously fast ({fired_after:?}) for a 3-world-tick call_out"
    );

    // No second `pong`: give the world several more ticks' worth of real
    // time and confirm nothing else arrives.
    assert_no_output_within(&mut reader, Duration::from_millis(5 * WORLD_TICK_MS));

    server.assert_alive();
}

#[test]
fn a_world_thread_that_falls_behind_never_has_more_than_one_pending_tick() {
    // There is no test-only hook into `serve()`'s internal `tick_pending`
    // flag (a black-box process test can't reach into another process's
    // `Arc<AtomicBool>`), so this pins the *externally observable*
    // consequence of coalescing instead: a `heart_beat()` that counts every
    // `World::tick()` call must, over several seconds of real (wall-clock)
    // time on a live server, land within one tick of
    // `elapsed / WORLD_TICK_INTERVAL` -- not run away to some much larger
    // number the way an unbounded queue of missed `Tick`s replayed back to
    // back would produce once the process got a chance to catch up (e.g.
    // after being descheduled by the OS scheduler under load).
    let mudlib = fixture("tworoom");
    let port = reserve_local_port();
    let bind = format!("127.0.0.1:{port}");

    let mut server = LoomServer::spawn(&mudlib, &bind);
    let stream = connect_with_retry(&bind, Duration::from_secs(5));
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set read timeout");
    let mut reader = BufReader::new(stream);
    let _ = read_until_contains(&mut reader, "Exits:", Duration::from_secs(5));

    send_line(&mut reader, "hbon");
    let _ = read_until_contains(&mut reader, "heartbeat on", Duration::from_secs(2));

    let start = Instant::now();
    std::thread::sleep(Duration::from_secs(3));

    send_line(&mut reader, "beats");
    let out = read_until_contains(&mut reader, "\n", Duration::from_secs(2));
    let beats: u64 = out.trim().parse().expect("numeric beats count");
    let elapsed_ticks = start.elapsed().as_millis() as u64 / WORLD_TICK_MS;

    // Default heartbeat cadence is every 20 world ticks; a bounded (never
    // more than one pending `Tick`) driver falls at most a handful of
    // ticks behind wall-clock even under CI scheduling jitter, so this
    // generous factor-of-2 slack still rejects "ticks queued up and never
    // coalesced" (which would run heartbeats far more often once the
    // world thread got CPU time back) while tolerating a slow CI host.
    let max_plausible_beats = elapsed_ticks / 20 + 2;
    assert!(
        beats <= max_plausible_beats,
        "heartbeat ran {beats} times in ~{elapsed_ticks} world ticks; \
         expected at most {max_plausible_beats} if ticks are bounded/coalesced, not queued"
    );

    server.assert_alive();
}

/// Reads for `window` and panics if anything at all arrives (used to pin
/// "not yet due").
///
/// Byte-based (OBI-355): what arrives is reported as the bytes/text it is, and each
/// give-up path says which failure it was, so a timing assertion can't be mistaken for
/// a transport problem or the other way round.
fn assert_no_output_within(reader: &mut BufReader<TcpStream>, window: Duration) {
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        match read_one(reader) {
            Chunk::Data(chunk) => panic!(
                "unexpected output before it was due: {chunk:?} ({} character(s) of transcript \
                 read from the child's socket inside the {window:?} window)",
                chunk.len()
            ),
            Chunk::Closed => panic!("connection closed unexpectedly while expecting silence"),
            Chunk::Idle => {}
            Chunk::Failed(err) => panic!("socket read failed while expecting silence: {err}"),
        }
    }
}

fn send_line(reader: &mut BufReader<TcpStream>, line: &str) {
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

fn connect_with_retry(addr: &str, timeout: Duration) -> TcpStream {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect(addr) {
            Ok(mut stream) => {
                drain_telnet_preamble(&mut stream, "on connecting to the server");
                return stream;
            }
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
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("read local addr").port()
}

struct LoomServer {
    child: Child,
}

impl LoomServer {
    fn spawn(mudlib: &Path, bind: &str) -> Self {
        let loom_bin = std::env::var("CARGO_BIN_EXE_loom-cli")
            .or_else(|_| std::env::var("CARGO_BIN_EXE_loom_cli"))
            .expect("cargo binary path for loom-cli");
        let http_port = reserve_local_port();

        let child = Command::new(loom_bin)
            .arg("serve")
            .arg("--mudlib")
            .arg(mudlib)
            .env("LOOM_TELNET_ADDR", bind)
            .env("LOOM_HTTP_ADDR", format!("127.0.0.1:{http_port}"))
            .env("RUST_LOG", "")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn loom serve");

        Self { child }
    }

    fn assert_alive(&mut self) {
        if let Some(status) = self.child.try_wait().expect("poll server process") {
            panic!("loom server exited early with status {status}");
        }
    }
}

impl Drop for LoomServer {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

static N: AtomicU32 = AtomicU32::new(0);

fn scratch(tag: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::SeqCst);
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir scratch");
    dir
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("mkdir destination");
    for entry in std::fs::read_dir(from).expect("read fixture directory") {
        let path = entry.expect("fixture entry").path();
        let dest = to.join(path.file_name().expect("fixture filename"));
        if path.is_dir() {
            copy_dir(&path, &dest);
        } else {
            std::fs::copy(&path, &dest).expect("copy fixture file");
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
