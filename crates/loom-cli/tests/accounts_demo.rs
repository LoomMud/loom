// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-85 acceptance criterion: "in-memory backend. Create -> account_result
//! (ok), duplicate -> exists, wrong password -> bad_credentials. The world
//! thread is never blocked by hashing (show it: another connection's input
//! is processed while a login is pending)." Exercised end to end against a
//! real `loom-cli serve` subprocess with `DATABASE_URL` unset, so it runs
//! the in-memory dev account backend CI/the load bot use.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

#[test]
fn in_memory_account_backend_create_duplicate_and_bad_password() {
    let mudlib = fixture("accounts");
    let port = reserve_local_port();
    let bind = format!("127.0.0.1:{port}");
    let mut server = LoomServer::spawn(&mudlib, &bind);

    let stream_a = connect_with_retry(&bind, Duration::from_secs(5));
    stream_a
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut a = BufReader::new(stream_a);
    read_until_contains(&mut a, "Welcome.", Duration::from_secs(5));

    send_line(&mut a, "create legolas hunter2pass");
    let out = read_until_contains(&mut a, "req ", Duration::from_secs(2));
    assert!(out.contains("req 1\n"), "{out}");
    let out = poll_until_contains(&mut a, "result 1 ", Duration::from_secs(2));
    assert!(
        out.contains("result 1 true "),
        "expected a successful create: {out}"
    );

    send_line(&mut a, "create legolas hunter2pass");
    let out = poll_until_contains(&mut a, "result 2 ", Duration::from_secs(2));
    assert!(
        out.contains("result 2 false exists"),
        "duplicate account must be rejected as `exists`: {out}"
    );

    send_line(&mut a, "login legolas wrong-password");
    let out = poll_until_contains(&mut a, "result 3 ", Duration::from_secs(2));
    assert!(
        out.contains("result 3 false bad_credentials"),
        "wrong password must be `bad_credentials`: {out}"
    );

    send_line(&mut a, "login legolas hunter2pass");
    let out = poll_until_contains(&mut a, "result 4 ", Duration::from_secs(2));
    assert!(
        out.contains("result 4 true "),
        "correct login must succeed: {out}"
    );

    server.assert_alive();
}

/// The world thread never blocks on Argon2 hashing: pipeline a batch of
/// `account_create` requests on one connection (without waiting for their
/// results -- Argon2 hashing for each happens off the world thread), then
/// immediately check that a *second* connection's unrelated input is still
/// answered promptly. If hashing ran on the world thread instead, this
/// would serialize behind however many hashes were still in flight.
#[test]
fn a_pending_login_does_not_block_another_connections_input() {
    let mudlib = fixture("accounts");
    let port = reserve_local_port();
    let bind = format!("127.0.0.1:{port}");
    let mut server = LoomServer::spawn(&mudlib, &bind);

    let stream_a = connect_with_retry(&bind, Duration::from_secs(5));
    stream_a
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut a = BufReader::new(stream_a);
    read_until_contains(&mut a, "Welcome.", Duration::from_secs(5));

    let stream_b = connect_with_retry(&bind, Duration::from_secs(5));
    stream_b
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut b = BufReader::new(stream_b);
    read_until_contains(&mut b, "Welcome.", Duration::from_secs(5));

    // Pipeline several account_create requests on `a` without waiting for
    // any reply in between -- each one queues real Argon2 hashing work.
    for i in 0..10 {
        send_line(&mut a, &format!("create player{i} hunter2password"));
    }

    // `b`'s completely unrelated command must still be answered quickly:
    // the world thread only ever does a bounded-channel send to issue
    // account_create, never the hash itself.
    let started = Instant::now();
    send_line(&mut b, "look");
    read_until_contains(&mut b, "ok", Duration::from_secs(2));
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "connection b's input took {elapsed:?} while 10 account_creates were \
         pending on connection a -- the world thread looks blocked on hashing"
    );

    server.assert_alive();
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

/// [`read_until_contains`], but also sends a harmless `look` on `reader`
/// every ~100 ms while waiting. Stands in for `NetEvent::Tick` (OBI-82,
/// not yet landed at the time of this change): without a periodic tick,
/// nothing re-polls the account backend's result channel on an otherwise
/// idle connection, so this nudges the world thread with *some* event
/// often enough that the drain in `spawn_world_thread` runs promptly.
/// Once OBI-82 lands, an idle connection gets the same result within one
/// tick with no client-side nudging at all.
fn poll_until_contains(
    reader: &mut BufReader<TcpStream>,
    needle: &str,
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    let mut transcript = String::new();
    let mut last_nudge = Instant::now() - Duration::from_secs(1);

    loop {
        if transcript.contains(needle) {
            return transcript;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for `{needle}`. Transcript so far:\n{transcript}");
        }
        if last_nudge.elapsed() >= Duration::from_millis(100) {
            send_line(reader, "look");
            last_nudge = Instant::now();
        }

        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => panic!(
                "connection closed while waiting for `{needle}`. Transcript so far:\n{transcript}"
            ),
            Ok(_) => transcript.push_str(&line.replace("\r\n", "\n")),
            Err(err)
                if err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => panic!("socket read failed while waiting for `{needle}`: {err}"),
        }
    }
}

fn read_until_contains(
    reader: &mut BufReader<TcpStream>,
    needle: &str,
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    let mut transcript = String::new();

    loop {
        if Instant::now() > deadline {
            panic!("timed out waiting for `{needle}`. Transcript so far:\n{transcript}");
        }

        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => panic!(
                "connection closed while waiting for `{needle}`. Transcript so far:\n{transcript}"
            ),
            Ok(_) => {
                let normalized = line.replace("\r\n", "\n");
                transcript.push_str(&normalized);
                if transcript.contains(needle) {
                    return transcript;
                }
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => panic!("socket read failed while waiting for `{needle}`: {err}"),
        }
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

        let child = Command::new(loom_bin)
            .arg("serve")
            .arg("--mudlib")
            .arg(mudlib)
            .env("LOOM_TELNET_ADDR", bind)
            .env_remove("DATABASE_URL")
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
