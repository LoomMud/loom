// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const INTRO_EXITS: &str = "Obvious exits: north.";
const HALL_DESC: &str = "A high-ceilinged hall of pale stone.";
const GARDEN_DESC: &str = "Neat beds of herbs line a gravel path.";
const UPDATED_GARDEN_DESC: &str =
    "Fresh rain darkens the gravel path, and rosemary scent hangs in the still air.";

#[test]
fn phase0_exit_demo_walks_and_hot_updates_without_disconnect() {
    let mudlib = fixture("warp-phase0");
    let port = reserve_local_port();
    let bind = format!("127.0.0.1:{port}");

    let mut server = LoomServer::spawn(&mudlib, &bind);
    let stream = connect_with_retry(&bind, Duration::from_secs(5));
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set read timeout");

    let mut reader = BufReader::new(stream);

    let intro = read_until_contains(&mut reader, INTRO_EXITS, Duration::from_secs(5));
    assert!(
        intro.contains("Welcome to Oberfield (Loom Phase 0)."),
        "{intro}"
    );
    assert!(intro.contains(HALL_DESC), "{intro}");
    let guest_name = extract_guest_name(&intro).expect("guest name in welcome line");
    assert_eq!(guest_name, "guest1");

    send_line(&mut reader, "look");
    let hall = read_until_contains(&mut reader, HALL_DESC, Duration::from_secs(2));
    assert!(hall.contains("The Entrance Hall"), "{hall}");

    send_line(&mut reader, "north");
    let garden = read_until_contains(&mut reader, GARDEN_DESC, Duration::from_secs(2));
    assert!(garden.contains("A Walled Garden"), "{garden}");

    rewrite_garden_description(&mudlib, UPDATED_GARDEN_DESC);
    send_line(&mut reader, "update /domains/start/garden");
    let update_ok = read_until_contains(&mut reader, "Updated.", Duration::from_secs(2));
    assert!(
        update_ok.contains("/domains/start/garden: Updated."),
        "{update_ok}"
    );

    send_line(&mut reader, "look");
    let refreshed = read_until_contains(&mut reader, UPDATED_GARDEN_DESC, Duration::from_secs(2));
    assert!(refreshed.contains("A Walled Garden"), "{refreshed}");
    assert!(!refreshed.contains(GARDEN_DESC), "{refreshed}");
    assert!(
        !refreshed.contains("Welcome to Oberfield") && !refreshed.contains("You are "),
        "unexpected reconnect output: {refreshed}"
    );

    let broken =
        "inherit /std/room\n\npub override fn describe() -> string {\n    return \"broken\" +\n}\n";
    std::fs::write(mudlib.join("domains/start/garden.wf"), broken).expect("write broken garden");

    send_line(&mut reader, "update /domains/start/garden");
    let update_err = read_until_contains(&mut reader, "error", Duration::from_secs(2));
    assert!(
        update_err.contains("/domains/start/garden: update failed."),
        "{update_err}"
    );

    send_line(&mut reader, "look");
    let after_failed_update =
        read_until_contains(&mut reader, UPDATED_GARDEN_DESC, Duration::from_secs(2));
    assert!(
        after_failed_update.contains("A Walled Garden"),
        "{after_failed_update}"
    );
    assert!(
        !after_failed_update.contains("Welcome to Oberfield")
            && !after_failed_update.contains("You are guest2"),
        "connection appears to have reset: {after_failed_update}"
    );

    send_line(&mut reader, "quit");
    let goodbye = read_until_contains(&mut reader, "Goodbye.", Duration::from_secs(2));
    assert!(goodbye.contains("Goodbye."), "{goodbye}");

    server.assert_alive();
}

fn rewrite_garden_description(mudlib: &Path, new_desc: &str) {
    let path = mudlib.join("domains/start/garden.wf");
    let src = std::fs::read_to_string(&path).expect("read garden source");
    let updated = src.replace(
        "Neat beds of herbs line a gravel path. Old brick walls keep the wind out. The archway back into the hall lies to the south.",
        new_desc,
    );
    assert_ne!(src, updated, "garden description replacement did not apply");
    std::fs::write(path, updated).expect("write garden source");
}

fn extract_guest_name(text: &str) -> Option<String> {
    let marker = "You are ";
    let start = text.find(marker)? + marker.len();
    let rest = &text[start..];
    let end = rest.find('.')?;
    Some(rest[..end].to_string())
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
            Ok(mut stream) => {
                drain_telnet_preamble(&mut stream);
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

/// `loom serve` opens with startup telnet option negotiation (OBI-26: `DO
/// NAWS`, `DO TTYPE`, `WILL GMCP`, `WILL MSSP` -- 12 bytes, none of them
/// valid UTF-8 on their own) before anything text-protocol shows up on the
/// wire. These tests read lines as UTF-8 text, so they don't speak telnet
/// back; just drop the fixed-size preamble rather than negotiate.
fn drain_telnet_preamble(stream: &mut TcpStream) {
    use std::io::Read;
    let mut preamble = [0_u8; 12];
    stream
        .read_exact(&mut preamble)
        .expect("read telnet negotiation preamble");
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
