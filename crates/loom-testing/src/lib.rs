// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared harness for loom's black-box process tests: port allocation, a
//! `loom serve` / `loom supervise` wrapper that does not report "started"
//! until the server is really serving, that server's captured output, and the
//! telnet transcript helpers those tests read through.
//!
//! OBI-305 lifts the harness `supervise_handoff.rs` grew in OBI-292 (PR #124)
//! into one place so the sibling integration tests stop carrying private
//! copies of the *old*, racy version of it.
//!
//! Why the old copy was racy: probing for a free port with an ephemeral bind
//! and then dropping the probe socket hands back a port from the *ephemeral*
//! range (`/proc/sys/net/ipv4/ip_local_port_range`, 32768-60999 on the CI
//! runners) which is released the instant the handle is dropped. Between that
//! release and the spawned server binding it, anything else on the box
//! allocating an ephemeral port can win it -- including another thread in this
//! same test binary making one of the many outbound
//! [`std::net::TcpStream::connect`] calls these tests do. The server then
//! exits on `failed to bind ...: Address already in use`, and the test sees
//! either `failed to connect ... before timeout` or, if it had already
//! connected into the doomed listener's backlog, a reset: CI's
//! `Connection reset by peer (os error 104)` in OBI-292.
//!
//! So [`reserve_local_port`] allocates from a fixed band *below* the ephemeral
//! range, which the kernel's auto-allocation never touches, and
//! [`Spawn::start`] is a readiness barrier -- it returns only once the server
//! has written the telnet negotiation preamble on a connection it holds --
//! with each attempt's own stdout+stderr kept for the post-mortem
//! ([`Server::log`]).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ------------------------------------------------------------------- ports --

/// Start of the port band these tests allocate listener ports from.
///
/// OBI-292: allocation used to be an ephemeral probe bind whose port was
/// released as soon as the probe handle was dropped -- see the module docs.
const TEST_PORT_BAND_START: u16 = 20_000;
/// Width of [`TEST_PORT_BAND_START`]'s band -- comfortably more than the
/// handful of ports one run needs (two per server, per startup attempt).
const TEST_PORT_BAND_WIDTH: u16 = 4_000;

/// Allocates the next free port in [`TEST_PORT_BAND_START`]'s band.
///
/// The cursor is process-global and atomic, so concurrent tests in this
/// binary can never be handed the same port twice; the band is entered at a
/// pid-dependent offset so separate invocations of this binary (a CI re-run,
/// another test binary's servers) don't all reach for the same port first.
pub fn reserve_local_port() -> u16 {
    static CURSOR: AtomicU16 = AtomicU16::new(0);
    let salt = std::process::id() as u16 % TEST_PORT_BAND_WIDTH;
    for _step in 0..TEST_PORT_BAND_WIDTH {
        let index = (salt + CURSOR.fetch_add(1, Ordering::Relaxed)) % TEST_PORT_BAND_WIDTH;
        let port = TEST_PORT_BAND_START + index;
        // Probe bind, held for the length of this `if` only. Nothing the
        // kernel auto-allocates can now take this port, and no other test in
        // this process will ask for it again (the cursor already moved past
        // it). The window that remains -- an unrelated process on the host
        // binding this exact port -- is not one a test can close, so startup
        // is additionally retried (`MAX_STARTUP_ATTEMPTS`).
        if TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).is_ok() {
            return port;
        }
    }
    panic!(
        "no free port in the test band {TEST_PORT_BAND_START}..{}",
        TEST_PORT_BAND_START + TEST_PORT_BAND_WIDTH
    );
}

/// The address string a reserved port is served and connected to at.
pub fn bind_string(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

// -------------------------------------------------------------- transcript --

/// How many bytes `loom serve` writes before a client has said anything: the
/// telnet option-negotiation preamble (OBI-26: `DO NAWS`, `DO TTYPE`, `WILL
/// GMCP`, `WILL MSSP`). Receiving it is the cheapest proof that the server
/// booted and is really serving *this* connection -- if startup were broken it
/// never arrives. It is also the only binary data on an otherwise text-only
/// stream, so it is drained before anything reads lines.
pub const TELNET_PREAMBLE_LEN: usize = 12;

/// How long [`Session::connect`] may keep retrying before it gives up. The
/// server is already past [`Spawn::start`]'s readiness barrier by then, so
/// this is slack for the socket, not for boot.
const CONNECT_BUDGET: Duration = Duration::from_secs(5);

/// How long a session's reads may block before a test's own timeout logic
/// takes over. The value each suite set by hand on every socket before this
/// lived here.
const SESSION_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// How many times [`Spawn::start`] will tear down a server that died or went
/// quiet before it ever served, and start a fresh one on fresh ports.
const MAX_STARTUP_ATTEMPTS: usize = 3;

/// How long one startup attempt may take before it is written off. This bounds
/// the *whole* attempt -- bind, spawn, compile the mudlib in debug, first bytes
/// on the wire -- so it is a liveness check on the server rather than a fixed
/// sleep; several tests' servers share one runner in CI.
const READY_BUDGET: Duration = Duration::from_secs(30);

/// How many lines of a server's own output to keep for the post-mortem.
const LOG_KEEP_LINES: usize = 400;

/// A telnet client connection, with the startup preamble already drained.
pub struct Session {
    stream: TcpStream,
    preamble: Vec<u8>,
}

impl Session {
    /// Connects to `addr` (retrying until [`CONNECT_BUDGET`] elapses) and
    /// drops the fixed-size startup preamble, so everything after this point
    /// is the mudlib's own text.
    pub fn connect(addr: &str) -> Self {
        let mut session = Self::connect_raw(addr);
        session.drain_preamble();
        session
    }

    /// Connects without draining the preamble, for tests that assert on the
    /// negotiation bytes themselves.
    pub fn connect_raw(addr: &str) -> Self {
        let deadline = Instant::now() + CONNECT_BUDGET;
        loop {
            match TcpStream::connect(addr) {
                Ok(stream) => {
                    let _ = stream.set_read_timeout(Some(SESSION_READ_TIMEOUT));
                    return Self {
                        stream,
                        preamble: Vec::new(),
                    };
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

    /// Wraps this connection in a line reader with `timeout` as the socket read
    /// timeout -- the per-test value these suites have always set by hand (200 ms
    /// where a test asserts "nothing more should have arrived", 2 s otherwise).
    pub fn into_reader(self, timeout: Duration) -> BufReader<TcpStream> {
        let stream = self.stream;
        stream
            .set_read_timeout(Some(timeout))
            .expect("set session read timeout");
        BufReader::new(stream)
    }

    /// The startup preamble this session drained, for a test that wants to
    /// assert on the negotiation bytes rather than throw them away.
    pub fn preamble(&self) -> &[u8] {
        &self.preamble
    }

    pub fn set_read_timeout(&mut self, timeout: Duration) {
        self.stream
            .set_read_timeout(Some(timeout))
            .expect("set session read timeout");
    }

    /// Reads exactly `n` bytes (short reads retried until `timeout` elapses),
    /// so byte-exact protocol assertions can compare a literal sequence
    /// instead of scanning for a substring.
    pub fn read_bytes(&mut self, n: usize, timeout: Duration) -> Vec<u8> {
        let mut buf = vec![0_u8; n];
        self.fill(&mut buf, timeout);
        buf
    }

    /// Writes `bytes` and flushes -- raw wire output, for tests that speak
    /// telnet rather than lines.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.stream
            .write_all(bytes)
            .unwrap_or_else(|err| panic!("write failed: {err}"));
        self.stream.flush().expect("flush write");
    }

    fn drain_preamble(&mut self) {
        let bytes = self.read_bytes(TELNET_PREAMBLE_LEN, CONNECT_BUDGET);
        self.preamble = bytes;
    }

    /// Reads until `want` is full, or panics with what arrived so far. Each
    /// individual read is short (the session's own read timeout) so a server
    /// that dies mid-handshake -- closing the listener, which resets this
    /// connection -- is reported in milliseconds rather than at the deadline.
    fn fill(&mut self, want: &mut [u8], timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let mut filled = 0;
        while filled < want.len() {
            match self.stream.read(&mut want[filled..]) {
                Ok(0) => panic!(
                    "connection closed after {filled}/{} bytes: {:?}",
                    want.len(),
                    &want[..filled]
                ),
                Ok(n) => filled += n,
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    if Instant::now() > deadline {
                        panic!(
                            "timed out after {filled}/{} bytes: {:?}",
                            want.len(),
                            &want[..filled]
                        );
                    }
                }
                Err(err) => panic!("socket read failed after {filled} bytes: {err}"),
            }
        }
    }
}

/// Writes one command line (`line` + `\n`) and flushes.
pub fn send_line(reader: &mut BufReader<TcpStream>, line: &str) {
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

/// Reads lines until the accumulated transcript contains `needle`, and returns
/// the transcript. Panics -- with the transcript so far -- if `timeout` elapses
/// first.
///
/// OBI-292: reads bytes, not `String`s. A telnet stream is *not* text -- an IAC
/// sequence landing inside one `\n`-terminated chunk used to make `read_line`
/// fail with `stream did not contain valid UTF-8 (os error 526)` and take a
/// test down for a non-ASCII byte it was never meant to assert on. Lossy
/// decoding keeps the transcript usable for substring matching, which is all
/// any caller here does with it.
pub fn read_until_contains(
    reader: &mut BufReader<TcpStream>,
    needle: &str,
    timeout: Duration,
) -> String {
    read_for(reader, needle, timeout, None)
}

/// [`read_until_contains`] for an async result that only gets drained when the
/// world thread has something else to do: without a periodic tick
/// (`NetEvent::Tick`, OBI-82) an idle connection never re-polls the account
/// backend's result channel, so these tests nudge it. `nudge` is the command
/// re-sent every ~100 ms while waiting; `None` just reads.
pub fn poll_until_contains(
    reader: &mut BufReader<TcpStream>,
    needle: &str,
    timeout: Duration,
    nudge: Option<&str>,
) -> String {
    read_for(reader, needle, timeout, nudge.map(|n| (Duration::from_millis(100), n)))
}

/// The outcome of one [`read_one_reply`] attempt.
#[derive(Debug)]
pub enum Reply {
    Line(String),
    /// Nothing arrived within the timeout; try again.
    Timeout,
    /// The peer closed the connection (`read` returned `Ok(0)`). Occasionally
    /// observed in CI against a real Postgres-backed server under load, root
    /// cause not fully pinned down; callers that can reconnect and retry should
    /// treat this the same as a timeout rather than failing outright.
    Closed,
}

/// Reads exactly one line (one command's reply), waiting up to `timeout`.
pub fn read_one_reply(reader: &mut BufReader<TcpStream>, timeout: Duration) -> Reply {
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    loop {
        match reader.read_until(b'\n', &mut bytes) {
            Ok(0) => return Reply::Closed,
            Ok(_) => return Reply::Line(String::from_utf8_lossy(&bytes).replace("\r\n", "\n")),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                if Instant::now() > deadline {
                    return Reply::Timeout;
                }
            }
            Err(err) => panic!("socket read failed while waiting for a reply: {err}"),
        }
    }
}

/// Reads for `window` and panics if anything at all arrives (used to pin "not
/// yet due").
pub fn assert_no_output_within(reader: &mut BufReader<TcpStream>, window: Duration) {
    let deadline = Instant::now() + window;
    let mut bytes = Vec::new();
    while Instant::now() < deadline {
        bytes.clear();
        match reader.read_until(b'\n', &mut bytes) {
            Ok(0) => panic!("connection closed unexpectedly"),
            Ok(_) => panic!(
                "unexpected output before it was due: {:?}",
                String::from_utf8_lossy(&bytes)
            ),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(err) => panic!("socket read failed: {err}"),
        }
    }
}

/// The shared line-reading loop: accumulate `\n`-terminated lines (lossy,
/// `\r\n` normalised) until the transcript contains `needle` or `timeout`
/// elapses, optionally re-sending `nudge` every ~100 ms while waiting.
fn read_for(
    reader: &mut BufReader<TcpStream>,
    needle: &str,
    timeout: Duration,
    nudge: Option<(Duration, &str)>,
) -> String {
    let deadline = Instant::now() + timeout;
    let mut transcript = String::new();
    let mut last_nudge = Instant::now() - Duration::from_millis(100);

    loop {
        if transcript.contains(needle) {
            return transcript;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for `{needle}`. Transcript so far:\n{transcript}");
        }
        if let Some((every, command)) = nudge
            && last_nudge.elapsed() >= every
        {
            send_line(reader, command);
            last_nudge = Instant::now();
        }

        let mut bytes = Vec::new();
        match reader.read_until(b'\n', &mut bytes) {
            Ok(0) => panic!(
                "connection closed while waiting for `{needle}`. Transcript so far:\n{transcript}"
            ),
            Ok(_) => {
                let line = String::from_utf8_lossy(&bytes).replace("\r\n", "\n");
                transcript.push_str(&line);
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

/// Strips `ESC [ ... m` ANSI SGR (colour) escape sequences --
/// `tracing_subscriber`'s `fmt` layer applies them unconditionally, not just
/// when the writer is a real terminal, so any test that wants to pattern-match
/// a log line's *fields* (as opposed to substrings that happen to survive being
/// interrupted by escape codes, like a field's own value) needs this first.
pub fn strip_ansi(line: &str) -> String {
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

// ------------------------------------------------------------------ server --

/// Which driver subcommand [`Spawn::start`] runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `loom serve` -- one process that owns its listening sockets.
    Serve,
    /// `loom supervise` -- the supervisor plus the standby child it hands those
    /// sockets to across a copyover (OBI-184).
    Supervise,
}

/// The version string the version-watch tests start their desired-version file
/// at (and which [`Spawn::version_watch`] tells the supervisor is its own
/// running version, so only the *change* each test writes is a change).
pub const DESIRED_VERSION_INITIAL: &str = "v1.0.0";

/// A `loom` subprocess to be started: mode, mudlib, binds and environment.
///
/// Build it with [`Spawn::serve`] / [`Spawn::supervise`], adjust with the
/// `with_*` setters, then [`Spawn::start`] -- which is a readiness barrier, not
/// a `spawn` in the fire-and-forget sense.
pub struct Spawn {
    mode: Mode,
    mudlib: PathBuf,
    telnet: Option<String>,
    http: Option<String>,
    env: Vec<(String, Option<String>)>,
    log_spec: String,
}

impl Spawn {
    /// A plain `loom serve` on `mudlib`: quiet (`RUST_LOG` empty) and with
    /// `DATABASE_URL`/`LOOM_SMOKE_DATABASE_URL` removed from the child's
    /// environment, so it runs the in-memory account backend and can never
    /// point at the ambient control-plane Postgres (OBI-151 -- agent shells
    /// export `DATABASE_URL` for Paperclip's own database). Both listener
    /// addresses are reserved from [`reserve_local_port`] at [`Spawn::start`].
    pub fn serve(mudlib: &Path) -> Self {
        Self::new(Mode::Serve, mudlib)
    }

    /// A `loom supervise` on `mudlib`: the supervisor plus the standby child it
    /// hands its listening sockets to.
    pub fn supervise(mudlib: &Path) -> Self {
        Self::new(Mode::Supervise, mudlib)
    }

    fn new(mode: Mode, mudlib: &Path) -> Self {
        Self {
            mode,
            mudlib: mudlib.to_path_buf(),
            telnet: None,
            http: None,
            // Every process test stays hermetic about the ambient DB (OBI-151).
            env: vec![
                ("DATABASE_URL".to_string(), None),
                ("LOOM_SMOKE_DATABASE_URL".to_string(), None),
            ],
            log_spec: String::new(),
        }
    }

    /// Sets the driver's `RUST_LOG` (default: empty, i.e. quiet). The driver's
    /// own `tracing` output goes to stdout, so it lands in [`Server::log`]
    /// either way; it is only worth turning up when a test asserts on log lines.
    pub fn with_log(mut self, spec: &str) -> Self {
        self.log_spec = spec.to_string();
        self
    }

    /// Adds (or replaces) an environment variable for the child -- e.g. a
    /// DB-backed test's `DATABASE_URL`, which [`Spawn::serve`] removes by
    /// default.
    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env.retain(|(k, _)| k != key);
        self.env.push((key.to_string(), Some(value.to_string())));
        self
    }

    /// Pins the telnet bind instead of reserving a free port. For tests that
    /// need an address they chose themselves; startup retries then reuse it.
    pub fn with_telnet_bind(mut self, bind: &str) -> Self {
        self.telnet = Some(bind.to_string());
        self
    }

    /// Pins the HTTP bind instead of reserving a free port.
    pub fn with_http_bind(mut self, bind: &str) -> Self {
        self.http = Some(bind.to_string());
        self
    }

    /// `supervise` only: points the supervisor at the desired-version file it
    /// watches, declares this supervisor's own running version as
    /// [`DESIRED_VERSION_INITIAL`], shortens the poll interval, and turns
    /// logging up to `info` -- the version-watch tests have nothing else
    /// observable to assert on (OBI-184's version watching was detection-only
    /// for a long time, so a log line was the only visible effect).
    ///
    /// Declaring the running version is what makes the barrier honest: without
    /// it the baseline is the crate version (0.0.1, from
    /// `running_version_from_env`), so the file's *initial* content already
    /// differs from it and the very first poll -- `tokio::time::interval`'s tick
    /// 0 fires immediately, so as soon as the child is up -- reports a change
    /// nobody made and triggers a reclaim/readopt round trip on a connection
    /// the test is still introducing. That is `supervise`'s documented
    /// behaviour (CTO review, OBI-256: seed from the running build's own
    /// identity, deliberately); it simply is not what those tests exercise --
    /// they want exactly one change, the one they write.
    pub fn version_watch(self, version_file: &Path) -> Self {
        assert_eq!(
            self.mode,
            Mode::Supervise,
            "version_watch is a `supervise`-only knob"
        );
        self.with_env(
            "LOOM_DESIRED_VERSION_FILE",
            &version_file.display().to_string(),
        )
        .with_env("LOOM_RUNNING_VERSION", DESIRED_VERSION_INITIAL)
        // CTO review (OBI-256 nit): overridable rather than a fixed 5s
        // production default, so the version tests have real slack against
        // their own timeouts instead of racing CI's timing margin at the
        // production cadence.
        .with_env("LOOM_VERSION_POLL_INTERVAL_MS", "200")
        .with_log("loom_cli=info")
    }

    /// Spawns the server and returns it once it is *serving*: a connection to
    /// the telnet listener has received the whole startup preamble.
    ///
    /// A server that dies or goes quiet before ever serving is a startup
    /// problem, not a result -- it is torn down and a fresh one started on fresh
    /// ports, up to [`MAX_STARTUP_ATTEMPTS`] times, with every failed attempt's
    /// own output carried into the panic message, so the reason (`failed to
    /// bind ...`, `waiting for the ready signal: ...`) is in the CI log instead
    /// of thrown away.
    pub fn start(self) -> Server {
        let (server, _lines) = self.start_inner(false);
        server
    }

    /// [`Spawn::start`] plus the live stream of the server's stdout lines,
    /// which is what the version-watch tests assert on as they arrive.
    pub fn start_with_log_lines(self) -> (Server, std::sync::mpsc::Receiver<String>) {
        self.start_inner(true)
    }

    fn start_inner(self, want_lines: bool) -> (Server, std::sync::mpsc::Receiver<String>) {
        let mut attempts = Vec::new();
        for attempt in 1..=MAX_STARTUP_ATTEMPTS {
            let telnet_bind = self.telnet_bind();
            let http_bind = self.http_bind();
            let (child, log, line_rx) = self.spawn_child(&telnet_bind, &http_bind, want_lines);
            let mut server = Server {
                child,
                log,
                telnet_bind,
                http_bind,
                mode: self.mode,
                barrier: None,
                preamble: Vec::new(),
            };
            match server.wait_until_serving() {
                Ok((stream, preamble)) => {
                    server.barrier = Some(stream);
                    server.preamble = preamble;
                    return (server, line_rx);
                }
                Err(reason) => {
                    let log = server.log();
                    let bind = server.telnet_bind.clone();
                    // `Drop` kills whatever is still running and releases both
                    // ports before the next attempt binds new ones.
                    drop(server);
                    attempts.push(format!(
                        "attempt {attempt}/{MAX_STARTUP_ATTEMPTS} on {bind}: {reason}\n\
                         --- server output ---\n{log}"
                    ));
                }
            }
        }
        panic!(
            "`loom {}` never served through {MAX_STARTUP_ATTEMPTS} startup attempts:\n{}",
            self.mode_name(),
            attempts.join("\n===\n")
        );
    }

    fn telnet_bind(&self) -> String {
        self.telnet
            .clone()
            .unwrap_or_else(|| bind_string(reserve_local_port()))
    }

    fn http_bind(&self) -> String {
        self.http
            .clone()
            .unwrap_or_else(|| bind_string(reserve_local_port()))
    }

    /// Builds the `Command` for one attempt and pipes both of its output
    /// streams into the shared bounded log -- nothing discards the server's
    /// output any more -- plus, for the spawns that ask, a channel of the same
    /// stdout lines.
    fn spawn_child(
        &self,
        telnet_bind: &str,
        http_bind: &str,
        want_lines: bool,
    ) -> (Child, Arc<Mutex<Vec<String>>>, std::sync::mpsc::Receiver<String>) {
        let loom_bin = std::env::var("CARGO_BIN_EXE_loom-cli")
            .or_else(|_| std::env::var("CARGO_BIN_EXE_loom_cli"))
            .expect("cargo binary path for loom-cli");

        let mut cmd = Command::new(loom_bin);
        cmd.arg(self.mode_name())
            .arg("--mudlib")
            .arg(&self.mudlib)
            .env("LOOM_TELNET_ADDR", telnet_bind)
            .env("LOOM_HTTP_ADDR", http_bind)
            .env("RUST_LOG", &self.log_spec);
        for (key, value) in &self.env {
            match value {
                Some(value) => {
                    cmd.env(key, value);
                }
                None => {
                    cmd.env_remove(key);
                }
            }
        }

        let (line_tx, line_rx) = std::sync::mpsc::channel::<String>();
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|err| panic!("spawn `loom {}`: {err}", self.mode_name()));

        let log = Arc::new(Mutex::new(Vec::new()));
        drain_pipe(
            child.stdout.take().expect("piped stdout"),
            Arc::clone(&log),
            want_lines.then_some(line_tx),
        );
        // stderr is never forwarded as lines: the driver's `tracing` fmt layer
        // writes to stdout, so anything here is a panic message or a library
        // log, which belongs in the post-mortem but not in a test's assertions.
        drain_pipe(child.stderr.take().expect("piped stderr"), Arc::clone(&log), None);

        (child, log, line_rx)
    }

    fn mode_name(&self) -> &'static str {
        match self.mode {
            Mode::Serve => "serve",
            Mode::Supervise => "supervise",
        }
    }
}

/// A running `loom` subprocess whose output is captured, and which was only
/// handed back once it had proved it was serving.
pub struct Server {
    child: Child,
    /// The server's stdout+stderr, kept so a failure can say *why*. Before
    /// OBI-292/OBI-305 most of these tests used `Stdio::null()`, which is why
    /// CI failures were undiagnosable from their logs: the one line that named
    /// the cause (`failed to bind ...: Address already in use`) was thrown
    /// away.
    log: Arc<Mutex<Vec<String>>>,
    telnet_bind: String,
    http_bind: String,
    mode: Mode,
    /// The connection [`Spawn::start`] proved readiness on.
    barrier: Option<TcpStream>,
    /// The bytes that connection's startup negotiation carried -- `loom-net`
    /// sends every new connection its own preamble, so a second connection
    /// gets its own (design §8.2, OBI-26).
    preamble: Vec<u8>,
}

impl Server {
    /// The address the telnet listener is bound to.
    pub fn telnet_bind(&self) -> &str {
        &self.telnet_bind
    }

    /// The address the HTTP/WS listener is bound to.
    pub fn http_bind(&self) -> &str {
        &self.http_bind
    }

    /// The startup preamble the readiness barrier was proved on.
    pub fn startup_preamble(&self) -> &[u8] {
        &self.preamble
    }

    /// A telnet session against this server.
    ///
    /// In [`Mode::Serve`] the first call hands over the very connection
    /// readiness was proved on -- which is what that connection exists for, and
    /// means the test sees exactly one preamble, the one already drained.
    ///
    /// In [`Mode::Supervise`] that connection is *kept open for the child's
    /// whole life* instead: the standby child claims one accepted connection
    /// slot for itself as its ready signal, so closing it makes the supervisor
    /// respawn the child mid-test (the OBI-225 crash/respawn path, which is not
    /// what the handoff tests are about). Every session there -- and every
    /// session after the first in `serve` mode -- is a fresh connection, with
    /// its own preamble drained.
    pub fn session(&mut self) -> Session {
        match (self.mode, self.barrier.take()) {
            (Mode::Serve, Some(stream)) => Session {
                stream,
                preamble: self.preamble.clone(),
            },
            _ => Session::connect(&self.telnet_bind),
        }
    }

    /// Fails the test if the server process has already exited -- the standing
    /// invariant every test here re-checks at the end, since giving up on a
    /// child that keeps crashing is a driver bug, not a passing test.
    pub fn assert_alive(&mut self) {
        if let Some(status) = self.child.try_wait().expect("poll server process") {
            panic!(
                "loom {} exited early with status {status}\n--- server output ---\n{}",
                self.mode_name(),
                self.log()
            );
        }
    }

    /// The server's exit status if it has already exited -- unlike
    /// [`Server::assert_alive`], safe to ask while an attempt is still in
    /// flight, which is what makes a dead-on-arrival server reportable in
    /// milliseconds instead of at the readiness deadline.
    pub fn exited(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    /// Waits (polling) for the process to exit on its own, returning its status,
    /// or `None` if `timeout` passed first.
    pub fn wait_to_exit(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().ok().flatten() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The process id, for tests that look for the supervisor's child in
    /// `/proc`.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Sends SIGTERM. `loom supervise` forwards it to its standby child
    /// (OBI-184/OBI-225) and exits once the child does.
    ///
    /// Shells out to `kill` rather than taking a `libc` dependency: this crate
    /// is test support and stays dependency-free.
    pub fn send_sigterm(&mut self) {
        let pid = self.pid().to_string();
        let status = Command::new("kill")
            .arg("-TERM")
            .arg(&pid)
            .status()
            .unwrap_or_else(|err| panic!("signal SIGTERM to {pid}: {err}"));
        assert!(status.success(), "`kill -TERM {pid}` failed: {status}");
    }

    /// The last [`LOG_KEEP_LINES`] lines of the server's own output, with ANSI
    /// colour codes stripped so a post-mortem is readable rather than a wall of
    /// escape codes.
    pub fn log(&self) -> String {
        let lines = self
            .log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lines
            .iter()
            .map(|line| strip_ansi(line))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn mode_name(&self) -> &'static str {
        match self.mode {
            Mode::Serve => "serve",
            Mode::Supervise => "supervise",
        }
    }

    /// Connects to the telnet listener and holds that one connection open until
    /// the server has written the whole startup preamble, reporting the reason
    /// it gave up rather than panicking, so [`Spawn::start_inner`] can decide
    /// whether to retry on fresh ports.
    fn wait_until_serving(&mut self) -> Result<(TcpStream, Vec<u8>), String> {
        let deadline = Instant::now() + READY_BUDGET;
        // Exactly one connection for the whole attempt. Connecting *again* would
        // queue a second entry on the listener's backlog, and the server accepts
        // the oldest entry first -- so a reconnect loop can hand the preamble to
        // a socket the caller already dropped and then time out on the one it
        // kept.
        let mut stream = loop {
            match TcpStream::connect(&self.telnet_bind) {
                Ok(stream) => break stream,
                Err(err) => {
                    if let Some(status) = self.exited() {
                        return Err(format!(
                            "server exited (status {status}) without ever listening on \
                             {}: {err}",
                            self.telnet_bind
                        ));
                    }
                    if Instant::now() >= deadline {
                        return Err(format!("never listened on {}: {err}", self.telnet_bind));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        };
        let mut preamble = [0_u8; TELNET_PREAMBLE_LEN];
        self.fill_before_deadline(&mut stream, &mut preamble, &deadline)?;
        // `fill_before_deadline` polls with a short read timeout; hand the
        // barrier connection back the 2 s a test used to get from its own
        // preamble read, so nothing downstream changes shape.
        stream
            .set_read_timeout(Some(SESSION_READ_TIMEOUT))
            .map_err(|err| err.to_string())?;
        Ok((stream, preamble.to_vec()))
    }

    /// Reads until `buf` is full, or reports why it stopped. Each individual read
    /// is short (`POLL_READ_TIMEOUT`) so a server that dies partway through the
    /// handshake -- closing the listener, which resets this connection -- is
    /// reported in milliseconds rather than at the deadline; the process is
    /// polled for exactly that between reads.
    fn fill_before_deadline(
        &mut self,
        stream: &mut TcpStream,
        buf: &mut [u8],
        deadline: &Instant,
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
                    // A server that dies mid-handshake closes the listener it
                    // dup'd to the child, which *resets* this connection -- poll
                    // for that here rather than waiting out the deadline, so a
                    // retry can start immediately.
                    if let Some(status) = self.exited() {
                        return Err(format!(
                            "server exited (status {status}) after the barrier connected but \
                             before serving -- closing the listener is what resets this connection"
                        ));
                    }
                    if Instant::now() >= *deadline {
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
}

impl Drop for Server {
    fn drop(&mut self) {
        // OBI-292: a panicking test used to leave behind nothing but the panic's
        // own message. Print what the server said instead -- captured output
        // only surfaces (to `cargo test`'s failure report) when the test
        // actually fails, so this is free on the green path.
        let status = self.child.try_wait().ok().flatten();
        if std::thread::panicking() {
            eprintln!(
                "`loom {}` (pid {}) status at drop: {status:?}\n--- server output ---\n{}",
                self.mode_name(),
                self.pid(),
                self.log()
            );
        }
        // `loom supervise` forwards SIGTERM/SIGINT to its standby child and exits
        // once the child does -- but a test that panicked before reaching that
        // point, or one that does not exercise the signal path at all, still
        // needs a hard cleanup so it can't leak the process (and the listening
        // sockets) past the test.
        if status.is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Drains one pipe of the server's output into its log (and, for the spawns that
/// stream lines to a caller, a channel of the same lines) on a dedicated thread.
/// Keeps the last [`LOG_KEEP_LINES`] lines so a long-running server can't grow
/// the buffer without bound.
///
/// The drain never stops early -- not even when the channel's receiver is gone
/// -- because a full pipe buffer would block the server itself writing to its
/// own stdout.
fn drain_pipe<R: Read + Send + 'static>(
    pipe: R,
    log: Arc<Mutex<Vec<String>>>,
    lines: Option<std::sync::mpsc::Sender<String>>,
) {
    std::thread::spawn(move || {
        for line in BufReader::new(pipe).lines().map_while(Result::ok) {
            {
                let mut buf = log.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if buf.len() >= LOG_KEEP_LINES {
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

// ---------------------------------------------------------------- fixtures --

/// Copies the named fixture mudlib out of `<manifest_dir>/tests/fixtures/<name>`
/// into a fresh scratch directory, so a test can rewrite `.wf` files without
/// touching the repository. `manifest_dir` is passed in (as
/// `env!("CARGO_MANIFEST_DIR")` at the call site) because this crate's own
/// manifest dir is not the one holding the fixtures.
pub fn fixture(manifest_dir: &str, name: &str) -> PathBuf {
    let src = Path::new(manifest_dir)
        .join("tests")
        .join("fixtures")
        .join(name);
    copy_dir(&src, &scratch_dir(name))
}

/// A unique, empty scratch directory under the system temp dir -- named after
/// the pid so two test binaries in one job can't collide, and after a
/// process-global counter so two tests in one binary can't either.
pub fn scratch_dir(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("loom-testing-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir scratch");
    dir
}

fn copy_dir(from: &Path, to: &Path) -> PathBuf {
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
    to.to_path_buf()
}

// ------------------------------------------------------------------- tests --

/// OBI-292's regression guard for the allocator itself, here so every suite
/// shares one copy: the ports a test hands to a spawned server must come from
/// the non-ephemeral band (so the kernel can never hand one of them to an
/// outbound connection) and must be distinct within a process (so two tests in
/// the same `cargo test` run can't be told the same port).
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

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
        let unique: HashSet<u16> = ports.iter().copied().collect();
        assert_eq!(
            unique.len(),
            ports.len(),
            "reserve_local_port handed out the same port twice"
        );
    }

    /// A port that is already taken must never be handed out again -- the
    /// property the old ephemeral probe could not guarantee, since the kernel
    /// was the one choosing it and the probe's own port was immediately
    /// reusable by anything else asking for one.
    #[test]
    fn an_occupied_port_is_skipped_not_reused() {
        let port = reserve_local_port();
        let held = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .expect("hold the reserved port");
        let next = reserve_local_port();
        assert_ne!(next, port, "a busy port was handed out again");
        drop(held);
    }

    /// Two threads racing the allocator get distinct ports, which is what the
    /// process-global cursor buys.
    #[test]
    fn concurrent_reservations_never_collide() {
        const THREADS: usize = 4;
        const PER_THREAD: usize = 16;
        let ports = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    scope.spawn(|| {
                        (0..PER_THREAD)
                            .map(|_| reserve_local_port())
                            .collect::<Vec<u16>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().expect("allocator thread"))
                .collect::<Vec<u16>>()
        });
        let unique: HashSet<u16> = ports.iter().copied().collect();
        assert_eq!(
            unique.len(),
            THREADS * PER_THREAD,
            "concurrent reservations collided"
        );
    }

    #[test]
    fn bind_string_is_loopback_and_parses() {
        let port = reserve_local_port();
        let addr = bind_string(port);
        assert!(addr.starts_with("127.0.0.1:"));
        assert_eq!(addr.parse::<SocketAddr>().expect("parses").port(), port);
    }

    #[test]
    fn strip_ansi_removes_only_sgr_sequences() {
        let coloured = "\u{1b}[32mINFO\u{1b}[0m loom supervise: serving\n";
        assert_eq!(strip_ansi(coloured), "INFO loom supervise: serving\n");
    }

    /// A transcript read must not fail on a non-UTF-8 byte in the middle of a
    /// line -- the `stream did not contain valid UTF-8` class of flake that
    /// OBI-292 hit and OBI-305 now guards for everyone.
    #[test]
    fn read_until_contains_survives_binary_noise() -> std::io::Result<()> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let addr = listener.local_addr()?;
        let client = TcpStream::connect(addr)?;
        let (mut peer, _) = listener.accept()?;
        // `IAC WILL ECHO` -- not valid UTF-8 on its own -- ahead of the needle.
        peer.write_all(&[0xff, 0xfb, 0x01])?;
        peer.write_all(b"Welcome.\n")?;
        peer.flush()?;
        client.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut reader = BufReader::new(client);
        let transcript = read_until_contains(&mut reader, "Welcome.", Duration::from_secs(2));
        assert!(transcript.contains("Welcome."), "{transcript}");
        Ok(())
    }

    /// And a *timeout* still reports the transcript it did read, which is the
    /// only thing that made OBI-292's CI failures diagnosable.
    #[test]
    fn a_stuck_transcript_read_panics_with_what_it_saw() -> std::io::Result<()> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let addr = listener.local_addr()?;
        let client = TcpStream::connect(addr)?;
        let (mut peer, _) = listener.accept()?;
        peer.write_all(b"partial output\n")?;
        peer.flush()?;
        client.set_read_timeout(Some(Duration::from_millis(50)))?;
        let mut reader = BufReader::new(client);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            read_until_contains(&mut reader, "never arrives", Duration::from_millis(200))
        }));
        assert!(caught.is_err(), "a missing needle must fail the test");
        Ok(())
    }
}
