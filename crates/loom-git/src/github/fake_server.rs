// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oberfield

//! The fake GitHub **server** every `loom-git` test talks to: one accept
//! loop, one thread per connection, and no connection it accepts without an
//! answer (OBI-351).
//!
//! OBI-350 fixed what the fake *read* -- one complete request, not one TCP
//! segment. This module fixes what the fake *does with a connection*, which
//! was the other half of the same flake:
//!
//! * **One accept loop serving connections serially.** A client that stalled
//!   mid-request put the whole fake out of service for as long as it took to
//!   give up on it, and every other connection queued behind that. Now the
//!   accept loop only accepts, and each connection is read, answered and
//!   closed on its own thread.
//! * **`Err(_) => continue` on a failed read** -- a connection accepted and
//!   then answered by nothing. The client's socket sees a bare close, `ureq`
//!   reports an io error, and `GitHubAppClient` maps *any* io error to
//!   [`crate::github::GitHubAppError::Transport`]. A test about *response
//!   parsing* then fails as if parsing were broken. Now every branch writes an
//!   HTTP response (`400` for a request it could not complete, `500` if the
//!   test's own handler panicked, `503` when the fake is at its connection
//!   ceiling) and records *why* in
//!   [`FakeHttpServer::dropped_connections`], so the assertion that goes red
//!   says which failure it saw.
//! * **An absolute 10 s budget on the client** (`transport.rs`, `Default` --
//!   a product policy, and it stays one). On a contended runner that number is
//!   a coin flip about scheduling, so the harness replaces it with a
//!   **readiness barrier**: [`FakeHttpServer::spawn`] does not return until the
//!   fake has answered a complete request on its own accept loop
//!   ([`READY_PATH`]). What a test then spends is its budget
//!   ([`TEST_TRANSPORT_BUDGET`]) on one loopback round trip against a server
//!   shown, one moment ago, to work.
//!
//! The ceiling ([`ServerOptions::max_inflight`]) is here because this is still
//! a fake a test can drive: threads are a resource, and the bounded answer
//! under pressure is a `503` we record rather than an unbounded spawn.
//!
//! A fake outlives its handle: like the fakes it replaces it serves for the
//! life of the test process. The only thing that stops it is the process
//! exiting, or [`MAX_ACCEPT_FAILURES`] consecutive `accept` errors -- which are
//! recorded before it stops, so a test waiting on a dead fake fails on its own
//! assertion instead of on a hang.

use std::any::Any;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::fake_http::{self, FakeRequest};
use crate::github::UreqClient;

/// The request the readiness probe sends. Handled by the server itself: never
/// passed to the test's handler, never counted as a GitHub request, so a test's
/// `request_count()` and `served_requests()` stay exact however many probes the
/// barrier needed.
pub const READY_PATH: &str = "/__fake_ready";

/// How long one probe waits for its answer before the barrier retries. Short on
/// purpose: the barrier is what is patient, and a timed-out probe is retried
/// rather than failed.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long [`FakeHttpServer::spawn`] keeps probing before it gives up and says
/// so. A loopback accept loop that has not answered in this long is not "busy",
/// it is wedged, and the run needs to be told rather than have every later
/// test fail as a transport error.
const READY_DEADLINE: Duration = Duration::from_secs(30);

/// Pause between readiness probes. The barrier is a retry loop, not a sleep: a
/// healthy fake is done on the first attempt.
const READY_RETRY: Duration = Duration::from_millis(10);

/// Default ceiling on connections served at the same time. Tests open a
/// handful; the number exists so a runaway client costs a recorded `503` rather
/// than an unbounded number of threads.
pub const DEFAULT_MAX_INFLIGHT: usize = 32;

/// How long one connection's read may take before the fake gives up on *it*.
///
/// Longer than [`crate::github::fake_http::READ_TIMEOUT`] on purpose, and safe
/// to be: that constant bounds the fakes which accept serially, where one
/// stalled client pauses every client behind it. Here each connection is
/// served on its own thread, so patience costs the connection that needed it
/// and nothing else -- which is the whole point of OBI-351. A two-segment POST
/// whose second segment is merely scheduled out must not be answered as if it
/// were malformed, and a busy runner is exactly when that happens.
pub const READ_PATIENCE: Duration = Duration::from_secs(10);

/// How many consecutive `accept()` errors the loop takes before it stops rather
/// than spins. One is a hiccup; this many means the listener is dead.
const MAX_ACCEPT_FAILURES: usize = 64;

/// Backoff between `accept()` retries once something has gone wrong.
const ACCEPT_RETRY: Duration = Duration::from_millis(5);

/// The wall-clock budget one test's own HTTP call gets.
///
/// Deliberately *not* the product default: `UreqClient::default()` gives a call
/// 10 s because the driver must not sit on a hung GitHub, while inside a test
/// the same absolute number is what turns a scheduled-out fake into a
/// `Transport` error (OBI-351). The fake has already been proven to answer
/// before a test's call is made, so this budget only has to cover one loopback
/// round trip -- with enough margin that runner load is not what decides
/// whether a parsing test passes.
pub const TEST_TRANSPORT_BUDGET: Duration = Duration::from_secs(60);

/// How long a harness client socket waits for an answer it should already have.
/// Generous, because nothing in a healthy run comes near it; when it expires,
/// [`read_response`] says exactly what that means.
pub const CLIENT_PATIENCE: Duration = Duration::from_secs(20);

/// How long a test waits for the fake to report that it has a connection
/// parked in the handler. A *rendezvous*, not a guess: the handler signals it,
/// so a test moves the moment the fake is genuinely holding a connection and
/// fails with a named reason if it never is.
pub const HOLD_RENDEZVOUS: Duration = Duration::from_secs(30);

/// What a fake answers one request with: status and body.
pub type Reply = (u16, String);

/// What a fake does with a request: `handle(which_request_number, request)`.
///
/// The request comes **by value**: a `&FakeRequest` parameter makes every
/// closure a test writes fight the compiler over higher-ranked lifetimes
/// (`FnOnce<(usize, &'1 FakeRequest)>` for any `'1`), and a fake that clones
/// one small struct per request is not what anyone is measuring here.
///
/// Object-safe so one handler can be shared by every connection thread without
/// a lock around the call: a handler that parked *while holding a lock* would
/// put connection-level concurrency back to one, which is the thing this module
/// exists to stop. Handlers that mutate state use a `Mutex`/`AtomicUsize` for
/// the record they want and release it before blocking.
pub trait FakeHandler: Send + Sync + 'static {
    fn handle(&self, call: usize, request: FakeRequest) -> Reply;
}

impl<F> FakeHandler for F
where
    F: Fn(usize, FakeRequest) -> Reply + Send + Sync + 'static,
{
    fn handle(&self, call: usize, request: FakeRequest) -> Reply {
        self(call, request)
    }
}

/// Tunables for [`FakeHttpServer::spawn_with`]. Both exist because a test needs
/// to set them: patience, to watch the fake give up on a stalled client without
/// waiting out [`READ_PATIENCE`], and the ceiling, to watch what it
/// does when it is full.
#[derive(Clone, Debug)]
pub struct ServerOptions {
    /// How long the fake waits for one complete request on one connection.
    pub read_timeout: Duration,
    /// How many connections it serves at the same time.
    pub max_inflight: usize,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            read_timeout: READ_PATIENCE,
            max_inflight: DEFAULT_MAX_INFLIGHT,
        }
    }
}

/// A connection the fake accepted and could not serve as a GitHub request.
/// It was *answered* anyway -- the record exists so a red test can name the
/// failure instead of inferring it from an io error.
#[derive(Clone, Debug)]
pub struct DropRecord {
    /// The client's address, or `"accept loop"` when no connection was ever
    /// handed over.
    pub peer: String,
    /// Why the fake could not serve it.
    pub reason: String,
}

/// A running fake GitHub server. Dropping the handle does not stop it; see the
/// module docs.
pub struct FakeHttpServer {
    addr: String,
    state: Arc<State>,
}

/// What the server counts, shared between the accept loop and the connection
/// threads.
#[derive(Default)]
struct State {
    /// GitHub requests handed to the test's handler, in arrival order. The
    /// readiness probe is not among them.
    requests: AtomicUsize,
    /// Readiness probes answered -- proof the barrier really round-tripped.
    probes: AtomicUsize,
    /// Connections being served right now.
    inflight: AtomicUsize,
    /// The full text of every request the fake took to its handler. Pushed
    /// *before* the handler runs, so a test that has seen the response has
    /// certainly seen the record.
    served: Mutex<Vec<String>>,
    /// Connections accepted but not served, each with its reason.
    dropped: Mutex<Vec<DropRecord>>,
}

impl FakeHttpServer {
    /// Spawn a loopback fake with default options, and **do not return until it
    /// has answered a real request** (see the module docs).
    ///
    /// Panics if the loopback bind or the readiness barrier fails: that is a
    /// broken harness, and no result from it is worth reporting.
    pub fn spawn<H: FakeHandler>(handler: H) -> Self {
        Self::spawn_with(ServerOptions::default(), handler)
            .expect("bind a loopback fake GitHub server")
    }

    /// [`spawn`](Self::spawn()) with explicit options. `None` only if the
    /// loopback bind or `local_addr()` fails.
    pub fn spawn_with<H: FakeHandler>(options: ServerOptions, handler: H) -> Option<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").ok()?;
        let addr = listener.local_addr().ok()?.to_string();
        let state = Arc::new(State::default());
        let handler: Arc<H> = Arc::new(handler);

        {
            let state = state.clone();
            let handler = handler.clone();
            let _accept_thread = std::thread::Builder::new()
                .name("fake-github-accept".to_string())
                .spawn(move || accept_loop(listener, state, handler, options));
            // If the accept loop itself could not start, the readiness barrier
            // below is what says so, and loudly.
        }

        let server = Self {
            addr,
            state: state.clone(),
        };
        server.wait_ready();
        Some(server)
    }

    /// The fake's `host:port`, for tests that connect as a raw client.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// `http://<addr>`, ready for
    /// [`GitHubAppClient::with_api_base`](crate::github::GitHubAppClient::with_api_base).
    pub fn api_base(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// How many GitHub requests reached the handler.
    pub fn request_count(&self) -> usize {
        self.state.requests.load(Ordering::SeqCst)
    }

    /// The full text of every request the fake served, in arrival order.
    pub fn served_requests(&self) -> Vec<String> {
        self.state.served.lock().unwrap().clone()
    }

    /// Connections the fake accepted and could not serve, each with the reason.
    /// Empty is the healthy answer.
    pub fn dropped_connections(&self) -> Vec<DropRecord> {
        self.state.dropped.lock().unwrap().clone()
    }

    /// How many readiness probes the fake has answered. At least one before
    /// [`spawn`](Self::spawn()) ever returned.
    pub fn readiness_probes(&self) -> usize {
        self.state.probes.load(Ordering::SeqCst)
    }

    /// Assert that nothing this fake accepted went unanswered.
    ///
    /// Cheap enough to end every test that talks to a fake with, and it is the
    /// assertion that separates "the parser disagreed with me" from "the
    /// harness lost a connection" -- the distinction OBI-351 exists for. A test
    /// that fails *here* has found a harness bug; one that fails anywhere else
    /// has found a product one.
    pub fn assert_healthy(&self) {
        let dropped = self.dropped_connections();
        assert!(
            dropped.is_empty(),
            "the fake accepted a connection it could not serve: {dropped:?}"
        );
    }

    /// Block until the fake has answered a complete readiness request.
    ///
    /// This is the harness's barrier: it proves the accept loop is running, and
    /// that a connection thread read a request, answered it and closed the way
    /// a real server does. Anything a test measures afterwards is measured
    /// against a server shown to work one moment ago -- not against a thread
    /// that may not have been scheduled yet.
    fn wait_ready(&self) {
        let deadline = Instant::now() + READY_DEADLINE;
        loop {
            // Every attempt that fails is remembered for the message: the
            // deadline is only ever reached on a failure, so the most recent
            // probe's reason is the one worth printing.
            let failure = match probe_once(&self.addr, PROBE_TIMEOUT) {
                Ok(()) => return,
                Err(failure) => failure,
            };
            if Instant::now() >= deadline {
                panic!(
                    "fake GitHub server at {} never answered the readiness request within {READY_DEADLINE:?} \
                     (last probe: {failure}); the harness is wedged, so nothing measured through it can be trusted",
                    self.addr
                );
            }
            std::thread::sleep(READY_RETRY);
        }
    }
}

/// Accept and hand over: the loop does nothing that can block on one client's
/// I/O, because one stalled client must not be able to stop the fake from
/// meeting the next one (OBI-351).
fn accept_loop<H: FakeHandler>(
    listener: TcpListener,
    state: Arc<State>,
    handler: Arc<H>,
    options: ServerOptions,
) {
    let mut accept_failures = 0usize;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                accept_failures = 0;
                serve_one_connection(stream, &state, &handler, &options);
            }
            Err(error) => {
                accept_failures += 1;
                state.dropped.lock().unwrap().push(DropRecord {
                    peer: "accept loop".to_string(),
                    reason: format!("accept failed: {error}"),
                });
                if accept_failures >= MAX_ACCEPT_FAILURES {
                    // Loud in the record, quiet on the CPU: a test still
                    // waiting on this fake fails on its own assertion rather
                    // than watching this loop spin for the rest of the run.
                    return;
                }
                std::thread::sleep(ACCEPT_RETRY);
            }
        }
    }
}

/// Hand one accepted connection to its own thread.
///
/// If the process cannot afford another thread, serve it on this one: the
/// promise of this module is that an accepted connection gets an answer, and
/// that has to hold even when the machine says no.
fn serve_one_connection<H: FakeHandler>(
    stream: TcpStream,
    state: &Arc<State>,
    handler: &Arc<H>,
    options: &ServerOptions,
) {
    let connection = match stream.try_clone() {
        Ok(connection) => connection,
        // No second handle to the socket, so no thread to hand it to.
        Err(_) => return serve_connection(stream, state.clone(), handler.clone(), options.clone()),
    };
    let thread_state = state.clone();
    let thread_handler = handler.clone();
    let thread_options = options.clone();
    let spawned = std::thread::Builder::new()
        .name("fake-github-conn".to_string())
        .spawn(move || serve_connection(connection, thread_state, thread_handler, thread_options));
    if spawned.is_err() {
        serve_connection(stream, state.clone(), handler.clone(), options.clone());
    }
}

/// Read, answer and close one connection. Every path through here writes an
/// HTTP response -- that is the rule OBI-351 exists to enforce.
fn serve_connection<H: FakeHandler>(
    mut stream: TcpStream,
    state: Arc<State>,
    handler: Arc<H>,
    options: ServerOptions,
) {
    let peer = stream
        .peer_addr()
        .map(|peer| peer.to_string())
        .unwrap_or_else(|_| "unknown peer".to_string());

    let Some(_slot) = InFlight::try_new(&state.inflight, options.max_inflight) else {
        state.dropped.lock().unwrap().push(DropRecord {
            peer,
            reason: format!("refused at the {}-connection ceiling", options.max_inflight),
        });
        fake_http::respond(
            &mut stream,
            503,
            r#"{"message":"fake GitHub server at its connection ceiling"}"#,
        );
        return;
    };

    match fake_http::read_request_within(&mut stream, options.read_timeout) {
        // The barrier's own request: answered here, invisible to tests.
        Some(request) if request.path == READY_PATH => {
            state.probes.fetch_add(1, Ordering::SeqCst);
            fake_http::respond(&mut stream, 200, r#"{"ready":true}"#);
        }
        Some(request) => {
            let call = state.requests.fetch_add(1, Ordering::SeqCst);
            state.served.lock().unwrap().push(request.raw.clone());
            // A handler that panics is a bug in the *test*, and the old harness
            // let that panic take the connection -- and, with a serial loop,
            // everything behind it -- down with it. Answer, record, keep going.
            match catch_unwind(AssertUnwindSafe(|| handler.handle(call, request))) {
                Ok((status, body)) => fake_http::respond(&mut stream, status, &body),
                Err(payload) => {
                    state.dropped.lock().unwrap().push(DropRecord {
                        peer,
                        reason: format!("the test's handler panicked: {}", panic_text(payload)),
                    });
                    fake_http::respond(
                        &mut stream,
                        500,
                        r#"{"message":"fake GitHub server: test handler panicked"}"#,
                    );
                }
            }
        }
        // The `continue` path, retired: this connection was accepted, so it gets
        // an answer and a record. Silence is what `ureq` reported as an io
        // error, which `GitHubAppClient` reported as `Transport`, which is what
        // made a parsing test look like a broken parser.
        None => {
            state.dropped.lock().unwrap().push(DropRecord {
                peer,
                reason: format!(
                    "request never became complete within {:?} \
                     (no header terminator, short body, or the client hung up)",
                    options.read_timeout
                ),
            });
            fake_http::respond(
                &mut stream,
                400,
                r#"{"message":"fake GitHub server: incomplete request"}"#,
            );
        }
    }
}

/// The panic payload as one line, for the record. `catch_unwind` hands back
/// `Box<dyn Any>`, and the useful half of a test failure is its message.
fn panic_text(payload: Box<dyn Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "panic with no message".to_string()
    }
}

/// One in-flight connection slot, released when the connection is done.
struct InFlight<'a>(&'a AtomicUsize);

impl<'a> InFlight<'a> {
    /// Take a slot, or `None` when the fake is already serving `max_inflight`
    /// connections. Compare-and-swap, so two clients cannot both take the last
    /// one.
    fn try_new(counter: &'a AtomicUsize, max_inflight: usize) -> Option<Self> {
        let mut current = counter.load(Ordering::SeqCst);
        loop {
            if current >= max_inflight {
                return None;
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Some(Self(counter)),
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Send one readiness request and read the answer. Used by the barrier, and by
/// the test that proves the barrier is not decoration.
fn probe_once(addr: &str, budget: Duration) -> Result<(), String> {
    // Its own connect, not the `connect` helper: a refused probe is a normal
    // thing to retry while the accept loop is coming up, and must not panic.
    let mut stream = TcpStream::connect(addr)
        .map_err(|error| format!("connect to the fake at {addr}: {error}"))?;
    stream
        .set_read_timeout(Some(budget))
        .map_err(|error| format!("set_read_timeout: {error}"))?;
    let request = get_request(READY_PATH);
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("write: {error}"))?;
    stream.flush().map_err(|error| format!("flush: {error}"))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| format!("read: {error}"))?;
    if response.starts_with("HTTP/1.1 200") && response.contains(r#""ready":true"#) {
        Ok(())
    } else {
        Err(format!("unexpected readiness response: {response:?}"))
    }
}

/// Connect to a fake at `addr` (`host:port`) as a raw client, with `patience`
/// to wait for an answer.
pub fn connect(addr: &str, patience: Duration) -> TcpStream {
    let stream = TcpStream::connect(addr)
        .unwrap_or_else(|error| panic!("connecting to the fake at {addr}: {error}"));
    stream
        .set_nodelay(true)
        .expect("set_nodelay on a loopback client");
    stream
        .set_read_timeout(Some(patience))
        .expect("set_read_timeout on a loopback client");
    stream
}

/// The bytes of a complete `GET path` that wants the connection closed after
/// the response.
pub fn get_request(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
}

/// Read a whole response from a harness client, or fail naming what the wait
/// meant. `unwrap()` here would be the same silence this issue is about: an io
/// error *is* what a lost connection looks like.
pub fn read_response(stream: &mut TcpStream, what: &str) -> String {
    let mut response = String::new();
    match stream.read_to_string(&mut response) {
        Ok(_) => response,
        Err(error) => panic!(
            "{what}: the fake accepted this connection and never answered it \
             ({error}) after {CLIENT_PATIENCE:?}"
        ),
    }
}

/// A one-way gate a handler parks behind until the test opens it, so a "while
/// this connection is held…" test can synchronise on the fake rather than sleep
/// and hope. Any number of connections can wait on it, and none of them holds a
/// lock across the wait.
#[derive(Default)]
pub struct Gate {
    open: Mutex<bool>,
    opened: Condvar,
}

impl Gate {
    /// Park this connection until [`open`](Self::open()) is called.
    pub fn wait_for_open(&self) {
        let mut guard = self.open.lock().unwrap();
        while !*guard {
            guard = self.opened.wait(guard).unwrap();
        }
    }

    /// Let every parked connection go.
    pub fn open(&self) {
        let mut guard = self.open.lock().unwrap();
        *guard = true;
        self.opened.notify_all();
    }
}

/// The transport every `loom-git` test should use: the real `ureq` code path
/// with the harness's budget rather than the product's (see
/// [`TEST_TRANSPORT_BUDGET`]).
pub fn test_transport() -> UreqClient {
    UreqClient::with_timeout(TEST_TRANSPORT_BUDGET)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// Send `path` to `server` and wait until its handler reports it is parked
    /// there, so the test never has to guess when the fake "got around to" the
    /// connection it just accepted.
    fn park_connection(
        server: &FakeHttpServer,
        path: &str,
        entered: &mpsc::Receiver<()>,
    ) -> TcpStream {
        let mut stream = connect(server.addr(), CLIENT_PATIENCE);
        stream.write_all(get_request(path).as_bytes()).unwrap();
        stream.flush().unwrap();
        entered.recv_timeout(HOLD_RENDEZVOUS).unwrap_or_else(|_| {
            panic!("the fake never started serving the {path} connection it accepted")
        });
        stream
    }

    #[test]
    fn spawn_returns_only_after_the_fake_has_answered_a_request() {
        // The readiness barrier is what stops a test's budget from being spent
        // waiting for the harness to come alive, so prove the barrier ran -- and
        // that it ran without leaving a mark on the counters tests read.
        let server =
            FakeHttpServer::spawn(|_call: usize, _request: FakeRequest| (200, "{}".to_string()));
        assert!(
            server.readiness_probes() >= 1,
            "spawn() handed out a fake that had not answered a single request"
        );
        assert_eq!(
            server.request_count(),
            0,
            "the readiness probe must not reach the handler or the request count"
        );
        assert!(
            server.served_requests().is_empty(),
            "the readiness probe was recorded as a served request: {:?}",
            server.served_requests()
        );
        server.assert_healthy();
        // And it still answers probes after the barrier did its job.
        probe_once(server.addr(), PROBE_TIMEOUT).expect("probe after spawn");
        assert_eq!(server.request_count(), 0);
    }

    #[test]
    fn answers_a_second_connection_while_the_first_is_still_being_held() {
        // OBI-351's regression test, deterministic by construction: the test
        // *knows* connection 1 is parked inside the handler (the handler told
        // it), and connection 2 is answered only if the harness serves
        // connections concurrently. Under the old serial accept loop connection
        // 2 sits in the kernel's backlog until the gate opens, so that harness
        // fails here by design rather than by timing.
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let gate = Arc::new(Gate::default());
        let gate_in_handler = gate.clone();

        let server = FakeHttpServer::spawn(move |call: usize, request: FakeRequest| {
            if request.path == "/held" {
                let _ = entered_tx.send(());
                gate_in_handler.wait_for_open();
                return (204, String::new());
            }
            (
                200,
                format!("{{\"call\":{call},\"path\":\"{}\"}}", request.path),
            )
        });

        let mut held = park_connection(&server, "/held", &entered_rx);

        let mut other = connect(server.addr(), CLIENT_PATIENCE);
        other.write_all(get_request("/second").as_bytes()).unwrap();
        let response = read_response(&mut other, "second connection, first still held");

        gate.open();
        let held_response = read_response(&mut held, "held connection, after release");

        assert!(
            response.contains("200 OK"),
            "the second connection was not answered normally while the first was held: {response:?}"
        );
        assert!(
            response.contains("/second"),
            "the second connection was answered by the wrong branch: {response:?}"
        );
        assert!(
            held_response.contains("204"),
            "the held connection never got its answer: {held_response:?}"
        );
        assert_eq!(
            server.request_count(),
            2,
            "both connections should have reached the handler"
        );
        server.assert_healthy();
    }

    #[test]
    fn answers_a_connection_whose_request_never_becomes_complete() {
        // The `Err(_) => continue` path, retired: a client that starts a request
        // and cannot finish it gets a `400` and a recorded reason, not a closed
        // socket. `GitHubAppClient` turns that `400` into `GitHubAppError::Api`
        // -- a definite answer -- where silence used to arrive as
        // `GitHubAppError::Transport`.
        const PATIENCE: Duration = Duration::from_millis(200);
        let server = FakeHttpServer::spawn_with(
            ServerOptions {
                read_timeout: PATIENCE,
                ..ServerOptions::default()
            },
            |_call: usize, _request: FakeRequest| -> Reply {
                unreachable!("an incomplete request must never reach the handler")
            },
        )
        .expect("loopback fake");

        let mut stream = connect(server.addr(), CLIENT_PATIENCE);
        // A request line and headers with no blank line: the reader never sees a
        // complete header block, so it gives up on its own clock (200 ms here)
        // and hands the connection back as "no request".
        //
        // A request whose *body* runs short is a different case on purpose: the
        // OBI-350 reader serves it as a request with the truncated body it got,
        // so it would reach the handler rather than this path.
        stream.write_all(b"POST /never HTTP/1.1\r\n").unwrap();
        stream.flush().unwrap();

        let response = read_response(&mut stream, "incomplete request");
        assert!(
            response.starts_with("HTTP/1.1 400"),
            "an incomplete request must be answered, not abandoned: {response:?}"
        );
        assert_eq!(server.request_count(), 0);
        let dropped = server.dropped_connections();
        assert_eq!(
            dropped.len(),
            1,
            "the drop has to be recorded for the assertion to read"
        );
        assert!(
            dropped[0].reason.contains("never became complete"),
            "the record should say what happened: {dropped:?}"
        );
        assert_ne!(
            dropped[0].peer, "accept loop",
            "the record should name the client connection that went unanswered"
        );
    }

    #[test]
    fn answers_at_capacity_with_503_and_a_record() {
        // Bounded by design: past the ceiling the fake says "no" in HTTP. It
        // does not queue unbounded threads, and it does not go quiet.
        const CEILING: usize = 2;
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let gate = Arc::new(Gate::default());
        let gate_in_handler = gate.clone();

        let server = FakeHttpServer::spawn_with(
            ServerOptions {
                max_inflight: CEILING,
                ..ServerOptions::default()
            },
            move |_call: usize, request: FakeRequest| {
                if request.path == "/held" {
                    let _ = entered_tx.send(());
                    gate_in_handler.wait_for_open();
                    return (204, String::new());
                }
                (200, "{}".to_string())
            },
        )
        .expect("loopback fake");

        let mut held = Vec::new();
        for _ in 0..CEILING {
            held.push(park_connection(&server, "/held", &entered_rx));
        }

        let mut overflow = connect(server.addr(), CLIENT_PATIENCE);
        overflow
            .write_all(get_request("/overflow").as_bytes())
            .unwrap();
        let response = read_response(&mut overflow, "connection over the in-flight ceiling");

        gate.open();
        for stream in &mut held {
            let body = read_response(stream, "held connection, after release");
            assert!(body.contains("204"), "held connection: {body:?}");
        }

        assert!(
            response.starts_with("HTTP/1.1 503"),
            "over the ceiling the fake must answer, not stall: {response:?}"
        );
        let dropped = server.dropped_connections();
        assert_eq!(dropped.len(), 1, "the refusal must be recorded");
        assert!(
            dropped[0].reason.contains("ceiling"),
            "the record should name the ceiling as the reason: {dropped:?}"
        );
        assert_eq!(
            server.request_count(),
            CEILING,
            "only the connections it had room for should reach the handler"
        );
    }

    #[test]
    fn a_panicking_handler_does_not_take_the_fake_down() {
        // A test that fails inside its handler must not become a fake that
        // cannot answer, because every later test would then read as a transport
        // error -- the exact disguise OBI-351 is about.
        let server = FakeHttpServer::spawn(|call: usize, _request: FakeRequest| {
            if call == 0 {
                panic!("the handler blew up on the first request");
            }
            (200, "{}".to_string())
        });

        let mut first = connect(server.addr(), CLIENT_PATIENCE);
        first.write_all(get_request("/boom").as_bytes()).unwrap();
        let first_response = read_response(&mut first, "connection whose handler panicked");
        assert!(
            first_response.starts_with("HTTP/1.1 500"),
            "a panicking handler is answered 500, not abandoned: {first_response:?}"
        );

        let mut second = connect(server.addr(), CLIENT_PATIENCE);
        second.write_all(get_request("/after").as_bytes()).unwrap();
        let second_response = read_response(&mut second, "connection after a panicking handler");
        assert!(
            second_response.contains("200 OK"),
            "the fake must keep serving after one handler panics: {second_response:?}"
        );

        let dropped = server.dropped_connections();
        assert_eq!(dropped.len(), 1, "the handler panic must be recorded");
        assert!(
            dropped[0].reason.contains("handler panicked"),
            "the record should say a handler panicked: {dropped:?}"
        );
        assert_eq!(server.request_count(), 2);
    }
}
