// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Telnet/WebSocket networking and sessions (§8.2). Owner: Legolas.

mod telnet;
mod ws;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

pub use telnet::GmcpMessage;
use telnet::{DO, DONT, IAC, SB, SE, TelnetEvent, TelnetOptionTable, WILL, WONT, encode_gmcp};

pub type ConnId = u64;

/// Cap on any telnet subnegotiation body (CTO decision, OBI-26): GMCP in
/// particular carries a client-controlled JSON parser on the network
/// edge, so an oversized frame gets dropped (and counted), not buffered
/// without bound.
pub(crate) const MAX_SUBNEGOTIATION_BYTES: usize = 8192;

pub const DEFAULT_TELNET_ADDR: &str = "0.0.0.0:4000";

pub fn telnet_addr_from_env() -> String {
    std::env::var("LOOM_TELNET_ADDR").unwrap_or_else(|_| DEFAULT_TELNET_ADDR.to_string())
}

#[derive(Debug, Clone)]
pub struct NetConfig {
    pub max_line_bytes: usize,
    pub read_buffer_bytes: usize,
    pub output_queue_depth: usize,
    pub rate_limit_burst: u32,
    pub rate_limit_per_second: f64,
    /// Static MSSP fields (spec §7), e.g. `NAME`, `CODEBASE`, `UPTIME`.
    /// Sent verbatim once the client accepts `WILL MSSP`; there is no
    /// dynamic refresh (player counts etc.) in the alpha.
    pub mssp_fields: Vec<(String, String)>,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            max_line_bytes: 4096,
            read_buffer_bytes: 1024,
            output_queue_depth: 64,
            rate_limit_burst: 20,
            rate_limit_per_second: 5.0,
            mssp_fields: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetEvent {
    Connected(ConnId),
    Line(ConnId, String),
    Disconnected(ConnId),
    /// World-tick timer (spec r5 N2, OBI-82): `loom-cli::serve()` sends one
    /// of these every `WORLD_TICK_INTERVAL` (100 ms) so the world thread can
    /// call `World::tick(host)` between other events. Carries no data: the
    /// world thread advances its own scheduler tick counter (`call_out`
    /// delays are in world ticks, not wall-clock time), so a `Tick` is only
    /// ever "advance by one", never "advance to time T". The timer that
    /// produces this coalesces (see `loom-cli`'s tick task): if the world
    /// thread falls behind, at most one `Tick` is ever pending in the event
    /// channel, not one per missed 100 ms interval.
    Tick,
    /// NAWS: the client's terminal window size in columns/rows.
    WindowSize(ConnId, u16, u16),
    /// TTYPE: one name in the client's MTTS terminal-type cycle. May fire
    /// more than once per connection (spec §7); the world keeps the latest
    /// and/or the richest (`MTTS <bitmask>`) one it understands.
    TerminalType(ConnId, String),
    /// GMCP: one parsed `package.message` frame.
    Gmcp(ConnId, GmcpMessage),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetCommand {
    Send(ConnId, String),
    Close(ConnId),
    /// Send a structured GMCP message (`package.message` + JSON payload) to
    /// one connection. Silently dropped if the connection never enabled
    /// GMCP or has since disconnected.
    SendGmcp(ConnId, String, serde_json::Value),
    /// Turn local client echo on/off around a no-echo input (spec §9,
    /// OBI-176): telnet gets `IAC WILL ECHO`/`IAC WONT ECHO`, WebSocket
    /// gets an `{"type":"echo","enabled":...}` envelope the web client
    /// uses to mask the field. `enabled = false` is the password-prompt
    /// state.
    SetEcho(ConnId, bool),
}

/// Output framing: the world sends text verbatim and owns its line breaks
/// (`send(ob, "...\n")`); on the wire every `\n` becomes telnet's `\r\n`.
/// Nothing is appended, so prompts without a newline stay on the same line.
fn to_wire(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + 8);
    let mut prev = 0_u8;
    for &b in text.as_bytes() {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}

#[derive(Debug)]
enum ConnControl {
    Send(String),
    Close,
    SendGmcp(String, serde_json::Value),
    SetEcho(bool),
    /// Copyover, old-process side (design §7.5 step 2, OBI-184): stop this
    /// connection's read/write loop *without* treating it as a disconnect
    /// (no `NetEvent::Disconnected`, so the world never runs `net_dead()`
    /// on the bound object), reunite the split `TcpStream`, and hand it
    /// back through the carried `oneshot::Sender`.
    ///
    /// `None` means no usable `TcpStream` came back -- either the
    /// connection is a WebSocket (no raw-fd story yet; see `ws.rs`'s
    /// handler, which also disconnects the session when this happens) or
    /// its task had already exited on its own between the reclaim request
    /// and the attempt to deliver it. **Reviewed (OBI-227): any `None`
    /// desyncs `fdpass::send_fds`' position-only fd<->`ConnId` matching
    /// (there is no fd to send for that slot), so the copyover driver
    /// (`loom-supervise`/`loom-cli`, not yet built) must treat `None` as
    /// "this conn_id does not cross the copyover" -- skip it in the send
    /// order on the old side and do not expect it in `live_connections()`
    /// on the new side -- rather than sending a placeholder or shifting
    /// every later fd by one.** `reunite` on two halves that genuinely
    /// came from the same `into_split()` call cannot itself fail, so a
    /// telnet connection's reclaim always sends `Some` once the task
    /// actually processes the request.
    Reclaim(oneshot::Sender<Option<TcpStream>>),
}

/// One pending "take this connection back as a raw `TcpStream`" request
/// (OBI-184's copyover hand-off, old-process side): matches a `ConnId` to
/// the `oneshot::Sender` [`run_server_full`] replies on. Kept as its own
/// channel rather than a `NetCommand` variant because `NetCommand` derives
/// `Clone`/`PartialEq`/`Eq` (for `Host`/test ergonomics elsewhere) and a
/// `oneshot::Sender` cannot implement any of those.
///
/// Ordering (reviewed, OBI-227; enforced by `run_server_full` as of
/// OBI-304): `reclaim_rx` and `command_rx` are read from the same unbiased
/// `tokio::select!`, so a `Send`/`Close`/`SetEcho` for a `ConnId` can still
/// be in flight on `command_rx` when that id's reclaim request is picked
/// up. As of OBI-304 that no longer costs the world any output: the
/// reclaim arm first applies every command `command_rx` has already
/// accepted ([`drain_commands_before_reclaim`]) before it removes the
/// connection's entry, and any command that arrives in the window between
/// the reclaim and the matching `adopt` is buffered for the session
/// ([`HandoffOutbox`]) and replayed, in order, onto the re-adopted
/// connection. Neither side of that has to be quiesced first to keep its
/// already-emitted output.
///
/// What this does *not* buy: it is not a general cross-channel ordering
/// guarantee. A command enqueued after the reclaim request is delivered
/// after the session comes back, not before it leaves -- which is the only
/// reading that is even meaningful once the socket has moved to another
/// process. The copyover driver's required order for a *consistent world*
/// is still the caller's (not this module's) responsibility to enforce:
/// quiesce new input to the objects being handed off, reclaim every live
/// connection (in the order `live_connections()` on the new side will
/// expect, per [`ConnControl::Reclaim`]'s docs), and only then take the
/// world snapshot -- reclaiming after the snapshot would hand off a
/// connection the snapshot never recorded as still bound.
pub type ReclaimRequest = (ConnId, oneshot::Sender<Option<TcpStream>>);

/// Output the world queued for a session while its socket was out of the
/// process for a copyover round trip (OBI-304), keyed by the `ConnId` the
/// id will come back under.
///
/// A `reclaim` removes the connection's `ConnEntry` immediately (so no
/// further command is routed at it in this process) and hands the fd to
/// the caller; a later `adopt` re-keys a *fresh* `run_connection` task
/// under the same id. Anything the world emitted in between had no owner
/// and used to be dropped on the floor -- design §7.5 promises a copyover
/// loses no output, and `loom serve`'s same-process rehearsal round trip
/// does not (and cannot) freeze the world for the duration, so a
/// heartbeat/`call_out` reply, or the tail of an intro burst that landed
/// after the reclaim was applied, silently vanished.
type HandoffOutbox = HashMap<ConnId, VecDeque<ConnControl>>;

/// Per-session bound on [`HandoffOutbox`] (OBI-304): a handed-off session
/// gets buffered no more output than a live one would (`NetConfig::
/// output_queue_depth`), which is also exactly what fits back into the
/// adopted connection's control channel in one pass -- see the `adopt_rx`
/// arm of [`run_server_full`]. Beyond the bound the newest command is
/// dropped with a `warn!` + counter, i.e. the old behaviour, but loudly.
///
/// A no-op unless `conn` is a session this loop actually accepted a
/// reclaim for.
fn park_for_handoff(
    conn: ConnId,
    control: ConnControl,
    handoff: &mut HandoffOutbox,
    queue_depth: usize,
) {
    // Only ids with a marker (i.e. a reclaim this loop actually accepted)
    // get an outbox: a command for a connection that never existed, or
    // one that disconnected normally, stays the silent no-op it has
    // always been.
    let Some(queue) = handoff.get_mut(&conn) else {
        return;
    };
    if queue.len() >= queue_depth {
        warn!(
            conn,
            queue_depth,
            "dropping output queued for a connection mid-copyover-handoff: handoff outbox full \
             (the socket was never re-adopted, or the world outran the handoff)"
        );
        metrics::counter!("loom_net_handoff_outbox_dropped_total").increment(1);
        return;
    }
    queue.push_back(control);
    metrics::counter!("loom_net_handoff_outbox_parked_total").increment(1);
}

/// How many already-queued [`NetCommand`]s [`run_server_full`] applies
/// before it goes back to the fair `select!` when a reclaim arrives
/// (OBI-304). `COMMANDS_PER_RECLAIM_DRAIN` is a *budget*, not the
/// guarantee: whatever exceeds it is still not lost, it just lands in the
/// session's [`HandoffOutbox`] instead of its socket. The number exists so
/// one flood of output for unrelated connections can't delay every other
/// reclaim/adopt in the loop indefinitely.
const COMMANDS_PER_RECLAIM_DRAIN: usize = 256;

#[derive(Debug)]
struct ConnEntry {
    tx: mpsc::Sender<ConnControl>,
    task: JoinHandle<()>,
}

/// Telnet-only server: no WebSocket connections ever arrive. Kept as a
/// thin wrapper over [`run_server_with_ws`] so existing callers (and
/// tests) don't have to thread through an unused channel.
pub async fn run_server(
    listener: TcpListener,
    config: NetConfig,
    event_tx: mpsc::Sender<NetEvent>,
    command_rx: mpsc::Receiver<NetCommand>,
    shutdown_rx: watch::Receiver<bool>,
) -> io::Result<()> {
    // Held for the lifetime of the call so the `ws_accept_rx` select arm
    // never sees a closed channel (which would otherwise short-circuit
    // `tokio::select!`'s `else` branch); nothing ever sends on it.
    let (_ws_accept_tx, ws_accept_rx) = mpsc::channel(1);
    let (_adopt_tx, adopt_rx) = mpsc::channel(1);
    let (_reclaim_tx, reclaim_rx) = mpsc::channel(1);
    run_server_full(
        listener,
        config,
        event_tx,
        command_rx,
        shutdown_rx,
        ws_accept_rx,
        adopt_rx,
        reclaim_rx,
    )
    .await
}

/// Telnet server that also accepts already-upgraded WebSocket connections
/// pushed in from `loom-http`'s `/ws` route (OBI-39). A WS connection
/// shares this function's `ConnId` counter, its `conns` registry (so
/// `NetCommand::Send`/`SendGmcp`/`Close` reach it exactly like a telnet
/// connection), and therefore the same `output_queue_depth` backpressure:
/// a slow WS reader is dropped by the same "queue full" path below as a
/// slow telnet client, not a separate one.
pub async fn run_server_with_ws(
    listener: TcpListener,
    config: NetConfig,
    event_tx: mpsc::Sender<NetEvent>,
    command_rx: mpsc::Receiver<NetCommand>,
    shutdown_rx: watch::Receiver<bool>,
    ws_accept_rx: mpsc::Receiver<axum::extract::ws::WebSocket>,
) -> io::Result<()> {
    // See `run_server`'s own comment: nothing sends on these either, they
    // just have to stay open for `run_server_full`'s select arms.
    let (_adopt_tx, adopt_rx) = mpsc::channel(1);
    let (_reclaim_tx, reclaim_rx) = mpsc::channel(1);
    run_server_full(
        listener,
        config,
        event_tx,
        command_rx,
        shutdown_rx,
        ws_accept_rx,
        adopt_rx,
        reclaim_rx,
    )
    .await
}

/// Copyover, new-process side (design §7.5 step 3, OBI-221): a connection
/// `loom-supervise`'s `SCM_RIGHTS` fd-passing (`loom-supervise::fdpass`,
/// OBI-184) handed this process as a raw, already-connected fd, now a
/// `std::net::TcpStream` the caller has converted with
/// [`std::os::fd::FromRawFd`] (this crate deliberately does not touch
/// raw fds itself -- that conversion, and deciding the fd really is a
/// `TcpStream` and not some other kind of socket, is the copyover driver's
/// job, not `loom-net`'s) and put into non-blocking mode so
/// [`tokio::net::TcpStream::from_std`] accepts it.
///
/// `conn` is the id to re-key this session under -- the copyover driver
/// is expected to pass the *same* `conn` id
/// [`loom_vm::World::live_connections`] recorded for this socket in the
/// snapshot's connection table, in the same order
/// `loom-supervise::fdpass::recv_fds` handed the fds back (see that
/// module's docs: the wire format has no self-describing framing, so
/// order is the only correlation the two sides share), so that once this
/// session is live the driver's `World::reconnect_all` resolves the right
/// object for the right socket. The caller, not `run_server_full`, is
/// responsible for making sure `conn` does not collide with a live
/// freshly-accepted connection's id -- in practice this means draining
/// every adopted connection before the listener accepts anything new,
/// which is exactly the copyover hand-off order already.
pub type AdoptedConn = (ConnId, TcpStream);

/// `run_server_with_ws` plus one more input source: already-connected
/// sockets pushed in by the copyover driver (see [`AdoptedConn`]'s docs),
/// each re-keyed under its own caller-chosen `ConnId` instead of this
/// function's auto-incrementing counter. Both `run_server`/
/// `run_server_with_ws` are thin wrappers over this with an `adopt_rx`
/// nothing ever sends on.
#[allow(clippy::too_many_arguments)]
pub async fn run_server_full(
    listener: TcpListener,
    config: NetConfig,
    event_tx: mpsc::Sender<NetEvent>,
    mut command_rx: mpsc::Receiver<NetCommand>,
    mut shutdown_rx: watch::Receiver<bool>,
    mut ws_accept_rx: mpsc::Receiver<axum::extract::ws::WebSocket>,
    mut adopt_rx: mpsc::Receiver<AdoptedConn>,
    mut reclaim_rx: mpsc::Receiver<ReclaimRequest>,
) -> io::Result<()> {
    let mut next_conn_id: ConnId = 1;
    let mut conns: HashMap<ConnId, ConnEntry> = HashMap::new();
    let mut handoff: HandoffOutbox = HandoffOutbox::new();
    let (closed_tx, mut closed_rx) = mpsc::channel::<ConnId>(256);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                debug!("shutdown signal received by net server");
                break;
            }
            Some(conn_id) = closed_rx.recv() => {
                conns.remove(&conn_id);
            }
            Some((conn, reply_tx)) = reclaim_rx.recv() => {
                // Copyover, old-process side (design §7.5 step 2): hand
                // this connection's raw socket back to the caller instead
                // of tearing it down. `conns.remove` here (not after the
                // task exits via `closed_tx`) stops routing any further
                // `NetCommand`s at this id in *this* process immediately --
                // the connection is, from this process's point of view,
                // already gone to its new owner, even though the task
                // itself is still finishing its reunite-and-reply.
                //
                // OBI-304: first apply whatever `command_rx` has already
                // accepted. `command_rx` and `reclaim_rx` are two different
                // channels read by one unbiased `select!`, so without this
                // the loop could remove the entry while the session's own
                // `NetCommand::Send`s were still queued behind the reclaim
                // request -- the command arm would then find no entry and
                // drop the world's already-emitted output (the OBI-292
                // flake: master `logon()`'s "welcome, then room
                // description" burst split across exactly this boundary).
                // Ordering is guaranteed in one direction only: every
                // command the world enqueued *before* the reclaim request
                // it is handing off for is visible here (the caller's
                // happens-before edge -- the world snapshot reply -- runs
                // through the world thread that produced those commands),
                // so this drain really does flush them to the socket before
                // its fd leaves.
                drain_commands_before_reclaim(&mut command_rx, &mut conns, &mut handoff, &event_tx, config.output_queue_depth).await;
                match conns.remove(&conn) {
                    Some(entry) => {
                        // `try_send` would leave a live connection stranded
                        // on `Full`/`Closed`: the entry is already removed
                        // above (so nothing in *this* loop can retry it),
                        // and dropping `reply_tx` on the spot turns the
                        // caller's `oneshot::Receiver::await` into a bare
                        // `RecvError` instead of the documented `None`.
                        // Block on the send instead, off the main select
                        // loop (so one slow/backed-up connection can't
                        // stall every other connection's reclaim/adopt/
                        // command handling), and recover `reply_tx` out of
                        // the failed send's payload to answer `None` if
                        // the connection task had already exited on its
                        // own in the meantime.
                        tokio::spawn(async move {
                            if let Err(mpsc::error::SendError(ConnControl::Reclaim(reply_tx))) =
                                entry.tx.send(ConnControl::Reclaim(reply_tx)).await
                            {
                                debug!(conn, "reclaim requested but connection task had already exited");
                                let _ = reply_tx.send(None);
                            }
                        });
                        // OBI-304: mark the id as "out of the process for a
                        // handoff" so anything the world emits for it before
                        // the readopt is buffered (see [`HandoffOutbox`])
                        // instead of dropped.
                        handoff.entry(conn).or_default();
                    }
                    None => {
                        debug!(conn, "reclaim requested for an unknown/already-gone connection");
                        let _ = reply_tx.send(None);
                    }
                }
            }
            Some((conn_id, stream)) = adopt_rx.recv() => {
                if let Err(err) = stream.set_nodelay(true) {
                    debug!(conn_id, %err, "set_nodelay failed on adopted connection");
                }
                debug!(conn_id, "adopted a pre-connected (copyover) connection");
                // Keep the auto-increment counter clear of every adopted
                // id, so a connection accepted off the listener right
                // after a batch of adoptions can never collide with one.
                if conn_id >= next_conn_id {
                    next_conn_id = conn_id + 1;
                }
                // CTO review (OBI-266): deliberately *not*
                // `event_tx.send(NetEvent::Connected(conn_id))` here,
                // unlike every other connection source in this loop.
                // An adopted connection is, by definition, one the world
                // already has (or is about to have, via `World::
                // load_snapshot`) a real binding for -- `Connected`
                // driving `World::connect` would call master `connect()`
                // unconditionally and bind a *second*, fresh player to
                // this id, orphaning whatever was already bound (no
                // `net_dead`, no autosave) regardless of whether this is
                // a same-process reclaim/readopt round trip or a real
                // cross-process copyover landing on a freshly-restored
                // `World`. The whole point of adopting under a caller-
                // chosen `ConnId` instead of the auto-increment counter
                // is that the caller (and the `World`) already knows
                // what this connection *is* -- `World::reconnect_all`
                // (OBI-221) is the mechanism that re-attaches a restored
                // binding to its (re)adopted connection, not `connect`.
                // The connection is still fully live and reachable below
                // (`conns.insert`) the moment this arm finishes --
                // nothing here waits for a "ready" signal that doesn't
                // exist.

                let (tx, rx) = mpsc::channel(config.output_queue_depth);
                // OBI-304: replay whatever the world queued for this
                // session while its fd was out, *before* the entry becomes
                // visible to `command_rx`. Pushing into a channel no one
                // else holds a sender for yet keeps the parked output
                // strictly ahead of any new command for this id, and the
                // fresh task writes the negotiation preamble before it ever
                // polls `control_rx`, so the player sees preamble -> output
                // they had already been "sent".
                let mut parked = handoff.remove(&conn_id).unwrap_or_default();
                while let Some(control) = parked.pop_front() {
                    if let Err(mpsc::error::TrySendError::Full(control)) = tx.try_send(control) {
                        // Cannot happen while the per-session bound in
                        // [`park_for_handoff`] equals `output_queue_depth`,
                        // but never lose it (and never block this loop):
                        // hand the remainder to a task that awaits room.
                        let mut remainder = VecDeque::with_capacity(parked.len() + 1);
                        remainder.push_back(control);
                        remainder.append(&mut parked);
                        let replay_tx = tx.clone();
                        tokio::spawn(async move {
                            for control in remainder {
                                if replay_tx.send(control).await.is_err() {
                                    break;
                                }
                            }
                        });
                        break;
                    }
                }
                let conn_event_tx = event_tx.clone();
                let conn_closed_tx = closed_tx.clone();
                let conn_config = config.clone();
                let task = tokio::spawn(async move {
                    run_connection(conn_id, stream, conn_config, rx, conn_event_tx, conn_closed_tx).await;
                });

                conns.insert(conn_id, ConnEntry { tx, task });
            }
            Some(socket) = ws_accept_rx.recv() => {
                let conn_id = next_conn_id;
                next_conn_id += 1;

                debug!(conn_id, "accepted websocket connection");
                if event_tx.send(NetEvent::Connected(conn_id)).await.is_err() {
                    break;
                }

                let (tx, rx) = mpsc::channel(config.output_queue_depth);
                let conn_event_tx = event_tx.clone();
                let conn_closed_tx = closed_tx.clone();
                let conn_config = config.clone();
                let task = tokio::spawn(async move {
                    ws::run_ws_connection(conn_id, socket, conn_config, rx, conn_event_tx, conn_closed_tx).await;
                });

                conns.insert(conn_id, ConnEntry { tx, task });
            }
            Some(cmd) = command_rx.recv() => {
                apply_command(cmd, &mut conns, &mut handoff, &event_tx, config.output_queue_depth).await;
            }
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted?;
                // Interactive line protocol: disable Nagle, or a prompt written
                // right after a command's output waits for the client's delayed
                // ACK (~40 ms on Linux) before it is sent.
                if let Err(err) = stream.set_nodelay(true) {
                    debug!(%peer_addr, %err, "set_nodelay failed");
                }
                let conn_id = next_conn_id;
                next_conn_id += 1;

                debug!(conn_id, %peer_addr, "accepted connection");
                if event_tx.send(NetEvent::Connected(conn_id)).await.is_err() {
                    break;
                }

                let (tx, rx) = mpsc::channel(config.output_queue_depth);
                let conn_event_tx = event_tx.clone();
                let conn_closed_tx = closed_tx.clone();
                let conn_config = config.clone();
                let task = tokio::spawn(async move {
                    run_connection(conn_id, stream, conn_config, rx, conn_event_tx, conn_closed_tx).await;
                });

                conns.insert(conn_id, ConnEntry { tx, task });
            }
            else => break,
        }
    }

    for (conn, entry) in conns.drain() {
        entry.task.abort();
        let _ = event_tx.send(NetEvent::Disconnected(conn)).await;
    }
    if !handoff.is_empty() {
        // OBI-304: a session whose fd left this process and never came back
        // has buffered output with nowhere to go (a real copyover's old
        // process exits here; the new one gets the world's own state from
        // the snapshot). Loud, not silent.
        warn!(
            sessions = handoff.len(),
            "net server shutting down with output still buffered for connections mid-copyover-handoff"
        );
    }

    Ok(())
}

/// Route one [`NetCommand`] to the live connection it is keyed by, with
/// exactly the behaviour every arm of the old inline `command_rx` match had
/// (send, GMCP, echo toggle, close; slow-client disconnect when a
/// connection's control queue is full), plus one new case (OBI-304): a
/// command for an id that is currently *out of the process for a copyover
/// handoff* is buffered for it instead of dropped. Factored out of
/// [`run_server_full`] so the reclaim path can replay the same logic over
/// [`drain_commands_before_reclaim`].
async fn apply_command(
    cmd: NetCommand,
    conns: &mut HashMap<ConnId, ConnEntry>,
    handoff: &mut HandoffOutbox,
    event_tx: &mpsc::Sender<NetEvent>,
    queue_depth: usize,
) {
    match cmd {
        NetCommand::Send(conn, text) => {
            route_or_park(
                conn,
                ConnControl::Send(text),
                conns,
                handoff,
                event_tx,
                queue_depth,
            )
            .await;
        }
        NetCommand::SendGmcp(conn, package_message, payload) => {
            route_or_park(
                conn,
                ConnControl::SendGmcp(package_message, payload),
                conns,
                handoff,
                event_tx,
                queue_depth,
            )
            .await;
        }
        NetCommand::SetEcho(conn, enabled) => {
            route_or_park(
                conn,
                ConnControl::SetEcho(enabled),
                conns,
                handoff,
                event_tx,
                queue_depth,
            )
            .await;
        }
        NetCommand::Close(conn) => match conns.remove(&conn) {
            Some(entry) => match entry.tx.try_send(ConnControl::Close) {
                Ok(()) => {}
                Err(_) => {
                    entry.task.abort();
                    let _ = event_tx.send(NetEvent::Disconnected(conn)).await;
                }
            },
            // OBI-304: the world asked to close a session whose fd is out
            // for a handoff. Re-adopting first, then closing, is the only
            // reading that keeps `net_dead()` running exactly once.
            None => park_for_handoff(conn, ConnControl::Close, handoff, queue_depth),
        },
    }
}

/// The `Send`/`SendGmcp`/`SetEcho` half of [`apply_command`]: these three
/// share one behaviour (queue it, or drop the client when its queue is
/// full), so they share one function rather than three copies of the same
/// match.
async fn route_or_park(
    conn: ConnId,
    control: ConnControl,
    conns: &mut HashMap<ConnId, ConnEntry>,
    handoff: &mut HandoffOutbox,
    event_tx: &mpsc::Sender<NetEvent>,
    queue_depth: usize,
) {
    if let Some(entry) = conns.get(&conn) {
        match entry.tx.try_send(control) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(conn, "disconnecting slow client: output queue full");
                if let Some(entry) = conns.remove(&conn) {
                    entry.task.abort();
                }
                let _ = event_tx.send(NetEvent::Disconnected(conn)).await;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                conns.remove(&conn);
            }
        }
    } else {
        park_for_handoff(conn, control, handoff, queue_depth);
    }
}

/// OBI-304: apply every [`NetCommand`] `command_rx` has already accepted
/// before a reclaim is allowed to remove a connection's entry, so output
/// the world emitted *before* asking for the fd back is written to that fd
/// while it is still here. Bounded by `COMMANDS_PER_RECLAIM_DRAIN`; excess
/// is not lost, it just goes through [`park_for_handoff`] instead.
async fn drain_commands_before_reclaim(
    command_rx: &mut mpsc::Receiver<NetCommand>,
    conns: &mut HashMap<ConnId, ConnEntry>,
    handoff: &mut HandoffOutbox,
    event_tx: &mpsc::Sender<NetEvent>,
    queue_depth: usize,
) {
    for _ in 0..COMMANDS_PER_RECLAIM_DRAIN {
        let Ok(cmd) = command_rx.try_recv() else {
            break;
        };
        apply_command(cmd, conns, handoff, event_tx, queue_depth).await;
    }
}

async fn run_connection(
    conn_id: ConnId,
    stream: TcpStream,
    config: NetConfig,
    mut control_rx: mpsc::Receiver<ConnControl>,
    event_tx: mpsc::Sender<NetEvent>,
    closed_tx: mpsc::Sender<ConnId>,
) {
    let (mut reader, mut writer) = stream.into_split();
    let mut read_buf = vec![0_u8; config.read_buffer_bytes];
    let mut codec = TelnetCodec::new(
        config.max_line_bytes,
        config.rate_limit_burst,
        config.rate_limit_per_second,
        config.mssp_fields.clone(),
    );

    let mut disconnected_sent = false;
    let mut reclaimed_reply: Option<oneshot::Sender<Option<TcpStream>>> = None;

    let start_bytes = codec.start();
    if !start_bytes.is_empty() && writer.write_all(&start_bytes).await.is_err() {
        disconnected_sent = true;
        let _ = event_tx.send(NetEvent::Disconnected(conn_id)).await;
    }

    if !disconnected_sent {
        loop {
            tokio::select! {
                Some(control) = control_rx.recv() => {
                    match control {
                        ConnControl::Send(text) => {
                            if writer.write_all(&to_wire(&text)).await.is_err() {
                                break;
                            }
                        }
                        ConnControl::SendGmcp(package_message, payload) => {
                            if codec.gmcp_enabled() {
                                let bytes = encode_gmcp(&package_message, &payload);
                                if writer.write_all(&bytes).await.is_err() {
                                    break;
                                }
                            } else {
                                debug!(
                                    conn_id,
                                    package_message,
                                    "dropping SendGmcp: GMCP was never negotiated on this connection"
                                );
                            }
                        }
                        ConnControl::Close => {
                            break;
                        }
                        ConnControl::SetEcho(enabled) => {
                            let bytes = codec.set_echo(enabled);
                            if !bytes.is_empty() && writer.write_all(&bytes).await.is_err() {
                                break;
                            }
                        }
                        ConnControl::Reclaim(reply_tx) => {
                            reclaimed_reply = Some(reply_tx);
                            break;
                        }
                    }
                }
                read = reader.read(&mut read_buf) => {
                    let Ok(n) = read else {
                        break;
                    };
                    if n == 0 {
                        break;
                    }

                    match codec.feed(&read_buf[..n]) {
                        CodecOutcome::Ok { lines, responses, events } => {
                            let mut should_break = false;
                            for response in responses {
                                if writer.write_all(&response).await.is_err() {
                                    disconnected_sent = true;
                                    let _ = event_tx.send(NetEvent::Disconnected(conn_id)).await;
                                    should_break = true;
                                    break;
                                }
                            }
                            if should_break {
                                break;
                            }

                            for event in events {
                                let net_event = match event {
                                    TelnetEvent::WindowSize(w, h) => NetEvent::WindowSize(conn_id, w, h),
                                    TelnetEvent::TerminalType(name) => NetEvent::TerminalType(conn_id, name),
                                    TelnetEvent::Gmcp(msg) => NetEvent::Gmcp(conn_id, msg),
                                };
                                if event_tx.send(net_event).await.is_err() {
                                    should_break = true;
                                    break;
                                }
                            }
                            if should_break {
                                break;
                            }

                            for line in lines {
                                if event_tx.send(NetEvent::Line(conn_id, line)).await.is_err() {
                                    should_break = true;
                                    break;
                                }
                            }
                            if should_break {
                                break;
                            }
                        }
                        CodecOutcome::Disconnect(reason) => {
                            warn!(conn_id, reason = reason.as_str(), "disconnecting");
                            if reason == DisconnectReason::RateLimited {
                                metrics::counter!("loom_net_rate_limit_disconnects_total")
                                    .increment(1);
                            }
                            break;
                        }
                    }
                }
                else => break,
            }
        }
    }

    if let Some(reply_tx) = reclaimed_reply {
        // Copyover hand-off, not a disconnect: no `NetEvent::Disconnected`
        // (the world must not run `net_dead()` on this object), and no
        // `closed_tx` notification either -- `run_server_full` already
        // removed this connection's `ConnEntry` before it ever sent
        // `ConnControl::Reclaim`, specifically so it wouldn't be waiting
        // on this task's own bookkeeping to know the handoff happened.
        let stream = reader
            .reunite(writer)
            .expect("reunite: reader/writer came from the same into_split() call");
        let _ = reply_tx.send(Some(stream));
        return;
    }

    if !disconnected_sent {
        let _ = event_tx.send(NetEvent::Disconnected(conn_id)).await;
    }
    let _ = closed_tx.send(conn_id).await;
}

#[derive(Debug)]
enum CodecOutcome {
    Ok {
        lines: Vec<String>,
        responses: Vec<Vec<u8>>,
        events: Vec<TelnetEvent>,
    },
    Disconnect(DisconnectReason),
}

/// Why [`CodecOutcome::Disconnect`] fired (OBI-149): logged at the one
/// call site that owns `conn_id` (`spawn_reader`) so a disconnect caused
/// by the input rate limit (20 burst, 5/s, `TokenBucket`) is
/// distinguishable in the logs from one caused by a client sending an
/// over-long line -- previously *both* closed the connection with no log
/// line at all, which cost an hour of flake-hunting in warp's smoke test
/// (a legitimate burst of input got rate-limited and disconnected, and
/// there was nothing to tell that apart from a client just hanging up).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisconnectReason {
    /// The per-connection input token bucket (burst/refill from
    /// `NetConfig::rate_limit_burst`/`rate_limit_per_second`) was empty.
    RateLimited,
    /// A line exceeded `max_line_bytes` before a terminator arrived.
    LineTooLong,
}

impl DisconnectReason {
    fn as_str(self) -> &'static str {
        match self {
            DisconnectReason::RateLimited => "input rate limit exceeded",
            DisconnectReason::LineTooLong => "input line too long",
        }
    }
}

#[derive(Debug)]
struct TelnetCodec {
    state: ParseState,
    line_buf: Vec<u8>,
    saw_cr: bool,
    max_line_bytes: usize,
    bucket: TokenBucket,
    options: TelnetOptionTable,
    sub_buf: Vec<u8>,
    sub_oversized: bool,
    oversize_subnegotiations: u64,
}

#[derive(Debug, Clone, Copy)]
enum ParseState {
    Data,
    Iac,
    IacVerb(u8),
    Subnegotiation,
    SubnegotiationIac,
}

impl TelnetCodec {
    fn new(
        max_line_bytes: usize,
        burst: u32,
        refill_per_second: f64,
        mssp_fields: Vec<(String, String)>,
    ) -> Self {
        Self {
            state: ParseState::Data,
            line_buf: Vec::with_capacity(128),
            saw_cr: false,
            max_line_bytes,
            bucket: TokenBucket::new(burst, refill_per_second),
            options: TelnetOptionTable::new(mssp_fields),
            sub_buf: Vec::new(),
            sub_oversized: false,
            oversize_subnegotiations: 0,
        }
    }

    /// Startup negotiation bytes to send right after accepting the
    /// connection, before reading anything from the client.
    fn start(&mut self) -> Vec<u8> {
        self.options.start()
    }

    /// Whether GMCP has actually been negotiated (`us == Yes`): gates
    /// `ConnControl::SendGmcp` so a caller can't push a GMCP frame onto a
    /// connection that never agreed to speak it.
    fn gmcp_enabled(&self) -> bool {
        self.options.is_enabled_us(telnet::OPT_GMCP)
    }

    /// Bytes to send to flip local client echo on/off (OBI-176): see
    /// `TelnetOptionTable::set_echo`.
    fn set_echo(&mut self, enabled: bool) -> Vec<u8> {
        self.options.set_echo(enabled)
    }

    fn feed(&mut self, chunk: &[u8]) -> CodecOutcome {
        let mut lines = Vec::new();
        let mut responses = Vec::new();
        let mut events = Vec::new();

        for byte in chunk {
            match self.state {
                ParseState::Data => {
                    if *byte == IAC {
                        self.state = ParseState::Iac;
                        continue;
                    }

                    if let Some(reason) = self.consume_data_byte(*byte, &mut lines) {
                        return CodecOutcome::Disconnect(reason);
                    }
                }
                ParseState::Iac => match *byte {
                    IAC => {
                        if let Some(reason) = self.consume_data_byte(IAC, &mut lines) {
                            return CodecOutcome::Disconnect(reason);
                        }
                        self.state = ParseState::Data;
                    }
                    DO | DONT | WILL | WONT => {
                        self.state = ParseState::IacVerb(*byte);
                    }
                    SB => {
                        self.sub_buf.clear();
                        self.sub_oversized = false;
                        self.state = ParseState::Subnegotiation;
                    }
                    _ => {
                        self.state = ParseState::Data;
                    }
                },
                ParseState::IacVerb(verb) => {
                    let response = if is_known_option(*byte) {
                        self.options.handle_verb(verb, *byte)
                    } else {
                        refusal_for(verb, *byte).unwrap_or_default()
                    };
                    if !response.is_empty() {
                        responses.push(response);
                    }
                    self.state = ParseState::Data;
                }
                ParseState::Subnegotiation => {
                    if *byte == IAC {
                        self.state = ParseState::SubnegotiationIac;
                    } else if self.sub_buf.len() >= MAX_SUBNEGOTIATION_BYTES {
                        // Cap any subnegotiation body at 8 KiB (CTO
                        // decision, OBI-26): a client-controlled parser
                        // (GMCP JSON in particular) sits on the network
                        // edge, so an oversized frame must be dropped and
                        // counted, not buffered forever or used to
                        // disconnect the connection outright.
                        self.sub_oversized = true;
                    } else {
                        self.sub_buf.push(*byte);
                    }
                }
                ParseState::SubnegotiationIac => {
                    if *byte == SE {
                        if self.sub_oversized {
                            self.oversize_subnegotiations += 1;
                            warn!(
                                total = self.oversize_subnegotiations,
                                "dropped oversized telnet subnegotiation (> {MAX_SUBNEGOTIATION_BYTES} bytes)"
                            );
                            // A flood of oversized junk frames is exactly
                            // the kind of client-controlled-parser cost
                            // the rate limit exists for (CTO review,
                            // OBI-26): charge a token here too, not just
                            // on successfully-parsed frames below.
                            if !self.bucket.try_take() {
                                return CodecOutcome::Disconnect(DisconnectReason::RateLimited);
                            }
                        } else {
                            let is_gmcp = self.sub_buf.first() == Some(&telnet::OPT_GMCP);
                            let (response, event) =
                                self.options.handle_subnegotiation(&self.sub_buf);
                            if !response.is_empty() {
                                responses.push(response);
                            }
                            if let Some(event) = event {
                                events.push(event);
                            }
                            // GMCP frames count against the same
                            // per-connection input rate limit as text
                            // lines (CTO decision, OBI-26): it's a
                            // client-controlled parser on the network
                            // edge, same as line input.
                            if is_gmcp && !self.bucket.try_take() {
                                return CodecOutcome::Disconnect(DisconnectReason::RateLimited);
                            }
                        }
                        self.sub_buf.clear();
                        self.sub_oversized = false;
                        self.state = ParseState::Data;
                    } else if *byte == IAC {
                        // Escaped 0xFF byte inside the subnegotiation body.
                        if !self.sub_oversized {
                            if self.sub_buf.len() >= MAX_SUBNEGOTIATION_BYTES {
                                self.sub_oversized = true;
                            } else {
                                self.sub_buf.push(IAC);
                            }
                        }
                        self.state = ParseState::Subnegotiation;
                    } else {
                        // Protocol violation: bail out of the subnegotiation
                        // rather than buffer forever.
                        self.sub_buf.clear();
                        self.sub_oversized = false;
                        self.state = ParseState::Data;
                    }
                }
            }
        }

        CodecOutcome::Ok {
            lines,
            responses,
            events,
        }
    }

    /// Returns `Some(reason)` when the connection should be disconnected.
    fn consume_data_byte(&mut self, byte: u8, lines: &mut Vec<String>) -> Option<DisconnectReason> {
        if self.saw_cr {
            self.saw_cr = false;
            if byte == b'\n' || byte == 0 {
                return self.finish_line(lines);
            }

            if let Some(reason) = self.finish_line(lines) {
                return Some(reason);
            }
        }

        match byte {
            b'\r' => {
                self.saw_cr = true;
                None
            }
            b'\n' => self.finish_line(lines),
            _ => {
                self.line_buf.push(byte);
                (self.line_buf.len() > self.max_line_bytes).then_some(DisconnectReason::LineTooLong)
            }
        }
    }

    /// Returns `Some(reason)` when the connection should be disconnected.
    fn finish_line(&mut self, lines: &mut Vec<String>) -> Option<DisconnectReason> {
        if !self.bucket.try_take() {
            return Some(DisconnectReason::RateLimited);
        }

        let text = String::from_utf8_lossy(&self.line_buf).into_owned();
        self.line_buf.clear();
        lines.push(text);
        None
    }
}

/// Shared by the telnet codec (this file) and the WebSocket connection
/// handler (`ws.rs`): both transports rate-limit input lines through the
/// same token-bucket algorithm and config fields (`rate_limit_burst`,
/// `rate_limit_per_second`), so a player can't get a materially different
/// input rate by switching transport.
#[derive(Debug)]
pub(crate) struct TokenBucket {
    tokens: f64,
    burst: f64,
    refill_per_second: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub(crate) fn new(burst: u32, refill_per_second: f64) -> Self {
        let burst = burst as f64;
        Self {
            tokens: burst,
            burst,
            refill_per_second,
            last_refill: Instant::now(),
        }
    }

    pub(crate) fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

fn is_known_option(option: u8) -> bool {
    // OPT_MCCP2 is deliberately *not* here: MCCP2 is deferred to Phase 2
    // (spec R4), so it gets the same blanket refusal as any option we've
    // never heard of (see `mccp2_is_refused_like_any_unsupported_option`).
    matches!(
        option,
        telnet::OPT_NAWS | telnet::OPT_TTYPE | telnet::OPT_MSSP | telnet::OPT_GMCP
    )
}

fn refusal_for(verb: u8, option: u8) -> Option<Vec<u8>> {
    // RFC 854/1143: never acknowledge a state you are already in. For an
    // option we've never heard of, we are implicitly always in `No`/`No`
    // (never asked to do it, never offered to do it), so a peer telling us
    // `WONT`/`DONT` is telling us something we already believe -- replying
    // would let a peer that also "correctly" answers refusals ping-pong
    // forever. Only `WILL`/`DO` (the peer asking us to change state) gets
    // an answer.
    match verb {
        WILL => Some(vec![IAC, DONT, option]),
        DO => Some(vec![IAC, WONT, option]),
        WONT | DONT => None,
        _ => unreachable!("caller only dispatches DO/DONT/WILL/WONT"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    #[test]
    fn output_translates_newlines_and_appends_nothing() {
        assert_eq!(to_wire("a\nb\n"), b"a\r\nb\r\n");
        assert_eq!(to_wire("already\r\n"), b"already\r\n");
        assert_eq!(to_wire("> "), b"> ");
        assert_eq!(to_wire(""), b"");
    }

    #[test]
    fn strips_negotiation_bytes_and_refuses() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let outcome = codec.feed(&[IAC, WILL, 1, b'h', b'i', b'\n']);

        let CodecOutcome::Ok {
            lines, responses, ..
        } = outcome
        else {
            panic!("unexpected disconnect");
        };

        assert_eq!(lines, vec!["hi"]);
        assert_eq!(responses, vec![vec![IAC, DONT, 1]]);
    }

    #[test]
    fn supports_split_packets_and_cr_variants() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let a = codec.feed(b"hel");
        let b = codec.feed(b"lo\r\nworld\r\0foo\n");

        let CodecOutcome::Ok { lines: a_lines, .. } = a else {
            panic!("unexpected disconnect");
        };
        assert!(a_lines.is_empty());

        let CodecOutcome::Ok { lines: b_lines, .. } = b else {
            panic!("unexpected disconnect");
        };
        assert_eq!(b_lines, vec!["hello", "world", "foo"]);
    }

    #[test]
    fn handles_subnegotiation_and_escaped_iac() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let out = codec.feed(&[
            IAC, SB, 24, 1, b'v', b't', b'1', b'0', b'0', IAC, SE, b'A', IAC, IAC, b'B', b'\n',
        ]);

        let CodecOutcome::Ok {
            lines, responses, ..
        } = out
        else {
            panic!("unexpected disconnect");
        };
        assert_eq!(lines, vec!["A�B"]);
        assert!(responses.is_empty());
    }

    #[test]
    fn disconnects_on_overlong_line() {
        let mut codec = TelnetCodec::new(4, 20, 5.0, Vec::new());
        let out = codec.feed(b"abcde");
        assert!(matches!(
            out,
            CodecOutcome::Disconnect(DisconnectReason::LineTooLong)
        ));
    }

    // OBI-149: a disconnect from the input token bucket (burst exhausted)
    // must carry `DisconnectReason::RateLimited`, distinct from an
    // over-long line -- the caller (`spawn_reader`) logs the two
    // differently, and previously neither was logged at all.
    #[test]
    fn disconnects_with_rate_limited_reason_once_the_burst_is_exhausted() {
        let mut codec = TelnetCodec::new(4096, 1, 0.0, Vec::new());
        // First line consumes the lone burst token and is accepted.
        let out = codec.feed(b"one\n");
        assert!(matches!(out, CodecOutcome::Ok { .. }));
        // The bucket never refills (0.0/s), so a second line disconnects
        // -- and must be reported as rate-limited, not as an overlong line.
        let out = codec.feed(b"two\n");
        assert!(matches!(
            out,
            CodecOutcome::Disconnect(DisconnectReason::RateLimited)
        ));
    }

    #[test]
    fn replaces_invalid_utf8() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let out = codec.feed(&[0xf0, 0x28, 0x8c, 0xbc, b'\n']);

        let CodecOutcome::Ok { lines, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(lines[0], "�(��");
    }

    /// Startup negotiation is always the first bytes on the wire (`DO
    /// NAWS`, `DO TTYPE`, `WILL GMCP`, `WILL MSSP`); tests that assert on
    /// raw bytes read it off first so it doesn't get mixed into whatever
    /// they're actually asserting on.
    const STARTUP_PREAMBLE: &[u8] = &[
        IAC,
        DO,
        telnet::OPT_NAWS,
        IAC,
        DO,
        telnet::OPT_TTYPE,
        IAC,
        WILL,
        telnet::OPT_GMCP,
        IAC,
        WILL,
        telnet::OPT_MSSP,
    ];

    async fn drain_preamble(client: &mut TcpStream) {
        let mut buf = vec![0_u8; STARTUP_PREAMBLE.len()];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, STARTUP_PREAMBLE);
    }

    #[test]
    fn startup_negotiation_offers_alpha_options_once() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        assert_eq!(
            codec.start(),
            vec![
                IAC,
                DO,
                telnet::OPT_NAWS,
                IAC,
                DO,
                telnet::OPT_TTYPE,
                IAC,
                WILL,
                telnet::OPT_GMCP,
                IAC,
                WILL,
                telnet::OPT_MSSP,
            ]
        );
        // Calling start() again must not re-request: every option is
        // already `WantYes`, so a second call is a no-op (RFC 1143 §7).
        assert!(codec.start().is_empty());
    }

    #[test]
    fn mccp2_is_refused_like_any_unsupported_option() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let out = codec.feed(&[IAC, WILL, telnet::OPT_MCCP2]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(responses, vec![vec![IAC, DONT, telnet::OPT_MCCP2]]);

        let out = codec.feed(&[IAC, DO, telnet::OPT_MCCP2]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(responses, vec![vec![IAC, WONT, telnet::OPT_MCCP2]]);
    }

    #[test]
    fn unknown_option_refusals_are_never_acknowledged() {
        // RFC 854/1143: never acknowledge a state you're already in. For an
        // unknown option we're implicitly always No/No, so WONT/DONT (the
        // peer telling us something we already believe) must get silence,
        // not another refusal -- otherwise a peer that also "correctly"
        // answers refusals ping-pongs forever (CTO review, OBI-26).
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let out = codec.feed(&[IAC, WONT, 99]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert!(
            responses.is_empty(),
            "WONT for an unknown option must get silence"
        );

        let out = codec.feed(&[IAC, DONT, 99]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert!(
            responses.is_empty(),
            "DONT for an unknown option must get silence"
        );

        // WILL/DO for an unknown option still get an answer (that's how
        // the peer learns we won't do it).
        let out = codec.feed(&[IAC, WILL, 99]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(responses, vec![vec![IAC, DONT, 99]]);

        let out = codec.feed(&[IAC, DO, 99]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(responses, vec![vec![IAC, WONT, 99]]);
    }

    #[test]
    fn disabling_a_known_option_from_yes_is_acknowledged() {
        // RFC 1143: a Yes -> No transition (the peer disabling something
        // that was negotiated on) must be acknowledged, or a Q-method peer
        // is stuck in WANTNO forever waiting for our answer (CTO review,
        // OBI-26).
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start(); // sends `DO NAWS`; him[NAWS] = WantYes

        // Client agrees: him[NAWS] -> Yes (no reply needed, we already asked).
        let out = codec.feed(&[IAC, WILL, telnet::OPT_NAWS]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert!(responses.is_empty());

        // Client disables it: Yes -> No must be acked with exactly one DONT.
        let out = codec.feed(&[IAC, WONT, telnet::OPT_NAWS]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(responses, vec![vec![IAC, DONT, telnet::OPT_NAWS]]);

        // A second WONT (already No) must get silence, not another DONT.
        let out = codec.feed(&[IAC, WONT, telnet::OPT_NAWS]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert!(responses.is_empty());
    }

    #[test]
    fn send_gmcp_is_dropped_until_gmcp_is_negotiated() {
        // Condition 3 (CTO review, OBI-26): `NetCommand::SendGmcp` must be
        // gated on having actually negotiated GMCP, not just written
        // unconditionally to the wire.
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start(); // sends `WILL GMCP`; us[GMCP] = WantYes
        assert!(!codec.gmcp_enabled());

        let _ = codec.feed(&[IAC, DO, telnet::OPT_GMCP]); // client agrees
        assert!(codec.gmcp_enabled());
    }

    #[test]
    fn set_echo_sends_will_then_wont_echo() {
        // OBI-176: turning off local echo for a password prompt claims
        // `IAC WILL ECHO` (the server will do the echoing, so a
        // well-behaved client stops echoing locally); turning it back on
        // gives `IAC WONT ECHO`.
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        assert_eq!(codec.set_echo(false), vec![IAC, WILL, telnet::OPT_ECHO]);
        assert_eq!(codec.set_echo(true), vec![IAC, WONT, telnet::OPT_ECHO]);
    }

    #[test]
    fn set_echo_is_idempotent_once_settled() {
        // Calling `set_echo` again with the state already where it wants
        // is a silent no-op (Q method, RFC 1143 §7): no repeated WILL/WONT
        // spam on the wire for e.g. two consecutive password prompts with
        // no echo-on in between.
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        assert_eq!(codec.set_echo(false), vec![IAC, WILL, telnet::OPT_ECHO]);
        assert!(codec.set_echo(false).is_empty());

        assert_eq!(codec.set_echo(true), vec![IAC, WONT, telnet::OPT_ECHO]);
        assert!(codec.set_echo(true).is_empty());
    }

    #[test]
    fn set_echo_on_with_echo_never_turned_off_is_a_silent_no_op() {
        // A connection that never had its echo disabled (every ordinary
        // line of input) must not get a stray `WONT ECHO` the first time
        // something calls `set_echo(true)` just to be safe.
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        assert!(codec.set_echo(true).is_empty());
    }

    #[test]
    fn naws_subnegotiation_emits_window_size() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();
        let out = codec.feed(&[
            IAC,
            WILL,
            telnet::OPT_NAWS,
            IAC,
            SB,
            telnet::OPT_NAWS,
            0,
            80,
            0,
            24,
            IAC,
            SE,
        ]);
        let CodecOutcome::Ok { events, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(events, vec![TelnetEvent::WindowSize(80, 24)]);
    }

    #[test]
    fn ttype_cycle_requests_again_until_client_repeats() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();

        // Client agrees to do TTYPE; the codec immediately asks it to SEND.
        let out = codec.feed(&[IAC, WILL, telnet::OPT_TTYPE]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(responses, vec![telnet_send(telnet::OPT_TTYPE)]);

        // First name: keep cycling.
        let out = codec.feed(&ttype_is(b"xterm"));
        let CodecOutcome::Ok {
            events, responses, ..
        } = out
        else {
            panic!("unexpected disconnect");
        };
        assert_eq!(events, vec![TelnetEvent::TerminalType("xterm".into())]);
        assert_eq!(responses, vec![telnet_send(telnet::OPT_TTYPE)]);

        // Second name, different: keep cycling.
        let out = codec.feed(&ttype_is(b"MTTS 137"));
        let CodecOutcome::Ok {
            events, responses, ..
        } = out
        else {
            panic!("unexpected disconnect");
        };
        assert_eq!(events, vec![TelnetEvent::TerminalType("MTTS 137".into())]);
        assert_eq!(responses, vec![telnet_send(telnet::OPT_TTYPE)]);

        // Client repeats the first name: cycle is done, no more SEND.
        let out = codec.feed(&ttype_is(b"xterm"));
        let CodecOutcome::Ok {
            events, responses, ..
        } = out
        else {
            panic!("unexpected disconnect");
        };
        assert_eq!(events, vec![TelnetEvent::TerminalType("xterm".into())]);
        assert!(responses.is_empty());
    }

    #[test]
    fn ttype_cycle_stops_after_max_rounds_if_client_never_repeats() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();
        let _ = codec.feed(&[IAC, WILL, telnet::OPT_TTYPE]);

        let mut last_responses = Vec::new();
        for i in 0..20 {
            let out = codec.feed(&ttype_is(format!("name-{i}").as_bytes()));
            let CodecOutcome::Ok { responses, .. } = out else {
                panic!("unexpected disconnect");
            };
            last_responses = responses;
        }
        assert!(
            last_responses.is_empty(),
            "cycle must terminate even if the client never repeats a name"
        );
    }

    #[test]
    fn gmcp_parses_core_hello_supports_and_char() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();
        let _ = codec.feed(&[IAC, DO, telnet::OPT_GMCP]);

        let msg = feed_gmcp(
            &mut codec,
            "Core.Hello",
            r#"{"client":"Mudlet","version":"4.0"}"#,
        );
        assert_eq!(
            msg,
            GmcpMessage::CoreHello {
                client: "Mudlet".into(),
                version: "4.0".into()
            }
        );

        let msg = feed_gmcp(&mut codec, "Core.Supports.Set", r#"["Char 1", "Room 1"]"#);
        assert_eq!(
            msg,
            GmcpMessage::CoreSupportsSet(vec!["Char 1".into(), "Room 1".into()])
        );

        let msg = feed_gmcp(&mut codec, "Char.Login", r#"{"name":"frodo"}"#);
        assert_eq!(
            msg,
            GmcpMessage::Package {
                module: "Char.Login".into(),
                payload: serde_json::json!({"name": "frodo"}),
            }
        );

        let msg = feed_gmcp(&mut codec, "Room.Info", r#"{"num":1}"#);
        assert_eq!(
            msg,
            GmcpMessage::Package {
                module: "Room.Info".into(),
                payload: serde_json::json!({"num": 1}),
            }
        );
    }

    #[test]
    fn gmcp_malformed_json_drops_the_frame() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();
        let _ = codec.feed(&[IAC, DO, telnet::OPT_GMCP]);

        let mut body = vec![IAC, SB, telnet::OPT_GMCP];
        body.extend_from_slice(b"Char.Login {not json");
        body.push(IAC);
        body.push(SE);
        let CodecOutcome::Ok { events, .. } = codec.feed(&body) else {
            panic!("unexpected disconnect");
        };
        assert!(
            events.is_empty(),
            "malformed JSON must drop the whole frame, not deliver payload: None"
        );
    }

    #[test]
    fn gmcp_oversize_subnegotiation_is_dropped_not_disconnected() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();
        let _ = codec.feed(&[IAC, DO, telnet::OPT_GMCP]);

        let mut body = vec![IAC, SB, telnet::OPT_GMCP];
        body.extend_from_slice(b"Char.Login ");
        body.extend(std::iter::repeat_n(b'a', MAX_SUBNEGOTIATION_BYTES + 1));
        body.push(IAC);
        body.push(SE);
        let CodecOutcome::Ok { events, .. } = codec.feed(&body) else {
            panic!("oversized frame must be dropped, not disconnect the connection");
        };
        assert!(
            events.is_empty(),
            "oversized frame must not produce an event"
        );

        // The connection must still be usable afterwards.
        let msg = feed_gmcp(&mut codec, "Core.Hello", r#"{"client":"x","version":"1"}"#);
        assert_eq!(
            msg,
            GmcpMessage::CoreHello {
                client: "x".into(),
                version: "1".into()
            }
        );
    }

    #[test]
    fn gmcp_core_supports_is_tracked_per_connection() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();
        let _ = codec.feed(&[IAC, DO, telnet::OPT_GMCP]);

        feed_gmcp(&mut codec, "Core.Supports.Set", r#"["Char 1", "Room 1"]"#);
        assert_eq!(
            codec.options.supports(),
            &["Char 1".to_string(), "Room 1".to_string()]
                .into_iter()
                .collect()
        );

        feed_gmcp(&mut codec, "Core.Supports.Add", r#"["Char 1"]"#);
        assert_eq!(
            codec.options.supports(),
            &["Char 1".to_string(), "Room 1".to_string()]
                .into_iter()
                .collect()
        );

        feed_gmcp(&mut codec, "Core.Supports.Remove", r#"["Room 1"]"#);
        assert_eq!(
            codec.options.supports(),
            &["Char 1".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn mssp_emits_configured_fields_once_client_agrees() {
        let fields = vec![
            ("NAME".to_string(), "ObieMud".to_string()),
            ("CODEBASE".to_string(), "Loom".to_string()),
        ];
        let mut codec = TelnetCodec::new(4096, 20, 5.0, fields);
        let _ = codec.start();

        let out = codec.feed(&[IAC, DO, telnet::OPT_MSSP]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(
            responses,
            vec![vec![
                IAC,
                SB,
                telnet::OPT_MSSP,
                1,
                b'N',
                b'A',
                b'M',
                b'E',
                2,
                b'O',
                b'b',
                b'i',
                b'e',
                b'M',
                b'u',
                b'd',
                1,
                b'C',
                b'O',
                b'D',
                b'E',
                b'B',
                b'A',
                b'S',
                b'E',
                2,
                b'L',
                b'o',
                b'o',
                b'm',
                IAC,
                SE,
            ]]
        );

        // A repeated DO must not re-send the data (already `Yes`).
        let out = codec.feed(&[IAC, DO, telnet::OPT_MSSP]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert!(responses.is_empty());
    }

    #[test]
    fn negotiation_settles_and_never_loops_under_repeated_offers() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();

        // A misbehaving/confused peer offers the same option over and over.
        let mut total_responses = 0;
        for _ in 0..100 {
            let out = codec.feed(&[IAC, WILL, telnet::OPT_NAWS]);
            let CodecOutcome::Ok { responses, .. } = out else {
                panic!("unexpected disconnect");
            };
            total_responses += responses.len();
        }
        // First WILL flips `him: WantYes -> Yes` silently (no reply needed,
        // we already sent DO at startup); every repeat after that is a
        // no-op in the `Yes` state. Total replies stay flat, not linear in
        // the number of repeats.
        assert!(
            total_responses <= 1,
            "repeated WILL must not keep provoking replies, got {total_responses}"
        );
    }

    fn telnet_send(option: u8) -> Vec<u8> {
        vec![IAC, SB, option, 1, IAC, SE]
    }

    fn ttype_is(name: &[u8]) -> Vec<u8> {
        let mut out = vec![IAC, SB, telnet::OPT_TTYPE, 0];
        out.extend_from_slice(name);
        out.push(IAC);
        out.push(SE);
        out
    }

    fn feed_gmcp(codec: &mut TelnetCodec, package_message: &str, json: &str) -> GmcpMessage {
        let mut body = vec![IAC, SB, telnet::OPT_GMCP];
        body.extend_from_slice(package_message.as_bytes());
        body.push(b' ');
        body.extend_from_slice(json.as_bytes());
        body.push(IAC);
        body.push(SE);
        let CodecOutcome::Ok { mut events, .. } = codec.feed(&body) else {
            panic!("unexpected disconnect");
        };
        let TelnetEvent::Gmcp(msg) = events.remove(0) else {
            panic!("expected a GMCP event");
        };
        msg
    }

    /// Fuzz seed corpus for the parser state machine (spec's acceptance
    /// criterion for OBI-26): hand-picked byte sequences that hit tricky
    /// transitions (option scanners, escaped `IAC`, truncated/unterminated
    /// subnegotiations, malformed GMCP payloads). Every seed must survive
    /// both a single `feed()` and a byte-at-a-time `feed()` per byte
    /// (the split-packet case) without panicking; `CodecOutcome::Disconnect`
    /// is a legitimate, non-panicking outcome.
    #[test]
    fn fuzz_seeds_never_panic() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/seeds");
        let mut seen = 0;
        for entry in std::fs::read_dir(&dir).expect("seeds dir") {
            let path = entry.expect("entry").path();
            if path.extension().is_none_or(|e| e != "bin") {
                continue;
            }
            seen += 1;
            let data = std::fs::read(&path).expect("read seed");

            let mut whole = TelnetCodec::new(4096, 1000, 1000.0, Vec::new());
            let _ = whole.start();
            let _ = whole.feed(&data);

            let mut byte_at_a_time = TelnetCodec::new(4096, 1000, 1000.0, Vec::new());
            let _ = byte_at_a_time.start();
            for b in &data {
                match byte_at_a_time.feed(std::slice::from_ref(b)) {
                    CodecOutcome::Disconnect(_) => break,
                    CodecOutcome::Ok { .. } => {}
                }
            }
        }
        assert!(seen > 0, "expected at least one seed file in {dir:?}");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        /// Arbitrary byte soup, fed in randomly-sized chunks (so state
        /// survives being split across `feed()` calls, same as real TCP
        /// reads), never panics.
        #[test]
        fn arbitrary_bytes_never_panic(
            bytes in prop::collection::vec(any::<u8>(), 0..512),
            chunk_sizes in prop::collection::vec(1..17_usize, 0..64),
        ) {
            let mut codec = TelnetCodec::new(256, 1000, 1000.0, Vec::new());
            let _ = codec.start();
            let mut offset = 0;
            let mut sizes = chunk_sizes.into_iter().cycle();
            while offset < bytes.len() {
                let take = sizes.next().unwrap_or(1).min(bytes.len() - offset);
                match codec.feed(&bytes[offset..offset + take]) {
                    CodecOutcome::Disconnect(_) => break,
                    CodecOutcome::Ok { .. } => {}
                }
                offset += take;
            }
        }

        /// Same idea, but built from telnet-protocol "tokens" (IAC/verbs/
        /// known option bytes/SB.../SE) instead of uniformly random bytes,
        /// to reach negotiation and subnegotiation states more often than
        /// pure random bytes would.
        #[test]
        fn telnet_token_soup_never_panics(idx in prop::collection::vec(0..TELNET_VOCAB.len(), 0..200)) {
            let mut bytes = Vec::new();
            for i in idx {
                bytes.extend_from_slice(TELNET_VOCAB[i]);
            }
            let mut codec = TelnetCodec::new(256, 1000, 1000.0, Vec::new());
            let _ = codec.start();
            let _ = codec.feed(&bytes);
        }
    }

    const TELNET_VOCAB: &[&[u8]] = &[
        &[IAC],
        &[DO],
        &[DONT],
        &[WILL],
        &[WONT],
        &[SB],
        &[SE],
        &[telnet::OPT_NAWS],
        &[telnet::OPT_TTYPE],
        &[telnet::OPT_MSSP],
        &[telnet::OPT_GMCP],
        &[telnet::OPT_MCCP2],
        &[0],
        &[1],
        b"\r",
        b"\n",
        b"Core.Hello ",
        b"Char.Foo ",
        b"{}",
        b"{\"a\":1}",
        b"line",
    ];

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_gmcp_over_the_wire_is_gated_on_negotiation() {
        // Condition 3 (CTO review, OBI-26), end to end: a `SendGmcp`
        // issued before the client has agreed to `DO GMCP` must produce no
        // bytes on the wire at all; one issued after negotiation completes
        // must produce the encoded frame.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = NetConfig::default();
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server = tokio::spawn(run_server(listener, config, event_tx, cmd_rx, shutdown_rx));

        let mut client = TcpStream::connect(addr).await.unwrap();
        drain_preamble(&mut client).await;

        let conn = loop {
            match event_rx.recv().await.expect("event channel closed") {
                NetEvent::Connected(id) => break id,
                _ => continue,
            }
        };

        // Before negotiation: SendGmcp must be dropped, not written.
        cmd_tx
            .send(NetCommand::SendGmcp(
                conn,
                "Char.Foo".to_string(),
                serde_json::json!({"x": 1}),
            ))
            .await
            .unwrap();

        // Prove "no bytes" by racing the drop against something that *does*
        // produce bytes: send a line and read its echo-free response
        // ourselves isn't available here (no echo task), so instead confirm
        // no data arrives within a short window, then complete negotiation
        // and confirm the second SendGmcp *does* arrive.
        client.write_all(b"unrelated line\r\n").await.unwrap(); // keeps the connection alive; not read by anything in this test
        let mut probe = [0_u8; 1];
        let timed_out = tokio::time::timeout(
            std::time::Duration::from_millis(150),
            client.read(&mut probe),
        )
        .await
        .is_err();
        assert!(
            timed_out,
            "SendGmcp before negotiation must not put any bytes on the wire"
        );

        // Complete GMCP negotiation: client agrees to DO GMCP.
        client
            .write_all(&[IAC, DO, telnet::OPT_GMCP])
            .await
            .unwrap();
        // Give the server a moment to process the negotiation frame.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        cmd_tx
            .send(NetCommand::SendGmcp(
                conn,
                "Char.Foo".to_string(),
                serde_json::json!({"x": 1}),
            ))
            .await
            .unwrap();

        let expected = encode_gmcp("Char.Foo", &serde_json::json!({"x": 1}));
        let mut buf = vec![0_u8; expected.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_exact(&mut buf),
        )
        .await
        .expect("timed out waiting for the post-negotiation GMCP frame")
        .unwrap();
        assert_eq!(buf, expected);

        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn echo_integration_server_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = NetConfig::default();
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server = tokio::spawn(run_server(listener, config, event_tx, cmd_rx, shutdown_rx));

        let echo = tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                if let NetEvent::Line(conn, line) = event {
                    let _ = cmd_tx
                        .send(NetCommand::Send(conn, format!("{line}\n")))
                        .await;
                }
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        drain_preamble(&mut client).await;
        client.write_all(b"hello\r\n").await.unwrap();

        let mut buf = [0_u8; 32];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello\r\n");

        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
        echo.abort();
    }

    /// OBI-176 acceptance: "test with a raw telnet client transcript".
    /// `NetCommand::SetEcho` sent around a line of input must put `IAC
    /// WILL ECHO` on the wire before the no-echo prompt and `IAC WONT
    /// ECHO` after the input line comes back, with the prompt/line text
    /// untouched either side -- a raw socket never speaks telnet back, so
    /// this is read byte-for-byte rather than through a telnet-aware
    /// client library.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn set_echo_puts_will_then_wont_echo_on_the_wire() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = NetConfig::default();
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server = tokio::spawn(run_server(listener, config, event_tx, cmd_rx, shutdown_rx));

        // Stands in for /secure/login.wf: on the connection's first line
        // (the account name) turn echo off and send a "Password:" prompt;
        // on the second line (the password) turn echo back on.
        let driver = tokio::spawn(async move {
            let mut turn = 0;
            while let Some(event) = event_rx.recv().await {
                if let NetEvent::Line(conn, _line) = event {
                    turn += 1;
                    if turn == 1 {
                        let _ = cmd_tx.send(NetCommand::SetEcho(conn, false)).await;
                        let _ = cmd_tx
                            .send(NetCommand::Send(conn, "Password: ".to_string()))
                            .await;
                    } else {
                        let _ = cmd_tx.send(NetCommand::SetEcho(conn, true)).await;
                        let _ = cmd_tx
                            .send(NetCommand::Send(conn, "Welcome.\n".to_string()))
                            .await;
                    }
                }
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        drain_preamble(&mut client).await;

        // OBI-222: `SetEcho` and `Send` are two separate `ConnCommand`s
        // that `run_connection` writes to the socket with two separate
        // `write_all` calls; the IAC bytes and the prompt text are *not*
        // guaranteed to land in the same TCP read on the client side --
        // under scheduling pressure (observed on the self-hosted CI
        // runner pool) the connection task can be preempted between the
        // two writes, so a single `client.read()` can return just the
        // IAC sequence. Read exactly the expected number of bytes
        // (looping internally via `read_exact`, same pattern as
        // `drain_preamble` above) instead of asserting both writes
        // coalesce into one `read()`.
        client.write_all(b"legolas\r\n").await.unwrap();
        let expected = [&[IAC, WILL, telnet::OPT_ECHO][..], b"Password: "].concat();
        let mut buf = vec![0_u8; expected.len()];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(
            buf, expected,
            "expected IAC WILL ECHO immediately before the password prompt"
        );

        client.write_all(b"hunter2\r\n").await.unwrap();
        let expected = [&[IAC, WONT, telnet::OPT_ECHO][..], b"Welcome.\r\n"].concat();
        let mut buf = vec![0_u8; expected.len()];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(
            buf, expected,
            "expected IAC WONT ECHO immediately after the password line"
        );

        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
        driver.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn supports_fifty_concurrent_clients() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = NetConfig::default();
        let (event_tx, mut event_rx) = mpsc::channel(1024);
        let (cmd_tx, cmd_rx) = mpsc::channel(1024);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server = tokio::spawn(run_server(listener, config, event_tx, cmd_rx, shutdown_rx));

        let echo = tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                if let NetEvent::Line(conn, line) = event {
                    let _ = cmd_tx
                        .send(NetCommand::Send(conn, format!("{line}\n")))
                        .await;
                }
            }
        });

        let mut clients = Vec::new();
        for _ in 0..50 {
            clients.push(TcpStream::connect(addr).await.unwrap());
        }

        for client in clients.iter_mut() {
            drain_preamble(client).await;
        }

        for (idx, client) in clients.iter_mut().enumerate() {
            client
                .write_all(format!("player-{idx}\n").as_bytes())
                .await
                .unwrap();
        }

        for (idx, client) in clients.iter_mut().enumerate() {
            let mut buf = [0_u8; 64];
            let n = client.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], format!("player-{idx}\r\n").as_bytes());
        }

        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
        echo.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_client_disconnect_does_not_affect_others() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = NetConfig {
            output_queue_depth: 1,
            ..NetConfig::default()
        };

        let (event_tx, mut event_rx) = mpsc::channel(256);
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server = tokio::spawn(run_server(listener, config, event_tx, cmd_rx, shutdown_rx));

        let mut slow = TcpStream::connect(addr).await.unwrap();
        let mut fast = TcpStream::connect(addr).await.unwrap();
        drain_preamble(&mut slow).await;
        drain_preamble(&mut fast).await;
        slow.write_all(b"slow\n").await.unwrap();
        fast.write_all(b"fast\n").await.unwrap();

        let mut slow_conn = None;
        let mut saw_slow_disconnect = false;
        let mut replied_fast = false;

        // Identify the clients by the line they sent, not by accept order:
        // the two connects race, and guessing wrong spams the client that
        // is never read from while the test waits forever (flake seen in CI).
        // Also keep going until the fast client got its reply: its line can
        // arrive after the slow client has already been dropped.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while !(saw_slow_disconnect && replied_fast) {
            let event = tokio::time::timeout_at(deadline, event_rx.recv())
                .await
                .expect("timed out waiting for the slow-client disconnect and the fast-client line")
                .expect("event channel closed");
            match event {
                NetEvent::Connected(_) => {}
                NetEvent::Line(id, line) => {
                    if line == "slow" {
                        slow_conn = Some(id);
                        for i in 0..200 {
                            let _ = cmd_tx
                                .send(NetCommand::Send(id, format!("spam-{i}\n")))
                                .await;
                        }
                    } else if line == "fast" {
                        let _ = cmd_tx.send(NetCommand::Send(id, "ok\n".to_string())).await;
                        replied_fast = true;
                    }
                }
                NetEvent::Disconnected(id) => {
                    if Some(id) == slow_conn {
                        saw_slow_disconnect = true;
                    }
                }
                NetEvent::Tick => {}
                NetEvent::WindowSize(..) | NetEvent::TerminalType(..) | NetEvent::Gmcp(..) => {}
            }
        }

        assert!(saw_slow_disconnect, "slow client never disconnected");

        let mut fast_buf = [0_u8; 32];
        let n = fast.read(&mut fast_buf).await.unwrap();
        assert_eq!(&fast_buf[..n], b"ok\r\n");

        let _ = slow.readable().await;

        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }

    /// Copyover, new-process side (OBI-221): a connection pushed through
    /// `run_server_full`'s `adopt_rx` under a caller-chosen `ConnId`
    /// (standing in for one `loom-supervise::fdpass` handed over as a raw
    /// fd, already converted to a `TcpStream` by the copyover driver --
    /// see `run_server_full`'s doc comment for why that conversion isn't
    /// this crate's job) is immediately live and reachable under *that*
    /// id, not an auto-incremented one -- every `NetCommand` keyed by it
    /// reaches the right socket. Deliberately does **not** wait for a
    /// `NetEvent::Connected` (CTO review, OBI-266/B1: an adopted
    /// connection must never fire one at all -- see the dedicated
    /// `adopted_connection_never_emits_a_connected_event` test and
    /// `adopt_rx`'s own arm comment in `run_server_full` for why).
    /// Retries the first `NetCommand::Send` briefly: nothing here signals
    /// "the connection is registered and its task has started", so a
    /// send immediately after `adopt_tx.send` can legitimately race the
    /// task spawn by a few scheduler ticks.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn adopted_connection_is_keyed_by_the_caller_chosen_conn_id() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _addr = listener.local_addr().unwrap();

        let config = NetConfig::default();
        let (event_tx, _event_rx) = mpsc::channel(256);
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (_ws_tx, ws_rx) = mpsc::channel(1);
        let (adopt_tx, adopt_rx) = mpsc::channel(4);
        let (_reclaim_tx, reclaim_rx) = mpsc::channel(4);

        let server = tokio::spawn(run_server_full(
            listener,
            config,
            event_tx,
            cmd_rx,
            shutdown_rx,
            ws_rx,
            adopt_rx,
            reclaim_rx,
        ));

        // Stand in for "a socket some other listener (pre-copyover) already
        // accepted, and the supervisor handed this process as a raw fd":
        // a plain TCP connection to a throwaway listener, nothing to do
        // with `run_server_full`'s own listener above.
        let stub_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stub_addr = stub_listener.local_addr().unwrap();
        let mut client = TcpStream::connect(stub_addr).await.unwrap();
        let (server_side, _peer) = stub_listener.accept().unwrap();
        server_side.set_nonblocking(true).unwrap();

        const RECONNECTED_ID: ConnId = 4242;
        adopt_tx
            .send((RECONNECTED_ID, TcpStream::from_std(server_side).unwrap()))
            .await
            .unwrap();

        // The adopted session is a real, live `loom-net` connection:
        // `NetCommand::Send` keyed by its id reaches `client`'s socket.
        // Retried briefly (no `Connected` event to wait on anymore, see
        // this test's own doc comment) -- `try_send` on a not-yet-
        // registered id is simply dropped by `run_server_full` (there is
        // no entry in `conns` yet), not an error, so this polls until it
        // lands.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        drain_preamble(&mut client).await;
        let mut buf = [0_u8; 8];
        loop {
            let _ = cmd_tx
                .send(NetCommand::Send(RECONNECTED_ID, "hi\n".to_string()))
                .await;
            match tokio::time::timeout(std::time::Duration::from_millis(100), client.read(&mut buf))
                .await
            {
                Ok(Ok(n)) if n > 0 => {
                    assert_eq!(&buf[..n], b"hi\r\n");
                    break;
                }
                _ if tokio::time::Instant::now() >= deadline => {
                    panic!("adopted connection never became reachable via NetCommand::Send")
                }
                _ => continue,
            }
        }

        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }

    /// CTO review (OBI-266/B1): the actual regression this guards
    /// against -- `run_server_full` firing `NetEvent::Connected` for an
    /// adopted connection drives `World::connect`, which unconditionally
    /// calls master `connect()` and binds a *fresh* player to that
    /// `ConnId`, orphaning whatever object a restored snapshot (or a
    /// same-process reclaim/readopt round trip) already bound there --
    /// no `net_dead`, no autosave, every player effectively logged out
    /// and replaced on every adoption. Proves the absence directly:
    /// adopt a connection, then confirm no `NetEvent::Connected` for its
    /// id arrives in a generous window, while other event traffic
    /// (a `Line` from real client input) still flows normally.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn adopted_connection_never_emits_a_connected_event() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _addr = listener.local_addr().unwrap();

        let config = NetConfig::default();
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let (_cmd_tx, cmd_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (_ws_tx, ws_rx) = mpsc::channel(1);
        let (adopt_tx, adopt_rx) = mpsc::channel(4);
        let (_reclaim_tx, reclaim_rx) = mpsc::channel(4);

        let server = tokio::spawn(run_server_full(
            listener,
            config,
            event_tx,
            cmd_rx,
            shutdown_rx,
            ws_rx,
            adopt_rx,
            reclaim_rx,
        ));

        let stub_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stub_addr = stub_listener.local_addr().unwrap();
        let mut client = TcpStream::connect(stub_addr).await.unwrap();
        let (server_side, _peer) = stub_listener.accept().unwrap();
        server_side.set_nonblocking(true).unwrap();

        const RECONNECTED_ID: ConnId = 4343;
        adopt_tx
            .send((RECONNECTED_ID, TcpStream::from_std(server_side).unwrap()))
            .await
            .unwrap();

        // Real client input still flows (proving the connection is
        // genuinely live and the event loop is running, not just
        // silent), while we watch for the one event that must never
        // appear.
        drain_preamble(&mut client).await;
        client.write_all(b"hello\r\n").await.unwrap();

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(500);
        let mut saw_line = false;
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(50), event_rx.recv()).await
            {
                Ok(Some(NetEvent::Connected(id))) if id == RECONNECTED_ID => panic!(
                    "adopted connection must never emit NetEvent::Connected (CTO review, OBI-266/B1)"
                ),
                Ok(Some(NetEvent::Line(id, _))) if id == RECONNECTED_ID => saw_line = true,
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => {}
            }
        }
        assert!(
            saw_line,
            "never saw the adopted connection's own input -- the connection wasn't actually live, so the absence of Connected proves nothing"
        );

        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }

    /// Copyover, old-process side (OBI-184): a live connection, reclaimed
    /// via `reclaim_rx`, comes back as a real, usable `TcpStream` -- and
    /// the world never sees a spurious `NetEvent::Disconnected` for it
    /// (reclaiming is a hand-off, not a close; a real `net_dead()` call
    /// on the bound object would be wrong here).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reclaimed_connection_is_a_live_stream_with_no_disconnect_event() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = NetConfig::default();
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let (_cmd_tx, cmd_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (_ws_tx, ws_rx) = mpsc::channel(1);
        let (_adopt_tx, adopt_rx) = mpsc::channel(1);
        let (reclaim_tx, reclaim_rx) = mpsc::channel(4);

        let server = tokio::spawn(run_server_full(
            listener,
            config,
            event_tx,
            cmd_rx,
            shutdown_rx,
            ws_rx,
            adopt_rx,
            reclaim_rx,
        ));

        let mut client = TcpStream::connect(addr).await.unwrap();
        let conn = loop {
            match event_rx.recv().await.expect("event channel closed") {
                NetEvent::Connected(id) => break id,
                _ => continue,
            }
        };
        drain_preamble(&mut client).await;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        reclaim_tx.send((conn, reply_tx)).await.unwrap();
        let mut reclaimed = reply_rx
            .await
            .expect("reclaim reply channel dropped")
            .expect("reclaim should succeed for a live connection");

        // The reclaimed stream is live and independent of `client`: write
        // through it and read on the client side.
        reclaimed.write_all(b"hi from reclaimed\n").await.unwrap();
        let mut buf = [0_u8; 32];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hi from reclaimed\n");

        // No spurious disconnect: the next event (if any arrives before
        // shutdown) must not be `Disconnected(conn)`.
        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
        while let Ok(ev) = event_rx.try_recv() {
            if let NetEvent::Disconnected(id) = ev {
                assert_ne!(
                    id, conn,
                    "reclaimed connection must not also fire Disconnected"
                );
            }
        }
    }

    /// Copyover, old-process side (OBI-184): reclaiming a `ConnId` that
    /// isn't (or is no longer) live must answer `None` promptly, not hang
    /// the caller's `oneshot::Receiver::await` -- this is the "connection
    /// task had already exited on its own" path reviewed in OBI-227.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reclaiming_an_unknown_conn_id_answers_none() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let config = NetConfig::default();
        let (event_tx, _event_rx) = mpsc::channel(256);
        let (_cmd_tx, cmd_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (_ws_tx, ws_rx) = mpsc::channel(1);
        let (_adopt_tx, adopt_rx) = mpsc::channel(1);
        let (reclaim_tx, reclaim_rx) = mpsc::channel(4);

        let server = tokio::spawn(run_server_full(
            listener,
            config,
            event_tx,
            cmd_rx,
            shutdown_rx,
            ws_rx,
            adopt_rx,
            reclaim_rx,
        ));

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        reclaim_tx.send((99999, reply_tx)).await.unwrap();
        let reclaimed = tokio::time::timeout(std::time::Duration::from_secs(5), reply_rx)
            .await
            .expect("reclaim of an unknown conn id must answer promptly, not hang")
            .expect("reclaim reply channel dropped");
        assert!(
            reclaimed.is_none(),
            "reclaiming an unknown conn id must answer None"
        );

        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }

    /// OBI-304, window 1: output the world had **already queued** for a
    /// session must reach the socket *before* the reclaim hands the fd
    /// back, not be dropped because `run_server_full`'s unbiased select
    /// happened to poll `reclaim_rx` before `command_rx`.
    ///
    /// This is the exact shape of the OBI-292/OBI-304 flake: master
    /// `logon()` sends `Welcome to Loom!` and then the room description
    /// as two separate `NetCommand::Send`s, and a copyover request that
    /// lands in between used to tear the session's `ConnEntry` out of
    /// `conns` while the second one was still sitting in `command_rx` --
    /// the command arm then found no entry and silently dropped the
    /// player's room description. Design §7.5 promises no lost output, so
    /// this asserts the guarantee directly, without a supervisor or a
    /// real world in the loop.
    ///
    /// 32 queued lines (not 1) because the race is a `tokio::select!`
    /// coin-flip per iteration -- `command_rx` and `reclaim_rx` are both
    /// ready, so whichever wins decides the split point of the burst.
    /// Every line the reclaim wins past used to be dropped outright; in
    /// 3/3 pre-fix runs of this test the reclaim won the very first flip
    /// and *all 32* lines were lost ("socket went quiet after [], wanted
    /// 32 lines"), which is what the OBI-292 bot saw as a mid-intro
    /// hang: the welcome made it, the room description did not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reclaim_flushes_output_already_queued_for_the_session() {
        const QUEUED_LINES: usize = 32;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = NetConfig::default();
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (_ws_tx, ws_rx) = mpsc::channel(1);
        let (_adopt_tx, adopt_rx) = mpsc::channel(4);
        let (reclaim_tx, reclaim_rx) = mpsc::channel(4);

        let server = tokio::spawn(run_server_full(
            listener,
            config,
            event_tx,
            cmd_rx,
            shutdown_rx,
            ws_rx,
            adopt_rx,
            reclaim_rx,
        ));

        let mut client = TcpStream::connect(addr).await.unwrap();
        let conn = loop {
            match event_rx.recv().await.expect("event channel closed") {
                NetEvent::Connected(id) => break id,
                _ => continue,
            }
        };
        drain_preamble(&mut client).await;

        // Everything the world emitted before it asked for the fd back --
        // the `logon()`-style "welcome, then room description" burst. The
        // client is deliberately *not* read in between, so all of it is
        // still in flight (in `command_rx`, or in the per-connection
        // control queue, or in the kernel send buffer) when the reclaim
        // is issued.
        for idx in 0..QUEUED_LINES {
            cmd_tx
                .send(NetCommand::Send(conn, format!("queued-{idx}\n")))
                .await
                .unwrap();
        }
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        reclaim_tx.send((conn, reply_tx)).await.unwrap();
        let reclaimed = reply_rx
            .await
            .expect("reclaim reply channel dropped")
            .expect("reclaim should succeed for a live connection");

        // Read *before* anything is re-adopted: the queued output was
        // written to the socket, so it must already be there -- the fd
        // hand-off carries the kernel send buffer with it.
        let got = read_lines(&mut client, QUEUED_LINES).await;
        let expected: Vec<String> = (0..QUEUED_LINES)
            .map(|idx| format!("queued-{idx}\r\n"))
            .collect();
        assert_eq!(
            got, expected,
            "a reclaim must not drop output already queued for the session"
        );

        // And the round trip really is a round trip: the fd still works.
        drop(reclaimed);
        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }

    /// OBI-304, window 2: output enqueued for a session *between* the
    /// reclaim and the readopt (the world is not frozen during
    /// `loom serve`'s rehearsal round trip, and in a real copyover the
    /// pause between "fd gone" and "fd back" is exactly where a
    /// `call_out`/heartbeat reply can land) must be buffered and
    /// delivered once the connection is adopted -- not dropped because
    /// the id had no `ConnEntry` for a few milliseconds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn readopt_delivers_output_queued_during_the_handoff_window() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = NetConfig::default();
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (_ws_tx, ws_rx) = mpsc::channel(1);
        let (adopt_tx, adopt_rx) = mpsc::channel(4);
        let (reclaim_tx, reclaim_rx) = mpsc::channel(4);

        let server = tokio::spawn(run_server_full(
            listener,
            config,
            event_tx,
            cmd_rx,
            shutdown_rx,
            ws_rx,
            adopt_rx,
            reclaim_rx,
        ));

        let mut client = TcpStream::connect(addr).await.unwrap();
        let conn = loop {
            match event_rx.recv().await.expect("event channel closed") {
                NetEvent::Connected(id) => break id,
                _ => continue,
            }
        };
        drain_preamble(&mut client).await;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        reclaim_tx.send((conn, reply_tx)).await.unwrap();
        let reclaimed = reply_rx
            .await
            .expect("reclaim reply channel dropped")
            .expect("reclaim should succeed for a live connection");

        // The handoff window: the world is still running and emits for
        // this session. `conns` no longer has an entry for `conn`, so
        // before OBI-304 both of these were silently dropped.
        cmd_tx
            .send(NetCommand::Send(conn, "during-handoff-1\n".to_string()))
            .await
            .unwrap();
        cmd_tx
            .send(NetCommand::Send(conn, "during-handoff-2\n".to_string()))
            .await
            .unwrap();
        // Give `run_server_full` a chance to actually process both (it
        // would drop them here rather than later, so this makes the test
        // fail for the right reason instead of passing by luck).
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        adopt_tx.send((conn, reclaimed)).await.unwrap();

        // A re-adopted connection always starts with a fresh negotiation
        // preamble (the codec state reset documented since OBI-227), then
        // whatever was parked for it, in order.
        drain_preamble(&mut client).await;
        let got = read_lines(&mut client, 2).await;
        assert_eq!(
            got,
            vec!["during-handoff-1\r\n", "during-handoff-2\r\n"],
            "output queued between reclaim and adopt must be replayed on adoption"
        );

        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }

    /// Read exactly `want` `\n`-terminated lines from `client`, failing
    /// (not hanging) if the socket goes quiet first.
    async fn read_lines(client: &mut TcpStream, want: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut pending = Vec::new();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while out.len() < want {
            if tokio::time::Instant::now() >= deadline {
                panic!("timed out after {out:?}, wanted {want} lines");
            }
            let mut buf = [0_u8; 512];
            let n = tokio::time::timeout_at(deadline, client.read(&mut buf))
                .await
                .unwrap_or_else(|_| {
                    panic!("read_lines: socket went quiet after {out:?}, wanted {want} lines")
                })
                .expect("client socket read failed");
            pending.extend_from_slice(&buf[..n]);
            while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = pending.drain(..=pos).collect();
                out.push(String::from_utf8_lossy(&line).into_owned());
            }
        }
        out
    }
}
