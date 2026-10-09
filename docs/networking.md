# loom-net wire contract (design §8.2)

Owner: Legolas. Normative text for what `loom-net` owes a connection it has already
accepted. The upstream source of truth is the Loom design specification v2, §8.2
("Networking & clients"); this file records the accept-path rule in the repo so the
rule ships with the code that keeps it.

## The accept path

**Contract (OBI-383, accepted by the CTO on OBI-388 §2):** once `loom-net` has taken a
connection out of the kernel's accept queue, it always writes the startup negotiation
offer — `IAC DO NAWS`, `IAC DO TTYPE`, `IAC WILL GMCP`, `IAC WILL MSSP` — *before* it
closes that connection, including when the world's event receiver is gone because the
world thread exited or a shutdown is in flight.

An accepted telnet connection is never answered with a zero-byte FIN. To a client that
is indistinguishable from a driver that hung up on the player, and in CI it is
unattributable: it was the shape of `supervise_handoff::version_file_change_is_detected_and_logged`
red-dening `main` as a bare `UnexpectedEof` in the 12-byte preamble drain, with nothing
in the transcript naming which process closed the socket.

Keeping the rule: `run_server_full`'s telnet arm calls `write_startup_offer` on the way
out, which reuses the same `TelnetCodec::start()` bytes a normal session's first flush
uses, then shuts the write half down. It logs at `warn` with `conn_id` and `peer_addr`,
and increments `loom_net_accept_after_world_gone_total`. The accept loop still stops —
there is nothing behind that channel to serve, so this is a courtesy on the way out, not
a protocol step the shutdown may block on (write errors are ignored deliberately: a peer
that already hung up cannot be made to receive anything). The loop is never re-entered.

Pinned by `accepted_connection_always_gets_the_startup_offer_even_if_the_world_is_gone`
(`crates/loom-net/src/lib.rs`), which reproduces the degenerate state by dropping the
event receiver while the listener is still accepting, and asserts the exact 12 bytes and
a clean close afterwards.

## Explicitly out of scope

The WebSocket accept arm keeps no equivalent contract: a browser client already reads a
socket that closes without frames as the normal "the server isn't there" signal and
reconnects, so a frameless close there is information rather than ambiguity. Rejected
alternatives, for the record: leaving the silent FIN (unattributable), sending a goodbye
text before close (new wire content for a degenerate state), and metric-only logging
(again unattributable from the client side).

## Spec provenance

One bullet, to be inserted in design spec v2 §8.2 immediately after the **Telnet** bullet
by that document's owner (the agent-side `PUT /api/issues/OBI-4/documents/design` is
refused with `Agent cannot mutate another agent's issue`):

> - **Accept-path contract (r6, OBI-383, CTO ruling on OBI-388):** once `loom-net` has
>   taken a connection out of the kernel's accept queue, it **always writes the startup
>   negotiation offer** (`IAC DO NAWS`, `IAC DO TTYPE`, `IAC WILL GMCP`, `IAC WILL MSSP`)
>   **before closing it** — including when the world's event receiver is gone because its
>   thread exited or a shutdown is in flight (that case is logged and counted as
>   `loom_net_accept_after_world_gone_total`, and the accept loop still stops). An
>   accepted telnet connection is never answered with a zero-byte FIN: to a client that is
>   indistinguishable from a driver that hung up on the player, and in CI it is
>   unattributable. WebSocket is deliberately outside this rule — a web client already
>   reads a frameless socket close as the normal "server isn't there" signal and
>   reconnects.
