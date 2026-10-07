// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-85 acceptance criterion: "in-memory backend. Create -> account_result
//! (ok), duplicate -> exists, wrong password -> bad_credentials. The world
//! thread is never blocked by hashing (show it: another connection's input
//! is processed while a login is pending)." Exercised end to end against a
//! real `loom-cli serve` subprocess with `DATABASE_URL` unset, so it runs
//! the in-memory dev account backend CI/the load bot use -- which is now
//! `loom_testing`'s default for a `serve` spawn (OBI-151/OBI-305), not
//! something this file has to remember.

use std::time::Duration;

use loom_testing::{Spawn, poll_until_contains, read_until_contains, send_line};

/// These tests assert on *promptness* (a pending hash must not stall another
/// connection), so the socket read timeout stays short and each wait is bounded
/// by its own needle timeout.
const READ_TIMEOUT: Duration = Duration::from_millis(200);

/// The nudge `poll_until_contains` re-sends while waiting for an async account
/// result, standing in for `NetEvent::Tick` (OBI-82).
const NUDGE: &str = "look";

#[test]
fn in_memory_account_backend_create_duplicate_and_bad_password() {
    let mudlib = loom_testing::fixture(env!("CARGO_MANIFEST_DIR"), "accounts");
    let mut server = Spawn::serve(&mudlib).start();
    let mut a = server.session().into_reader(READ_TIMEOUT);
    read_until_contains(&mut a, "Welcome.", Duration::from_secs(5));

    send_line(&mut a, "create legolas hunter2pass");
    let out = read_until_contains(&mut a, "req ", Duration::from_secs(2));
    assert!(out.contains("req 1\n"), "{out}");
    let out = poll_until_contains(&mut a, "result 1 ", Duration::from_secs(2), Some(NUDGE));
    assert!(
        out.contains("result 1 true "),
        "expected a successful create: {out}"
    );

    send_line(&mut a, "create legolas hunter2pass");
    let out = poll_until_contains(&mut a, "result 2 ", Duration::from_secs(2), Some(NUDGE));
    assert!(
        out.contains("result 2 false exists"),
        "duplicate account must be rejected as `exists`: {out}"
    );

    send_line(&mut a, "login legolas wrong-password");
    let out = poll_until_contains(&mut a, "result 3 ", Duration::from_secs(2), Some(NUDGE));
    assert!(
        out.contains("result 3 false bad_credentials"),
        "wrong password must be `bad_credentials`: {out}"
    );

    send_line(&mut a, "login legolas hunter2pass");
    let out = poll_until_contains(&mut a, "result 4 ", Duration::from_secs(2), Some(NUDGE));
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
    let mudlib = loom_testing::fixture(env!("CARGO_MANIFEST_DIR"), "accounts");
    let mut server = Spawn::serve(&mudlib).start();
    let mut a = server.session().into_reader(READ_TIMEOUT);
    read_until_contains(&mut a, "Welcome.", Duration::from_secs(5));

    // A second connection: `serve` mode hands the readiness barrier's own
    // connection to the first session, and every session after that is a fresh
    // connection with its own startup negotiation drained (design §8.2).
    let mut b = server.session().into_reader(READ_TIMEOUT);
    read_until_contains(&mut b, "Welcome.", Duration::from_secs(5));

    // Pipeline several account_create requests on `a` without waiting for
    // any reply in between -- each one queues real Argon2 hashing work.
    for i in 0..10 {
        send_line(&mut a, &format!("create player{i} hunter2password"));
    }

    // `b`'s completely unrelated command must still be answered quickly:
    // the world thread only ever does a bounded-channel send to issue
    // account_create, never the hash itself.
    let started = std::time::Instant::now();
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
