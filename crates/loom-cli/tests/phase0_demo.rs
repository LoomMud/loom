// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 0 demo (OBI-14/OBI-21): walk two rooms, hot-update a room's
//! description in place, and show that neither the update nor a *failed*
//! update costs the connected player their session.
//!
//! Port allocation, the server's lifecycle, and the line-reading helpers all
//! come from `loom_testing` (OBI-305); the readiness barrier behind
//! [`Spawn::start`] is what guarantees this test is talking to a serving
//! process rather than retrying into one that may never bind.

use std::path::Path;
use std::time::Duration;

use loom_testing::{Spawn, read_until_contains, send_line};

const INTRO_EXITS: &str = "Obvious exits: north.";
const HALL_DESC: &str = "A high-ceilinged hall of pale stone.";
const GARDEN_DESC: &str = "Neat beds of herbs line a gravel path.";
const UPDATED_GARDEN_DESC: &str =
    "Fresh rain darkens the gravel path, and rosemary scent hangs in the still air.";

#[test]
fn phase0_exit_demo_walks_and_hot_updates_without_disconnect() {
    let mudlib = loom_testing::fixture(env!("CARGO_MANIFEST_DIR"), "warp-phase0");
    let mut server = Spawn::serve(&mudlib).start();
    // 200 ms per read: every wait here is bounded by the needle's own timeout
    // below, so a short socket timeout just means a stalled server is noticed
    // instead of hanging the test binary.
    let mut reader = server.session().into_reader(Duration::from_millis(200));

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
