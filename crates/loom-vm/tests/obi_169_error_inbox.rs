// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-169 (grouped runtime errors / the `errors` efun /
//! `/api/v1/errors`): grouping, permission filtering, and the
//! `errors()` efun's shape, exercised end to end through [`World`].

mod common;

use common::{FakeHost, fixture, on_world_thread};
use loom_vm::World;

#[test]
fn repeated_runtime_errors_on_the_same_program_function_message_group_and_count() {
    on_world_thread(|| {
        let root = fixture("errors_inbox");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        world.input(1, "boom", &mut host);
        let first = host.take(1);
        assert!(
            first.contains("random(): n must be > 0"),
            "the raised error is reported to the player: {first}"
        );
        world.input(1, "boom", &mut host);
        host.take(1);

        let rows = world.errors_snapshot(None);
        assert_eq!(rows.len(), 1, "one group: same program/function/message");
        let row = &rows[0];
        assert_eq!(row.program, "/std/player");
        assert_eq!(row.message, "random(): n must be > 0");
        assert_eq!(row.count, 2);
        assert!(row.first_seen_unix_ms <= row.last_seen_unix_ms);
        assert!(
            !row.sample_trace.is_empty(),
            "a sample trace is captured, not just the message"
        );
    });
}

#[test]
fn a_different_message_on_the_same_program_is_a_different_group() {
    on_world_thread(|| {
        let root = fixture("errors_inbox");
        let limits = loom_vm::Limits {
            heartbeat_interval_ticks: 1,
            ..Default::default()
        };
        let mut world = World::boot_with_limits(&root, limits).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        // `boom` -> random(0) -> "random(): n must be > 0".
        world.input(1, "boom", &mut host);
        host.take(1);
        // An unknown verb goes through a different code path but is not
        // itself an error (the `else` branch sends "What?\n" rather than
        // raising) -- use the vault's heartbeat to get a second, distinct
        // program/message group instead.
        world.input(1, "spawnvault", &mut host);
        host.take(1);
        world.tick(&mut host);

        let rows = world.errors_snapshot(None);
        assert_eq!(
            rows.len(),
            2,
            "player's and vault's errors are distinct groups"
        );
        assert!(rows.iter().any(|r| r.program == "/std/player"));
        assert!(rows.iter().any(|r| r.program == "/std/vault"));
    });
}

#[test]
fn the_errors_efun_omits_programs_the_caller_cannot_valid_read() {
    on_world_thread(|| {
        let root = fixture("errors_inbox");
        let limits = loom_vm::Limits {
            heartbeat_interval_ticks: 1,
            ..Default::default()
        };
        let mut world = World::boot_with_limits(&root, limits).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        // The player's own error is visible...
        world.input(1, "boom", &mut host);
        host.take(1);
        // ...but the vault's is not: `secure/master.wf`'s `valid_read`
        // denies `/std/vault` specifically.
        world.input(1, "spawnvault", &mut host);
        host.take(1);
        world.tick(&mut host);

        // The Rust-side inbox (no permission filter) sees both groups...
        assert_eq!(world.errors_snapshot(None).len(), 2);

        // ...but the in-game `errors()` efun, filtered by the caller's
        // own `valid_read`, sees only the player's.
        world.input(1, "errorcount", &mut host);
        assert_eq!(host.take(1), "1\n");
    });
}

#[test]
fn the_errors_efun_prefix_filter_narrows_by_program() {
    on_world_thread(|| {
        let root = fixture("errors_inbox");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        world.input(1, "boom", &mut host);
        host.take(1);

        world.input(1, "errorcount /std/player", &mut host);
        assert_eq!(host.take(1), "1\n");

        world.input(1, "errorcount /nowhere", &mut host);
        assert_eq!(host.take(1), "0\n");
    });
}

/// CTO review (OBI-169, PR #72, must-fix 1): a `/std` object that calls
/// into a program it has no `valid_read` access to must not leak that
/// program's error under its own (readable) entry. Before the fix,
/// `note_error` attributed every error to the *entry* object's own
/// program (`acting`) regardless of which program actually raised it --
/// so `/std/player` calling into `/secure/leak` (denied by this
/// fixture's `valid_read`) would have recorded the error under
/// `/std/player`, which the caller can always read, leaking `/secure`
/// error text to it. After the fix, the entry is attributed to
/// `/secure/leak` itself, and the per-program `valid_read` filter the
/// `errors` efun already applies hides it from this caller entirely --
/// same as it already hides a denied program's *own* errors (the
/// `/std/vault` case above), just now also covering an error that
/// originated several frames deep inside a call chain the entry object
/// started.
#[test]
fn a_denied_programs_error_raised_through_a_call_chain_is_attributed_to_it_not_the_caller() {
    on_world_thread(|| {
        let root = fixture("errors_inbox");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        world.input(1, "triggerleak", &mut host);
        let reply = host.take(1);
        assert!(
            reply.contains("random(): n must be > 0"),
            "the error still propagates to the caller as a reported error: {reply}"
        );

        // The Rust-side inbox (no permission filter) attributes the
        // error to `/secure/leak`, the program that actually raised it --
        // never to `/std/player`, the entry object that merely called
        // into it.
        let rows = world.errors_snapshot(None);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].program, "/secure/leak");
        assert!(
            rows[0].redacted,
            "a /secure/** origin is always recorded redacted"
        );

        // The in-game `errors()` efun, filtered by the caller's own
        // `valid_read`, sees nothing at all: `/secure/leak` is denied,
        // and (unlike the pre-fix behaviour) there is no `/std/player`
        // entry for this error to hide behind.
        world.input(1, "errorcount", &mut host);
        assert_eq!(host.take(1), "0\n");
    });
}

/// CTO review (OBI-169, PR #72, must-fix 2): a `/secure/**` origin's
/// message is shown as `"<redacted>"` to anyone below T5, and as the
/// real text only to T5 -- independent of whether `valid_read` itself
/// allows the program (`/secure/vault2` does, unlike `/secure/leak`
/// above, so this isolates the message-redaction rule from the
/// program-visibility filter).
#[test]
fn a_secure_origins_message_is_redacted_below_t5_and_shown_at_t5() {
    on_world_thread(|| {
        let root = fixture("errors_inbox");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        world.input(1, "triggervault2", &mut host);
        host.take(1);

        let rows = world.errors_snapshot(None);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].program, "/secure/vault2");
        assert!(rows[0].redacted);
        assert_eq!(
            rows[0].message, "random(): n must be > 0",
            "the Rust-side inbox (no permission/redaction filter) always has the real text"
        );

        // Below T5 (this fixture's default, no roles snapshot at all):
        // the `errors` efun shows the flag but masks the message.
        world.input(1, "errormessage /secure/vault2", &mut host);
        assert_eq!(host.take(1), "<redacted>\n");

        // At T5 (`seteuid` to an account this fixture's roles snapshot
        // maps to tier 5, mirroring a real post-auth `seteuid`): the real
        // message is shown.
        world.set_roles_snapshot(std::sync::Arc::new(
            loom_vm::RolesSnapshot::from_seed_json(r#"{"staff": {"root-tester": 5}}"#)
                .expect("seed parses"),
        ));
        world.input(1, "become root-tester", &mut host);
        assert_eq!(host.take(1), "ok\n");
        world.input(1, "errormessage /secure/vault2", &mut host);
        assert_eq!(host.take(1), "random(): n must be > 0\n");
    });
}
