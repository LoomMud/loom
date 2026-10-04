// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-235/OBI-237 (`GET /api/v1/admin/errors`, world-thread side):
//! `World::admin_errors` reuses the OBI-169 error inbox's grouping, the
//! same per-program `valid_read` filter, and the same M-ERR-1 `/secure`
//! redaction rule as the `errors` efun (`tests/obi_169_error_inbox.rs`),
//! just invoked for an HTTP admin caller (a `caller_tier` passed in
//! directly, no in-game euid/roles-snapshot plumbing needed) instead of
//! an in-game one.

mod common;

use common::{FakeHost, fixture, on_world_thread};
use loom_vm::World;

#[test]
fn admin_errors_omits_programs_the_caller_cannot_valid_read() {
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

        // The Rust-side inbox (no permission filter) sees both groups.
        assert_eq!(world.errors_snapshot(None).len(), 2);

        // `admin_errors` for a non-root caller sees only the readable one
        // -- same filter the `errors` efun applies, not a stand-in.
        let groups = world.admin_errors("guest", 3, None, &mut host);
        assert_eq!(groups.len(), 1, "{groups:?}");
        assert_eq!(groups[0].program, "/std/player");
    });
}

#[test]
fn admin_errors_program_prefix_narrows_the_result() {
    on_world_thread(|| {
        let root = fixture("errors_inbox");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        world.input(1, "boom", &mut host);
        host.take(1);

        let narrowed = world.admin_errors("guest", 5, Some("/std/player"), &mut host);
        assert_eq!(narrowed.len(), 1);

        let empty = world.admin_errors("guest", 5, Some("/nowhere"), &mut host);
        assert!(empty.is_empty());
    });
}

/// Mirrors `tests/obi_169_error_inbox.rs`'s
/// `a_secure_origins_message_is_redacted_below_t5_and_shown_at_t5`, but
/// for the admin-query world-thread side: `caller_tier` is passed in
/// directly (the HTTP-authenticated staff tier), not derived from an
/// in-game euid/roles snapshot -- M-ERR-1's redaction rule is keyed on
/// that tier either way.
#[test]
fn admin_errors_redacts_a_secure_origins_message_below_t5_and_shows_it_at_t5() {
    on_world_thread(|| {
        let root = fixture("errors_inbox");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        // `/secure/vault2` is readable (unlike `/secure/leak`), isolating
        // the message-redaction rule from the program-visibility filter.
        world.input(1, "triggervault2", &mut host);
        host.take(1);

        let rows = world.errors_snapshot(None);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!(rows[0].redacted);
        assert_eq!(
            rows[0].message, "random(): n must be > 0",
            "the Rust-side inbox (no permission/redaction filter) always has the real text"
        );

        let below_t5 = world.admin_errors("guest", 4, None, &mut host);
        assert_eq!(below_t5.len(), 1);
        assert_eq!(below_t5[0].program, "/secure/vault2");
        assert!(below_t5[0].redacted);
        assert_eq!(below_t5[0].message, "<redacted>");

        let at_t5 = world.admin_errors("guest", 5, None, &mut host);
        assert_eq!(at_t5.len(), 1);
        assert!(at_t5[0].redacted, "the flag itself is unconditional");
        assert_eq!(at_t5[0].message, "random(): n must be > 0");
    });
}

/// CTO review (OBI-237 PR #102, must-fix B1): see
/// `tests/obi_237_admin_query.rs`'s identical test on `admin_list_objects`/
/// `admin_object_vars` for the full rationale -- `admin_errors` must
/// refuse a reserved driver principal (`root`, `mudlib`, `domain:*`) as
/// `caller_euid` too, not silently grant it root's unconditional
/// `valid_read` pass via an accidentally-empty guard.
#[test]
fn admin_errors_refuses_a_reserved_principal_as_caller_euid() {
    on_world_thread(|| {
        let root = fixture("errors_inbox");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        world.input(1, "boom", &mut host);
        host.take(1);
        assert_eq!(world.errors_snapshot(None).len(), 1);

        for reserved in ["root", "mudlib", "domain:shire"] {
            let groups = world.admin_errors(reserved, 5, None, &mut host);
            assert!(
                groups.is_empty(),
                "caller_euid={reserved:?} must not see anything, got {groups:?}"
            );
        }

        // Sanity: a non-reserved euid still sees the readable program.
        let as_guest = world.admin_errors("guest", 5, None, &mut host);
        assert_eq!(as_guest.len(), 1);
    });
}
