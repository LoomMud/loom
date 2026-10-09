// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-360: the audit ring is bounded, so a sink that falls behind loses
//! rows -- and `World::drain_audit_since` must *say so* rather than let the
//! caller mistake "the ring overwrote them" for "nothing happened".
//!
//! CTO decision (2026-10-09, on OBI-354): never block the world thread and
//! never refuse eviction; make the gap visible and durable. These tests are
//! half (a) of that acceptance -- the reported evicted count, checked against
//! decisions this test counted itself. Halves (b) and (c), the
//! `loom_audit_rows_evicted_total` metric and the one `audit_gap` row, are
//! `loom-cli`'s `AuditHandoff` (`crates/loom-cli/src/main.rs`'s
//! `audit_handoff_tests`).
//!
//! Every decision here is a real master `valid_read` denial through
//! `World::call_file_efun`, so the ring arithmetic is exercised against the
//! entries `authorize` actually records. Each denial uses a distinct path, so
//! a surviving row names *which* decision it is and the gap can be checked
//! for contiguity, not just for a number.

mod common;

use common::{FakeHost, scratch};
use loom_vm::security::AUDIT_LOG_CAPACITY;
use loom_vm::{AuditRow, Value, World};

/// Refuse every path outside the caller's own workroom, so each
/// `call_file_efun` below is one audited denial.
const MASTER: &str = r#"
fn valid_efun(name: string, class: int, ob: object) -> bool {
    return true
}

fn valid_read(path: string, ob: object, op: string) -> bool {
    let parts = split(path, "/")
    return len(parts) >= 3 and parts[1] == "builders" and parts[2] == effective_principal()
}

fn valid_write(path: string, ob: object, op: string) -> bool {
    return valid_read(path, ob, op)
}
"#;

fn boot(tag: &str) -> (World, FakeHost, std::path::PathBuf) {
    let root = scratch(tag);
    let p = root.join("secure/master.wf");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, MASTER).unwrap();
    let world = World::boot(&root).expect("boot");
    (world, FakeHost::default(), root)
}

/// The path of decision `n`: distinct per decision, and refused for
/// `glorfindel` because it is not under `/builders/glorfindel/`.
fn path_of(n: u64) -> String {
    format!("/secure/gap-{n}.wf")
}

/// One audited privileged decision: a denied read of `path_of(n)`. Asserts it
/// recorded exactly one audit entry, which is what lets the tests below count
/// rows instead of estimating them.
fn decision(world: &mut World, host: &mut FakeHost, n: u64) {
    let before = world.security().audit_total();
    let err = world
        .call_file_efun(
            "glorfindel",
            "read_file",
            vec![Value::str(&path_of(n))],
            host,
        )
        .expect_err("/secure is outside the caller's workroom");
    assert!(err.contains("permission denied"), "{err}");
    assert_eq!(
        world.security().audit_total(),
        before + 1,
        "one denied file efun must record exactly one audit entry, or the \
         counts below are arithmetic on the wrong basis"
    );
}

/// Record `count` decisions, numbered from `first`.
fn decisions(world: &mut World, host: &mut FakeHost, first: u64, count: u64) {
    for n in first..first + count {
        decision(world, host, n);
    }
}

/// The numbers in a drained batch's `argument`s, oldest first.
fn gap_numbers(rows: &[AuditRow]) -> Vec<u64> {
    rows.iter()
        .map(|r| {
            r.argument
                .rsplit('-')
                .next()
                .and_then(|s| s.strip_suffix(".wf").or(Some(s)))
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or_else(|| panic!("row argument is not a gap path: {:?}", r.argument))
        })
        .collect()
}

/// The gap is measured from *the caller's* cursor, not from "the ring
/// wrapped": a flush that keeps up reports nothing, however many times the
/// ring has turned over underneath it -- and rows it already took are never
/// counted as lost.
#[test]
fn a_cursor_that_keeps_up_reports_no_gap_however_the_ring_wraps() {
    let (mut world, mut host, _root) = boot("audit-gap-keeping-up");
    let boot = world.drain_audit_since(0);
    assert_eq!(
        boot.evicted, 0,
        "boot itself must not have overflowed the ring"
    );
    let mut cursor = boot.cursor;

    // Well past one full ring, draining every round.
    for n in 0..(2 * AUDIT_LOG_CAPACITY as u64 + 40) {
        decision(&mut world, &mut host, n);
        let drain = world.drain_audit_since(cursor);
        assert_eq!(
            drain.evicted, 0,
            "a sink at the ring's edge must not be told it lost rows (after {n} decisions)"
        );
        assert_eq!(
            gap_numbers(&drain.rows),
            vec![n],
            "exactly the one decision since the last drain"
        );
        cursor = drain.cursor;
        assert_eq!(cursor, world.security().audit_total());
    }
}

/// The OBI-360 acceptance case, at the ring: record more decisions than the
/// ring can hold with no reader, then drain from a cursor the ring has left
/// behind. Exactly the decisions between that cursor and the oldest surviving
/// row are reported as evicted -- no more, no fewer, and the survivors are
/// contiguous.
#[test]
fn a_ring_that_wrapped_reports_every_row_it_overshadowed() {
    let (mut world, mut host, _root) = boot("audit-gap-wrapped");

    // Take everything the ring holds so far and hold that cursor: this is the
    // handoff's "batch deferred because the sink queue is full" state, with
    // the world still recording behind it.
    let held = world.drain_audit_since(0);
    assert_eq!(held.evicted, 0, "nothing is lost before the ring wraps");
    let cursor = held.cursor;

    // Overflow: a full ring plus a known surplus, none of it read.
    let surplus: u64 = 37;
    let recorded = AUDIT_LOG_CAPACITY as u64 + surplus;
    decisions(&mut world, &mut host, 0, recorded);
    let total = world.security().audit_total();
    assert_eq!(total, cursor + recorded, "one entry per decision");

    let drain = world.drain_audit_since(cursor);
    // (a) The count is exactly the surplus: what the ring can no longer
    // reach, and nothing that the cursor had already passed.
    assert_eq!(
        drain.evicted, surplus,
        "the drain must report the rows it can no longer return"
    );
    assert_eq!(
        drain.rows.len(),
        AUDIT_LOG_CAPACITY,
        "the whole retained window comes back, oldest first"
    );
    assert_eq!(drain.cursor, total);

    // The survivors are the *last* `AUDIT_LOG_CAPACITY` decisions, in order,
    // with no hole in them -- so the reported count is the real shortfall,
    // not a guess from an empty batch.
    let numbers = gap_numbers(&drain.rows);
    assert_eq!(
        numbers,
        (surplus..recorded).collect::<Vec<_>>(),
        "decisions 0..{surplus} are gone; {surplus}..{recorded} survive in order"
    );

    // The gap is reported *once*: from the new cursor the ring is whole
    // again, so `loom-cli`'s flush must not re-log, re-count, or re-write it.
    let after = world.drain_audit_since(drain.cursor);
    assert_eq!(after.evicted, 0, "a gap is not a standing condition");
    assert!(after.rows.is_empty());

    // A cursor from before boot reports the whole shortfall -- saturating
    // against the ring's own window, never negative, never short.
    let far = world.drain_audit_since(0);
    assert_eq!(far.evicted, far.cursor - far.rows.len() as u64);
    assert!(
        far.evicted >= surplus,
        "already-taken rows are not 'evicted', so this counts the ring's own wrap"
    );
    assert_eq!(far.rows.len(), AUDIT_LOG_CAPACITY);
}

/// The durable half of the record: the shape `loom-cli` writes into
/// `audit_log` when a drain reports `evicted > 0`. `kind`/`apply` name it,
/// `detail` carries the count, `argument` the lost sequence range, and the
/// verdict is `deny`, because the schema admits nothing else and a gap must
/// never read as an approved decision.
#[test]
fn the_gap_row_is_shaped_for_the_audit_log_table() {
    let row = AuditRow::audit_gap(17, 1_024, 1_041);
    assert_eq!(row.kind, loom_vm::AUDIT_GAP_KIND);
    assert_eq!(row.apply, loom_vm::AUDIT_GAP_KIND);
    assert_eq!(row.detail.as_deref(), Some("evicted=17"));
    assert_eq!(row.argument, "1024..1041");
    assert!(!row.allowed, "a gap is recorded as a deny, never an allow");
    assert_eq!(
        row.class, 0,
        "no privilege class applies to a driver record"
    );
    assert!(row.caller.is_none() && row.effective_principal.is_none());
    assert!(row.guard_set.is_empty());
    assert!(
        row.at_unix_ms > 1_700_000_000_000,
        "a gap is stamped when it was detected, its own decisions having no time to carry"
    );

    // The fields a reader needs to reconcile the ring, the cursor and the log
    // line are consistent by construction.
    let (from, to) = row.argument.split_once("..").expect("range is from..to");
    let (from, to) = (from.parse::<u64>().unwrap(), to.parse::<u64>().unwrap());
    assert_eq!(
        to - from,
        17,
        "`argument` spans exactly the `evicted` count"
    );
}
