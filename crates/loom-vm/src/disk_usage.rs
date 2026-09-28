// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-`<u>` disk byte counter for `disk_quota_mb` (OBI-137 S1, OBI-36
//! design note §3): `check_disk_quota` used to re-walk the whole
//! `/builders/<u>/**` tree (`fileio::dir_size_bytes`) on *every*
//! `write_file`, an `O(files)` cost per write. [`DiskUsage`] instead
//! seeds a `<u>`'s total with exactly one such walk, the first time `<u>`
//! is ever asked about, and then maintains it incrementally in `O(1)` on
//! every write/remove/rename -- [`DiskUsage::note_write`] always takes
//! the old size from `fileio::file_size_bytes` (`metadata().len()`),
//! never the old file's contents.

use std::collections::HashMap;
use std::path::Path;

/// Owned by `World`, one entry per `<u>` that has ever been asked about
/// (a builder who has never written under quota is never seeded, so an
/// idle mudlib with a thousand builders costs nothing here until one of
/// them actually gets a `disk_quota_mb` row and writes something).
#[derive(Default)]
pub struct DiskUsage {
    totals: HashMap<String, u64>,
}

impl DiskUsage {
    /// `<u>`'s current total, seeding it with one recursive walk of
    /// `/builders/<u>/**` the first time `<u>` is asked about (`root`/`u`
    /// are only ever touched on that one seed; every later call is a
    /// plain `HashMap` lookup, no filesystem access at all).
    pub fn seeded_total(&mut self, root: &Path, u: &str) -> u64 {
        *self.totals.entry(u.to_string()).or_insert_with(|| {
            crate::fileio::dir_size_bytes(root, &format!("/builders/{u}")).unwrap_or(0)
        })
    }

    /// Record a write that replaces a file which used to be `old_bytes`
    /// (0 for a brand new file) with one of `new_bytes`. Must only be
    /// called once the caller has committed to actually performing the
    /// write (a write rejected for being over quota must not touch the
    /// counter) -- and only after `<u>`'s total has been seeded via
    /// [`Self::seeded_total`] (this never seeds on its own: an
    /// unconditional `entry().or_insert(0)` here would silently treat an
    /// unseeded `<u>` as starting from zero instead of its real on-disk
    /// total).
    pub fn note_write(&mut self, u: &str, old_bytes: u64, new_bytes: u64) {
        if let Some(total) = self.totals.get_mut(u) {
            *total = total.saturating_sub(old_bytes).saturating_add(new_bytes);
        }
    }

    /// Record a file of `old_bytes` being removed from `<u>`'s tree.
    pub fn note_remove(&mut self, u: &str, old_bytes: u64) {
        if let Some(total) = self.totals.get_mut(u) {
            *total = total.saturating_sub(old_bytes);
        }
    }

    /// Record a rename moving a file of `bytes` out of `from_u`'s tree
    /// and into `to_u`'s (a no-op net delta if they are the same uid,
    /// but still routed through both `note_remove`/`note_write` so a
    /// rename *within* one uid's own tree, which does not change that
    /// uid's total, still only touches counters that were actually
    /// seeded).
    pub fn note_rename(&mut self, from_u: &str, to_u: &str, bytes: u64) {
        self.note_remove(from_u, bytes);
        self.note_write(to_u, 0, bytes);
    }

    #[cfg(test)]
    fn total_for(&self, u: &str) -> Option<u64> {
        self.totals.get(u).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_total_walks_the_directory_exactly_once() {
        let root =
            std::env::temp_dir().join(format!("loom-disk-usage-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        crate::fileio::write_file(&root, "/builders/appr/a.wf", "12345").unwrap();
        crate::fileio::write_file(&root, "/builders/appr/b.wf", "1234567890").unwrap();

        let mut usage = DiskUsage::default();
        assert_eq!(usage.seeded_total(&root, "appr"), 15);

        // A file appears on disk *after* the seed: `seeded_total` must
        // not re-walk and pick it up -- the whole point is "one walk,
        // then counters".
        crate::fileio::write_file(&root, "/builders/appr/c.wf", "x").unwrap();
        assert_eq!(
            usage.seeded_total(&root, "appr"),
            15,
            "no re-walk on a later call: the cached total is authoritative"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn note_write_tracks_new_files_overwrites_and_shrinks() {
        let mut usage = DiskUsage::default();
        // Seed manually (as if `seeded_total` had walked an empty tree).
        usage.totals.insert("appr".to_string(), 0);

        usage.note_write("appr", 0, 100); // new file, 100 bytes
        assert_eq!(usage.total_for("appr"), Some(100));

        usage.note_write("appr", 100, 40); // overwrite: shrink to 40 bytes
        assert_eq!(usage.total_for("appr"), Some(40));

        usage.note_write("appr", 40, 40); // overwrite with the same size
        assert_eq!(usage.total_for("appr"), Some(40));
    }

    #[test]
    fn note_remove_subtracts_and_never_underflows() {
        let mut usage = DiskUsage::default();
        usage.totals.insert("appr".to_string(), 50);
        usage.note_remove("appr", 30);
        assert_eq!(usage.total_for("appr"), Some(20));
        usage.note_remove("appr", 999); // more than remains: saturates at 0
        assert_eq!(usage.total_for("appr"), Some(0));
    }

    #[test]
    fn note_rename_moves_bytes_between_two_uids() {
        let mut usage = DiskUsage::default();
        usage.totals.insert("appr".to_string(), 100);
        usage.totals.insert("senior".to_string(), 0);
        usage.note_rename("appr", "senior", 30);
        assert_eq!(usage.total_for("appr"), Some(70));
        assert_eq!(usage.total_for("senior"), Some(30));
    }

    #[test]
    fn note_write_before_any_seed_is_a_no_op() {
        // The counter for a `<u>` that was never seeded must stay
        // unseeded (not silently spring into existence at whatever delta
        // a write happens to pass): the first real quota check always
        // seeds via `seeded_total` first.
        let mut usage = DiskUsage::default();
        usage.note_write("never-seeded", 0, 500);
        assert_eq!(usage.total_for("never-seeded"), None);
    }
}
