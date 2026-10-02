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
//!
//! **Two pools, not one (OBI-236 fix, follow-up to PR #75's CTO
//! re-review):** `disk_quota_mb` covers both `/builders/<u>/**`
//! (`seeded_total`/`note_write`/`note_remove`/`note_rename`, below) and
//! `<u>`'s own `save_object` file (`seeded_save_total`/
//! `note_save_write`), and these two things are seeded from completely
//! different sources (a directory walk vs. a single `metadata()` stat on
//! an unrelated path only `check_save_disk_quota` ever learns). An
//! earlier version kept both in one `HashMap<String, u64>` behind
//! `entry().or_insert_with`, so whichever side asked about `<u>` first
//! silently won the seed for *both*:
//!
//! - save first: the shared counter seeded from the save file's size
//!   alone, and `/builders/<u>/**` was never walked at all -- a builder
//!   near quota got roughly one extra full quota's worth of `write_file`
//!   per driver restart, for as long as `<u>` happened to save before it
//!   wrote.
//! - `write_file` first: the shared counter seeded from the directory
//!   walk alone (no save file in it), but `check_save_disk_quota` still
//!   unconditionally subtracted the save file's `old_bytes` from that same
//!   counter on an overwrite -- the saturating subtraction then silently
//!   undercounted by the old save's size from that point on.
//!
//! Keeping the two pools separate (`dir_totals`/`save_totals`) removes
//! the seed race entirely: each pool is seeded only from its own source,
//! the first time *that* pool specifically is asked about, regardless of
//! what order the two call sites run in. A quota check still has to see
//! "everything `<u>` has on disk" as the spec requires, so both
//! `check_disk_quota` and `check_save_disk_quota` add the *other* pool's
//! current total (0 if that pool has never been seeded yet -- see
//! [`Self::dir_total`]/[`Self::save_total`]) to their own projected delta
//! before comparing against `disk_quota_mb`.

use std::collections::HashMap;
use std::path::Path;

/// Owned by `World`, one entry per `<u>` that has ever been asked about
/// (a builder who has never written under quota is never seeded, so an
/// idle mudlib with a thousand builders costs nothing here until one of
/// them actually gets a `disk_quota_mb` row and writes something).
#[derive(Default)]
pub struct DiskUsage {
    /// `/builders/<u>/**`'s total, seeded by one `dir_size_bytes` walk.
    dir_totals: HashMap<String, u64>,
    /// `<u>`'s own `save_object` file's size, seeded by one
    /// `file_size_bytes` stat.
    save_totals: HashMap<String, u64>,
}

impl DiskUsage {
    /// `<u>`'s current `/builders/<u>/**` total, seeding it with one
    /// recursive walk the first time `<u>` is asked about through this
    /// method (`root`/`u` are only ever touched on that one seed; every
    /// later call is a plain `HashMap` lookup, no filesystem access at
    /// all). Independent of [`Self::seeded_save_total`]'s pool: seeding
    /// one never seeds, or looks at, the other.
    pub fn seeded_total(&mut self, root: &Path, u: &str) -> u64 {
        *self.dir_totals.entry(u.to_string()).or_insert_with(|| {
            crate::fileio::dir_size_bytes(root, &format!("/builders/{u}")).unwrap_or(0)
        })
    }

    /// `<u>`'s current `/builders/<u>/**` total *without* seeding it --
    /// `0` if `<u>` has never gone through [`Self::seeded_total`]. Used
    /// by `check_save_disk_quota` to fold the directory pool into a
    /// save's projected total without forcing a directory walk on every
    /// save (that pool only needs the walk once something actually asks
    /// about `/builders/<u>/**` itself).
    pub fn dir_total(&self, u: &str) -> u64 {
        self.dir_totals.get(u).copied().unwrap_or(0)
    }

    /// Record a write under `/builders/<u>/**` that replaces a file which
    /// used to be `old_bytes` (0 for a brand new file) with one of
    /// `new_bytes`. Must only be called once the caller has committed to
    /// actually performing the write (a write rejected for being over
    /// quota must not touch the counter) -- and only after `<u>`'s
    /// directory total has been seeded via [`Self::seeded_total`] (this
    /// never seeds on its own: an unconditional `entry().or_insert(0)`
    /// here would silently treat an unseeded `<u>` as starting from zero
    /// instead of its real on-disk total).
    pub fn note_write(&mut self, u: &str, old_bytes: u64, new_bytes: u64) {
        if let Some(total) = self.dir_totals.get_mut(u) {
            *total = total.saturating_sub(old_bytes).saturating_add(new_bytes);
        }
    }

    /// Record a file of `old_bytes` being removed from `<u>`'s
    /// `/builders/<u>/**` tree.
    pub fn note_remove(&mut self, u: &str, old_bytes: u64) {
        if let Some(total) = self.dir_totals.get_mut(u) {
            *total = total.saturating_sub(old_bytes);
        }
    }

    /// Record a rename moving a file of `bytes` out of `from_u`'s
    /// `/builders/<u>/**` tree and into `to_u`'s (a no-op net delta if
    /// they are the same uid, but still routed through both
    /// `note_remove`/`note_write` so a rename *within* one uid's own
    /// tree, which does not change that uid's total, still only touches
    /// counters that were actually seeded).
    pub fn note_rename(&mut self, from_u: &str, to_u: &str, bytes: u64) {
        self.note_remove(from_u, bytes);
        self.note_write(to_u, 0, bytes);
    }

    /// `<u>`'s total, seeded from its own save file under `save_root`
    /// (OBI-171 `save_object`'s `disk_quota_mb` charge; CTO review on
    /// PR #75: "charge the save to the writing object's uid, using the
    /// same `seeded_total`/`note_write` path, but seeded from the save
    /// root"), if `<u>`'s save pool has not already been seeded. A
    /// separate pool from [`Self::seeded_total`]'s directory walk (OBI-236
    /// fix): unlike that walk, this is a single `metadata()` stat
    /// (`fileio::file_size_bytes`) -- the master's save-path
    /// authorization contract (`docs/save-objects.md`) confines a uid to
    /// exactly one save path, so there is nothing to recursively walk.
    pub fn seeded_save_total(&mut self, save_root: &Path, u: &str, save_file_rel: &str) -> u64 {
        *self.save_totals.entry(u.to_string()).or_insert_with(|| {
            crate::fileio::file_size_bytes(save_root, save_file_rel).unwrap_or(0)
        })
    }

    /// `<u>`'s current save-file total *without* seeding it -- `0` if
    /// `<u>` has never gone through [`Self::seeded_save_total`]. Used by
    /// `check_disk_quota` to fold the save pool into a `write_file`'s
    /// projected total without forcing a save-file stat on every
    /// unrelated write.
    pub fn save_total(&self, u: &str) -> u64 {
        self.save_totals.get(u).copied().unwrap_or(0)
    }

    /// Record a `save_object` write that replaces a save file which used
    /// to be `old_bytes` (0 for a brand new save) with one of
    /// `new_bytes`. Same "committed write, already seeded" contract as
    /// [`Self::note_write`], but against the save pool.
    pub fn note_save_write(&mut self, u: &str, old_bytes: u64, new_bytes: u64) {
        if let Some(total) = self.save_totals.get_mut(u) {
            *total = total.saturating_sub(old_bytes).saturating_add(new_bytes);
        }
    }

    #[cfg(test)]
    fn total_for(&self, u: &str) -> Option<u64> {
        self.dir_totals.get(u).copied()
    }

    #[cfg(test)]
    fn save_total_for(&self, u: &str) -> Option<u64> {
        self.save_totals.get(u).copied()
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
        usage.dir_totals.insert("appr".to_string(), 0);

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
        usage.dir_totals.insert("appr".to_string(), 50);
        usage.note_remove("appr", 30);
        assert_eq!(usage.total_for("appr"), Some(20));
        usage.note_remove("appr", 999); // more than remains: saturates at 0
        assert_eq!(usage.total_for("appr"), Some(0));
    }

    #[test]
    fn note_rename_moves_bytes_between_two_uids() {
        let mut usage = DiskUsage::default();
        usage.dir_totals.insert("appr".to_string(), 100);
        usage.dir_totals.insert("senior".to_string(), 0);
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

    /// OBI-236: `seeded_save_total` running before `seeded_total` must
    /// not swallow the directory pool's seed -- the two pools are
    /// independent, so seeding the save pool first still leaves the
    /// directory pool completely unseeded (not "seeded at 0", and not
    /// "seeded at the save file's size").
    #[test]
    fn seeded_save_total_does_not_prevent_the_directory_pool_from_being_seeded() {
        let root =
            std::env::temp_dir().join(format!("loom-disk-usage-test-save1-{}", std::process::id()));
        let save_root = std::env::temp_dir().join(format!(
            "loom-disk-usage-test-save1-saves-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&save_root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&save_root).unwrap();
        crate::fileio::write_file(&root, "/builders/appr/a.wf", "0123456789").unwrap(); // 10 bytes
        std::fs::write(save_root.join("appr.o"), "12345").unwrap(); // 5 bytes

        let mut usage = DiskUsage::default();
        // Save seeds first (as `check_save_disk_quota` would on an
        // autosave that fires before the builder ever calls `write_file`).
        assert_eq!(usage.seeded_save_total(&save_root, "appr", "/appr.o"), 5);
        assert_eq!(usage.dir_total("appr"), 0, "directory pool not seeded yet");

        // `write_file` runs later: its own pool must still walk and see
        // the full 10-byte tree, not come back 0 or 5 because the shared
        // counter was already "claimed" by the save seed.
        assert_eq!(usage.seeded_total(&root, "appr"), 10);
        assert_eq!(
            usage.save_total_for("appr"),
            Some(5),
            "save pool untouched by the dir seed"
        );

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&save_root);
    }

    /// OBI-236: `seeded_total` running before `seeded_save_total` must
    /// not cause the save pool to start from the directory total (or
    /// from 0) -- the save pool still has to see the save file's *actual*
    /// current size the first time it is seeded, even though that file
    /// already existed before `write_file` ever touched the directory
    /// pool.
    #[test]
    fn seeded_total_does_not_undercount_a_later_save_overwrite() {
        let root =
            std::env::temp_dir().join(format!("loom-disk-usage-test-save2-{}", std::process::id()));
        let save_root = std::env::temp_dir().join(format!(
            "loom-disk-usage-test-save2-saves-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&save_root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&save_root).unwrap();
        crate::fileio::write_file(&root, "/builders/appr/a.wf", "01234").unwrap(); // 5 bytes
        // A save file already exists on disk from a previous run, before
        // `save_object` has ever gone through `DiskUsage` this process.
        std::fs::write(save_root.join("appr.o"), "0123456789").unwrap(); // 10 bytes

        let mut usage = DiskUsage::default();
        // `write_file` seeds (and bumps) the directory pool first.
        assert_eq!(usage.seeded_total(&root, "appr"), 5);
        usage.note_write("appr", 0, 3); // a brand new 3-byte file
        assert_eq!(usage.total_for("appr"), Some(8));

        // Now `save_object` overwrites the existing save with something
        // bigger. The seed must see the *real* pre-existing 10 bytes on
        // disk, not 0 (which would make the saturating subtraction below
        // undercount by the old save's size).
        let old_bytes = 10u64;
        let new_bytes = 20u64;
        let seeded = usage.seeded_save_total(&save_root, "appr", "/appr.o");
        assert_eq!(seeded, 10, "save pool must see the real on-disk save size");
        usage.note_save_write("appr", old_bytes, new_bytes);
        assert_eq!(
            usage.save_total_for("appr"),
            Some(20),
            "10 - 10 + 20, not a saturating-subtraction undercount from an unseeded 0"
        );
        // The directory pool is completely unaffected by the save write.
        assert_eq!(usage.total_for("appr"), Some(8));

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&save_root);
    }
}
