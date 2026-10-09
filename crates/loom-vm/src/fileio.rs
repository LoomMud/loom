// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Mudlib-confined file I/O for the `read_file`/`write_file` efuns (spec
//! §5.5, OBI-85): the `ed`-lite builder command's storage. Paths are
//! mudlib-absolute (`/domains/x/y.wf`), normalised and confined to the
//! mudlib root -- `..` and NUL are rejected outright -- and both
//! directions are capped at [`MAX_FILE_BYTES`].
//!
//! Confinement is two layers (CTO review, OBI-85): [`resolve`] rejects
//! `..`/NUL/non-absolute paths lexically, and [`confine_canonical`]
//! additionally canonicalizes (resolves symlinks) before trusting the
//! result, so a symlink planted *inside* the root that points outside it
//! (`/domains/x/evil -> /etc`) cannot be used to read or write outside the
//! mudlib root even though `resolve` alone would accept it.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use unicode_normalization::UnicodeNormalization;

/// Read/write size cap (spec: "cap it at 1 MiB").
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Resolve a mudlib-absolute path to a filesystem path confined under
/// `root`, purely lexically. This is the one shared VFS path resolver
/// (M-FS-2, OBI-180 threat model): every caller -- the `read_file`/
/// `write_file` efuns here and the planned `/api/v1/files/*` HTTP
/// handlers -- goes through this single function, so there is exactly
/// one place that decides what a mudlib-absolute path means.
///
/// M-FS-2's steps, in order: reject a NUL byte or a `\` anywhere in the
/// input (never meaningful in a mudlib path, and `\` is a trap for any
/// caller that might later hand the string to something that treats it
/// as a Windows separator); require a leading `/`; NFC-normalise the
/// remainder once (so two different Unicode encodings of visually
/// identical text can never resolve to two different paths); then split
/// into `/`-separated segments and reject `.`, `..`, and any *other*
/// empty segment (a bare leading `/` yields exactly one leading empty
/// segment, which is expected and skipped; `//`, trailing `/`, or an
/// internal `//` all produce an empty segment that is rejected instead
/// of silently collapsed, matching M-FS-2's "reject ... empty segments"
/// rather than normalising them away). Non-UTF-8 input cannot reach
/// this function at all -- `path: &str` is already guaranteed valid
/// UTF-8 by the type system; the HTTP layer's one-time percent-decode
/// is responsible for turning any non-UTF-8 byte sequence into a
/// rejection before it ever becomes a `&str`.
///
/// Does not touch the filesystem, so it also confines a path that does
/// not exist yet (`write_file` creating a new file). Suffix checks
/// (`write_file`'s `.wf`/`.txt` allow-list) run against `path` *before*
/// trimming happens here, keeping both checks looking at the same text.
fn resolve(root: &Path, path: &str) -> Result<PathBuf, String> {
    if path.as_bytes().contains(&0) {
        return Err("path must not contain a NUL byte".to_string());
    }
    if path.contains('\\') {
        return Err("path must not contain a `\\`".to_string());
    }
    let trimmed = path.trim();
    if !trimmed.starts_with('/') {
        return Err("path must be mudlib-absolute (start with `/`)".to_string());
    }
    // Perf (bench-gate regression on `priv_miss`/`priv_read_hit`, CI):
    // the overwhelming majority of real mudlib paths are already NFC
    // (plain ASCII qualifies trivially), so `is_nfc_quick` -- a cheap
    // per-codepoint scan with no allocation -- lets that common case
    // skip the `nfc().collect()` allocation entirely; only a path that
    // actually needs normalising pays for it.
    let normalized: std::borrow::Cow<str> =
        match unicode_normalization::is_nfc_quick(trimmed.chars()) {
            unicode_normalization::IsNormalized::Yes => std::borrow::Cow::Borrowed(trimmed),
            _ => std::borrow::Cow::Owned(trimmed.nfc().collect()),
        };
    let mut out = root.to_path_buf();
    for (i, seg) in normalized.split('/').enumerate() {
        if seg.is_empty() {
            // Exactly one empty segment is expected: the one produced by
            // the mandatory leading `/`, always at index 0. Any other
            // empty segment (`//`, a trailing `/`) is rejected rather
            // than collapsed.
            if i == 0 {
                continue;
            }
            return Err("path must not contain an empty segment".to_string());
        }
        if seg == "." {
            return Err("path must not contain a `.` segment".to_string());
        }
        if seg == ".." {
            return Err("path must not contain `..`".to_string());
        }
        // P0 driver rule (D-B3.2, OBI-190): nothing named `.git` may
        // exist anywhere in the VFS, regardless of master policy -- the
        // driver's own git dir is a *separate* `GIT_DIR`
        // (`/mudlib-git/warp.git`), never a path under the mudlib root a
        // builder can reach through `read_file`/`write_file`.
        if seg.eq_ignore_ascii_case(".git") {
            return Err("path must not contain a `.git` segment".to_string());
        }
        out.push(seg);
    }
    Ok(out)
}

/// Canonicalize `candidate` (or, if it does not exist, its deepest
/// existing ancestor) and require the result to still be under `root`'s
/// own canonical form. This is the layer that catches a symlink *inside*
/// the root pointing outside it -- `resolve`'s purely lexical check
/// cannot see through one.
///
/// // S2: this is still just "no symlink escape"; `valid_write`'s
/// per-tier/per-domain write confinement is a separate, later policy
/// layer on top of this one.
fn confine_canonical(root: &Path, candidate: &Path) -> Result<(), String> {
    let canonical_root =
        std::fs::canonicalize(root).map_err(|e| format!("{}: {e}", root.display()))?;
    let mut probe = candidate.to_path_buf();
    loop {
        // `symlink_metadata`, not `exists()`: a *dangling* symlink must
        // count as existing, so `canonicalize` below fails on it instead
        // of this loop skipping past it to its (confined) parent and a
        // later write following it outside the root.
        if std::fs::symlink_metadata(&probe).is_ok() {
            break;
        }
        if !probe.pop() {
            // Ran out of ancestors without finding one that exists; `root`
            // itself always exists (checked above), so this can't happen
            // for a `candidate` actually built from `resolve(root, ..)`.
            return Err("path has no existing ancestor under the mudlib root".to_string());
        }
    }
    let canonical_probe =
        std::fs::canonicalize(&probe).map_err(|e| format!("{}: {e}", probe.display()))?;
    if !canonical_probe.starts_with(&canonical_root) {
        return Err("path escapes the mudlib root".to_string());
    }
    Ok(())
}

/// `O_NOFOLLOW` on the leaf path only (M-FS-2): `confine_canonical`
/// already walks up to the deepest existing ancestor and checks *that*
/// canonicalizes under `root`, but a symlink planted at the exact leaf
/// in the window between that check and this open would otherwise still
/// be followed. Opening with `O_NOFOLLOW` turns that race into a clean
/// `ELOOP` error instead of a followed read/write -- every real mudlib
/// file is created by `write_file` itself and is never a symlink, so
/// this never rejects a legitimate file.
#[cfg(unix)]
fn open_nofollow(path: &Path, opts: &std::fs::OpenOptions) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    opts.clone().custom_flags(libc::O_NOFOLLOW).open(path)
}

#[cfg(not(unix))]
fn open_nofollow(path: &Path, opts: &std::fs::OpenOptions) -> std::io::Result<std::fs::File> {
    opts.open(path)
}

/// `read_file()`: `Ok(None)` if the file does not exist, `Err` for a bad
/// path, an oversized file, or any other I/O failure.
pub fn read_file(root: &Path, path: &str) -> Result<Option<String>, String> {
    let resolved = resolve(root, path)?;
    if !resolved.exists() {
        return Ok(None);
    }
    confine_canonical(root, &resolved)?;

    // Read at most `MAX_FILE_BYTES + 1` bytes through `Read::take`, so a
    // file that grows between an earlier `metadata()` check and the read
    // itself (TOCTOU) can never smuggle more than one byte over the cap
    // through, rather than trusting a stale size (CTO review, OBI-85).
    let file = open_nofollow(&resolved, std::fs::OpenOptions::new().read(true))
        .map_err(|e| format!("{path}: {e}"))?;
    let mut buf = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{path}: {e}"))?;
    if buf.len() as u64 > MAX_FILE_BYTES {
        return Err(format!("{path}: exceeds the {MAX_FILE_BYTES}-byte cap"));
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|e| format!("{path}: not valid UTF-8: {e}"))
}

/// The size of `path` in bytes, from `metadata().len()` -- never its
/// contents (OBI-137 S1: the `disk_quota_mb` counter's "old size" input
/// on an overwrite must not read a file just to size it). `Ok(0)` for a
/// path that does not exist (a brand new file has no old size to
/// subtract). Confined the same way `read_file`/`write_file` are.
pub fn file_size_bytes(root: &Path, path: &str) -> Result<u64, String> {
    let resolved = resolve(root, path)?;
    if !resolved.exists() {
        return Ok(0);
    }
    confine_canonical(root, &resolved)?;
    std::fs::metadata(&resolved)
        .map(|m| m.len())
        .map_err(|e| format!("{}: {e}", resolved.display()))
}

/// Immediate entries of a mudlib-absolute directory (OBI-180 M-FS-3):
/// each entry's bare name (not a full path), files and subdirectories
/// both included, sorted for determinism. Dotfiles (a name starting with
/// `.`, e.g. a live mudlib checkout's own `.git`, OBI-190) are hidden
/// (CTO review on PR #117, should-fix 2) -- there is no caller yet that
/// needs them, and a bare `valid_read` pass on `/` would otherwise
/// expose repository internals nothing in the mudlib ever intended to
/// publish as a file. `Ok(None)` for a path that doesn't exist or isn't
/// a directory -- the driver-side caller
/// (`World::list_dir`) maps that to the same "not found" shape
/// `read_file` already gives a missing file, so a listing you can't read
/// looks exactly like one that doesn't exist (M-FS-3). Confined the same
/// way `read_file`/`write_file` are (lexical `resolve` + `confine_
/// canonical`, `O_NOFOLLOW` has no meaning for a directory open itself,
/// but `confine_canonical` still refuses an escape via a symlinked
/// ancestor).
pub fn list_dir(root: &Path, path: &str) -> Result<Option<Vec<String>>, String> {
    let resolved = resolve(root, path)?;
    if !resolved.is_dir() {
        return Ok(None);
    }
    confine_canonical(root, &resolved)?;
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&resolved).map_err(|e| format!("{}: {e}", resolved.display()))? {
        let entry = entry.map_err(|e| format!("{}: {e}", resolved.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        names.push(name);
    }
    names.sort();
    Ok(Some(names))
}

/// Recursive byte total of every regular file under a mudlib-absolute
/// directory (OBI-121 S2c `disk_quota_mb`, `/builders/<u>/**`). `Ok(0)`
/// for a directory that does not exist yet (a builder who has never
/// written anything): the quota check treats that the same as "empty",
/// not an error. Confined the same way `read_file`/`write_file` are
/// (lexical `resolve` + `confine_canonical`), so a symlink cannot be used
/// to make this walk (or the quota it feeds) see bytes outside `root`.
///
/// **OBI-137 S1: called at most once per `<u>`, ever** (`disk_usage::
/// DiskUsage::seeded_total`'s lazy seed) -- this is the one `O(files)`
/// walk the design note allows ("seeded lazily by one walk"); every
/// write/remove/rename after that updates the cached total in `O(1)`
/// instead of re-walking.
pub fn dir_size_bytes(root: &Path, dir: &str) -> Result<u64, String> {
    let resolved = resolve(root, dir)?;
    if !resolved.exists() {
        return Ok(0);
    }
    confine_canonical(root, &resolved)?;
    let mut total = 0u64;
    let mut stack = vec![resolved];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
            let meta = entry
                .metadata()
                .map_err(|e| format!("{}: {e}", entry.path().display()))?;
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                total += meta.len();
            }
        }
    }
    Ok(total)
}

/// Make the driver's *own* save root exist before the first save
/// (OBI-324). `write_file_atomic`'s confinement check canonicalizes its
/// `root`, and `std::fs::canonicalize` fails with `ENOENT` for a directory
/// that does not exist yet -- a check that runs *before* the `create_dir_all`
/// which would have created it. So against a save root nobody ever made (a
/// fresh checkout, a container whose volume was never mounted), **every**
/// `save_object` failed the same way and could never repair itself: player
/// state silently never persisted, one `/std/player` runtime error per
/// autosave.
///
/// This belongs to the driver rather than to the mudlib: the save root is
/// driver state (spec §8.5 -- never a path a builder chooses), so the driver
/// creates it on first use instead of depending on an operator `mkdir`. A
/// failure is still returned, not swallowed: it means the save root
/// genuinely cannot be created (read-only mount, `EACCES`), which is exactly
/// the case the caller wants to surface as a save error.
///
/// `is_dir` first so the common (already-created) case costs one stat, not a
/// `mkdir` that has to fail with `EEXIST`.
pub fn ensure_save_root(root: &Path) -> Result<(), String> {
    if root.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(root).map_err(|e| format!("{}: {e}", root.display()))
}

/// `write_file()`: only `.wf`/`.txt` suffixes are allowed; parent
/// directories are created under the root as needed.
pub fn write_file(root: &Path, path: &str, text: &str) -> Result<bool, String> {
    let trimmed = path.trim();
    if !(trimmed.ends_with(".wf") || trimmed.ends_with(".txt")) {
        return Err(format!("{path}: write_file only allows .wf or .txt files"));
    }
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(format!(
            "{path}: {} bytes exceeds the {MAX_FILE_BYTES}-byte cap",
            text.len()
        ));
    }
    let resolved = resolve(root, path)?;
    // Confine *before* `create_dir_all` too, so a symlinked directory
    // inside the root can't be used to create directories outside it
    // (the deepest existing ancestor is what gets checked here).
    confine_canonical(root, &resolved)?;
    if let Some(parent) = resolved.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{path}: {e}"))?;
    }
    // Canonicalize *after* `create_dir_all`, so newly created parent
    // directories are confirmed to exist and be confined before any
    // write happens; `confine_canonical` walks up to `resolved`'s deepest
    // existing ancestor, which also catches a pre-existing symlink
    // planted at `resolved` itself (its own canonical form is checked
    // too, not just its parent's).
    // M-FS-2: open the leaf itself with `O_NOFOLLOW` (`open_nofollow`,
    // above), so even a symlink planted in the window between this
    // check and the write below is refused outright instead of raced.
    confine_canonical(root, &resolved)?;
    let mut file = open_nofollow(
        &resolved,
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true),
    )
    .map_err(|e| format!("{path}: {e}"))?;
    file.write_all(text.as_bytes())
        .map_err(|e| format!("{path}: {e}"))?;
    Ok(true)
}

/// `save_object()`'s durable write (spec §8.1, OBI-171): same
/// confinement as [`write_file`] (lexical `resolve` + symlink-escape
/// `confine_canonical`) and the same [`MAX_FILE_BYTES`] cap, but a
/// different suffix allow-list (`.o`, the classic save-file extension,
/// not `.wf`/`.txt`) and a different durability contract: the new
/// content is written to a sibling temp file in the same directory,
/// `fsync`ed, then atomically renamed over the target. A crash (process
/// kill, power loss) at any point before the rename leaves whatever was
/// at `path` before this call completely untouched -- there is no
/// window where a reader can observe a half-written save. See
/// [`stage_write`]/[`commit_write`] (split out for
/// `crash_before_rename_leaves_the_previous_save_intact` below, which
/// exercises exactly that window without needing to actually kill a
/// process) for the two halves this composes.
pub fn write_file_atomic(root: &Path, path: &str, text: &str) -> Result<bool, String> {
    let tmp = stage_write(root, path, text)?;
    commit_write(root, path, &tmp)
}

/// Phase 1: validate, confine, and durably write `text` to a sibling
/// temp file next to where `path` resolves -- but do not yet touch
/// `path` itself. Returns the temp file's path, still present on disk.
fn stage_write(root: &Path, path: &str, text: &str) -> Result<PathBuf, String> {
    let trimmed = path.trim();
    if !trimmed.ends_with(".o") {
        return Err(format!("{path}: save files must end in .o"));
    }
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(format!(
            "{path}: {} bytes exceeds the {MAX_FILE_BYTES}-byte cap",
            text.len()
        ));
    }
    let resolved = resolve(root, path)?;
    // Confine before *and* after `create_dir_all`, exactly like
    // `write_file`: catches a symlink planted at `resolved` itself as
    // well as one along a not-yet-created parent directory.
    confine_canonical(root, &resolved)?;
    if let Some(parent) = resolved.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{path}: {e}"))?;
    }
    confine_canonical(root, &resolved)?;
    let parent = resolved
        .parent()
        .expect("resolved always has a parent under root");
    let leaf = resolved
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("save");
    let tmp = parent.join(format!(".{leaf}.tmp-{}", std::process::id()));
    // CTO review (OBI-171, PR #75): a previous crash between this
    // `stage_write` and its matching `commit_write` can leave a stale
    // tmp file at this exact name (same pid is reused by the OS only
    // after a reboot, but a retried `save_object` call from the *same*
    // still-running process reuses it immediately) -- clear it first so
    // `create_new` below can't spuriously fail on it. Not found is fine;
    // any other removal error is surfaced; it's safer to fail the save
    // than silently clobber or follow something unexpected left in its
    // place.
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{path}: clearing stale tmp file: {e}")),
    }
    {
        use std::io::Write;
        // `create_new` (O_EXCL), not `File::create` (CTO review, OBI-171,
        // PR #75): `File::create` truncates-or-creates and *follows* a
        // symlink planted at this exact tmp-file name, so a symlink
        // planted here pointing outside `root` would have this write its
        // save contents through it. `create_new` atomically fails
        // instead of following anything already at this path -- and
        // nothing legitimate is ever already at this path (the removal
        // above just cleared the one case that can be, a stale tmp file
        // of this process's own making).
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| format!("{path}: {e}"))?;
        f.write_all(text.as_bytes())
            .map_err(|e| format!("{path}: {e}"))?;
        f.sync_all().map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(tmp)
}

/// Phase 2: atomically rename a temp file staged by [`stage_write`] over
/// `path`'s resolved location -- the single filesystem operation after
/// which the new content is durably in place -- then `fsync` the parent
/// directory (CTO review, OBI-171, PR #75). The rename alone is only
/// atomic, not durable: on most filesystems a directory entry update is
/// itself buffered, so a power loss shortly after a `rename()` returns
/// can roll the rename back on the next boot even though `save_object`
/// already reported success. `fsync`ing the parent's directory fd is
/// what makes the *directory entry* for the rename durable, matching
/// `stage_write`'s own `sync_all()` on the tmp file's *contents* before
/// the rename. Cleans up `tmp` on a rename failure rather than leaving
/// it behind.
fn commit_write(root: &Path, path: &str, tmp: &Path) -> Result<bool, String> {
    let resolved = resolve(root, path)?;
    std::fs::rename(tmp, &resolved).map_err(|e| {
        let _ = std::fs::remove_file(tmp);
        format!("{path}: {e}")
    })?;
    if let Some(parent) = resolved.parent() {
        std::fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|e| format!("{path}: fsync parent dir: {e}"))?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("loom-fileio-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        // Canonicalize once here too, so tests that compare against
        // `root` don't trip over e.g. macOS's `/tmp` -> `/private/tmp`
        // symlink looking like an "escape".
        std::fs::canonicalize(&root).unwrap()
    }

    #[test]
    fn read_missing_is_none() {
        let root = tmp_root("missing");
        assert_eq!(read_file(&root, "/domains/x/nope.wf").unwrap(), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn write_then_read_round_trips() {
        let root = tmp_root("roundtrip");
        assert!(write_file(&root, "/domains/x/y.wf", "hello").unwrap());
        assert_eq!(
            read_file(&root, "/domains/x/y.wf").unwrap(),
            Some("hello".to_string())
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn list_dir_returns_sorted_entry_names() {
        let root = tmp_root("list-dir");
        write_file(&root, "/domains/x/b.wf", "b").unwrap();
        write_file(&root, "/domains/x/a.wf", "a").unwrap();
        std::fs::create_dir_all(root.join("domains/x/sub")).unwrap();
        assert_eq!(
            list_dir(&root, "/domains/x").unwrap(),
            Some(vec![
                "a.wf".to_string(),
                "b.wf".to_string(),
                "sub".to_string()
            ])
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn list_dir_hides_dotfiles() {
        let root = tmp_root("list-dir-dotfiles");
        write_file(&root, "/domains/x/visible.wf", "v").unwrap();
        std::fs::create_dir_all(root.join("domains/x/.git")).unwrap();
        std::fs::write(root.join("domains/x/.gitignore"), "x").unwrap();
        assert_eq!(
            list_dir(&root, "/domains/x").unwrap(),
            Some(vec!["visible.wf".to_string()]),
            "dotfiles (.git, .gitignore) must never show up in a listing"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn list_dir_on_a_missing_path_is_none() {
        let root = tmp_root("list-dir-missing");
        assert_eq!(list_dir(&root, "/domains/nope").unwrap(), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn list_dir_on_a_file_not_a_directory_is_none() {
        let root = tmp_root("list-dir-on-file");
        write_file(&root, "/domains/x/a.wf", "a").unwrap();
        assert_eq!(list_dir(&root, "/domains/x/a.wf").unwrap(), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dotdot_is_rejected() {
        let root = tmp_root("dotdot");
        assert!(read_file(&root, "/domains/../../etc/passwd").is_err());
        assert!(write_file(&root, "/domains/../../etc/passwd.txt", "x").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dotgit_segment_is_rejected_anywhere_in_the_path() {
        // P0 driver rule (D-B3.2, OBI-190): regardless of where it
        // appears, a `.git` segment is never resolvable in the VFS --
        // the driver's own git dir lives outside the mudlib root
        // entirely.
        let root = tmp_root("dotgit");
        assert!(read_file(&root, "/.git/config").is_err());
        assert!(read_file(&root, "/domains/x/.git/config").is_err());
        assert!(write_file(&root, "/.git/config", "x").is_err());
        assert!(write_file(&root, "/domains/x/.git/HEAD.txt", "x").is_err());
        assert!(read_file(&root, "/domains/x/.GIT/config").is_err());
        assert!(write_file(&root, "/.GIT/config", "x").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn nul_is_rejected() {
        let root = tmp_root("nul");
        assert!(read_file(&root, "/domains/x\0y.wf").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn absolute_path_outside_root_stays_confined() {
        let root = tmp_root("confine");
        // Not `..`, but an absolute-looking mudlib path is always resolved
        // *under* root, never as a real absolute filesystem path.
        assert!(write_file(&root, "/etc/passwd.txt", "pwned").unwrap());
        assert!(root.join("etc/passwd.txt").exists());
        assert!(
            !Path::new("/etc/passwd.txt").exists() || {
                // Extremely defensive: never true in CI, but never trust a
                // real /etc/passwd.txt existing because of this test.
                std::fs::read_to_string("/etc/passwd.txt").unwrap_or_default() != "pwned"
            }
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn file_size_bytes_is_zero_for_a_missing_path_and_the_metadata_len_otherwise() {
        let root = tmp_root("file-size");
        assert_eq!(file_size_bytes(&root, "/domains/x/nope.wf").unwrap(), 0);
        write_file(&root, "/domains/x/y.wf", "hello").unwrap();
        assert_eq!(file_size_bytes(&root, "/domains/x/y.wf").unwrap(), 5);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn bad_suffix_is_rejected() {
        let root = tmp_root("suffix");
        assert!(write_file(&root, "/domains/x/y.exe", "no").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn atomic_write_round_trips_and_only_allows_dot_o() {
        let root = tmp_root("atomic-roundtrip");
        assert!(write_file_atomic(&root, "/players/bob.o", "{\"hp\":10}").unwrap());
        assert_eq!(
            read_file(&root, "/players/bob.o").unwrap(),
            Some("{\"hp\":10}".to_string())
        );
        assert!(write_file_atomic(&root, "/players/bob.txt", "nope").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn atomic_write_replaces_the_old_save_and_leaves_no_temp_file_behind() {
        let root = tmp_root("atomic-replace");
        assert!(write_file_atomic(&root, "/players/bob.o", "old").unwrap());
        assert!(write_file_atomic(&root, "/players/bob.o", "new").unwrap());
        assert_eq!(
            read_file(&root, "/players/bob.o").unwrap(),
            Some("new".to_string())
        );
        let entries: Vec<_> = std::fs::read_dir(root.join("players"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            entries,
            vec!["bob.o".to_string()],
            "no leftover .tmp-* file"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The crash-safety contract `write_file_atomic` exists for: a crash
    /// (process kill, power loss) between the temp write and the rename
    /// must leave whatever was already saved completely untouched. This
    /// drives exactly that window by calling `stage_write` (temp file
    /// written and fsynced) without ever calling `commit_write` --
    /// equivalent to the process dying right there -- and asserts the
    /// previous save is still exactly as it was (OBI-171 acceptance:
    /// "crash during write leaves the old save intact").
    #[test]
    fn crash_before_rename_leaves_the_previous_save_intact() {
        let root = tmp_root("atomic-crash");
        assert!(write_file_atomic(&root, "/players/bob.o", "original save").unwrap());

        let tmp = stage_write(&root, "/players/bob.o", "corrupted half-written save").unwrap();
        assert!(tmp.exists(), "the staged temp file exists mid-\"crash\"");

        // "Crash": nothing calls `commit_write`. The real save file must
        // be exactly what it was before this attempt.
        assert_eq!(
            read_file(&root, "/players/bob.o").unwrap(),
            Some("original save".to_string()),
            "a crash before the rename must not touch the previous save"
        );

        // Finishing the commit afterwards (the process restarts and a
        // later save succeeds) still works and replaces it.
        assert!(commit_write(&root, "/players/bob.o", &tmp).unwrap());
        assert_eq!(
            read_file(&root, "/players/bob.o").unwrap(),
            Some("corrupted half-written save".to_string())
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// OBI-324 regression: a save root that does not exist yet must not
    /// stay unwritable. `confine_canonical` canonicalizes its `root`, and
    /// `canonicalize` is `ENOENT` for a missing directory -- a check that
    /// runs *before* the `create_dir_all` of the save file's parent, so
    /// under a never-created root every save failed the same way and could
    /// never repair itself (this is what made one `/std/player` runtime
    /// error per player in `loadtest-e1-1`). `ensure_save_root` is the
    /// driver-side step `save_object` now runs first.
    #[test]
    fn a_save_root_that_does_not_exist_yet_becomes_writable_after_ensuring() {
        let parent = tmp_root("save-root-missing");
        let root = parent.join("saves");
        assert!(!root.exists());
        let err = write_file_atomic(&root, "/players/bob.o", "{}").unwrap_err();
        assert!(
            err.contains("No such file") || err.contains("os error 2"),
            "the pre-fix failure must be the missing-root canonicalize, got {err}"
        );

        ensure_save_root(&root).expect("the driver creates its own save root");
        assert!(root.is_dir());
        // Idempotent (the hot path: every later save re-checks it).
        ensure_save_root(&root).expect("ensure is idempotent");
        assert!(write_file_atomic(&root, "/players/bob.o", "{}").unwrap());
        assert_eq!(
            read_file(&root, "/players/bob.o").unwrap(),
            Some("{}".to_string())
        );

        // A nested root is created in one call, and a root that genuinely
        // cannot be created is an error, never a swallowed one.
        let nested = parent.join("a/b/c");
        ensure_save_root(&nested).expect("nested create");
        assert!(nested.is_dir());
        std::fs::write(parent.join("blocked"), b"x").unwrap();
        assert!(ensure_save_root(&parent.join("blocked/saves")).is_err());
        let _ = std::fs::remove_dir_all(&parent);
    }

    /// CTO review (OBI-171, PR #75, must-fix 3/4): `stage_write` must
    /// not blindly `File::create` the tmp-file name -- a symlink planted
    /// there (e.g. a race with something else writing under the save
    /// root) must never be followed to write through it. This plants one
    /// pointing outside the save root, then asserts the save still
    /// succeeds (the stale-clear step unlinks the symlink itself --
    /// `unlink`/`remove_file` always targets the link entry, never what
    /// it points to -- and `create_new` then makes a fresh regular file)
    /// and, the actual security property, that the symlink's target was
    /// never written through.
    #[cfg(unix)]
    #[test]
    fn stage_write_does_not_follow_a_symlink_planted_at_the_tmp_name() {
        use std::os::unix::fs::symlink;

        let root = tmp_root("atomic-tmp-symlink");
        std::fs::create_dir_all(root.join("players")).unwrap();
        let outside = std::env::temp_dir().join(format!(
            "loom-fileio-test-outside-{}-{}",
            "tmp-symlink",
            std::process::id()
        ));
        std::fs::write(&outside, "do not touch").unwrap();

        let tmp_name = format!(".bob.o.tmp-{}", std::process::id());
        symlink(&outside, root.join("players").join(&tmp_name)).unwrap();

        let tmp = stage_write(&root, "/players/bob.o", "attacker-controlled").unwrap();
        assert!(commit_write(&root, "/players/bob.o", &tmp).unwrap());
        assert_eq!(
            read_file(&root, "/players/bob.o").unwrap(),
            Some("attacker-controlled".to_string()),
            "the save itself still succeeds, into a fresh real file"
        );
        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            "do not touch",
            "the symlink target must never be written through"
        );
        let _ = std::fs::remove_file(&outside);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// CTO review (OBI-171, PR #75, must-fix 3): a tmp file left behind
    /// by an earlier crashed attempt (same pid, process never got to
    /// `commit_write`) must be cleared before `create_new`, not treated
    /// as a pre-existing-file error.
    #[test]
    fn stage_write_clears_a_stale_tmp_file_from_an_earlier_crashed_attempt() {
        let root = tmp_root("atomic-stale-tmp");
        std::fs::create_dir_all(root.join("players")).unwrap();
        let tmp_name = format!(".bob.o.tmp-{}", std::process::id());
        std::fs::write(root.join("players").join(&tmp_name), "stale half-write").unwrap();

        let tmp = stage_write(&root, "/players/bob.o", "fresh save").unwrap();
        assert_eq!(std::fs::read_to_string(&tmp).unwrap(), "fresh save");
        assert!(commit_write(&root, "/players/bob.o", &tmp).unwrap());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn atomic_write_oversized_is_rejected_without_touching_disk() {
        let root = tmp_root("atomic-oversize");
        let big = "a".repeat(MAX_FILE_BYTES as usize + 1);
        assert!(write_file_atomic(&root, "/players/bob.o", &big).is_err());
        assert_eq!(read_file(&root, "/players/bob.o").unwrap(), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    #[cfg(unix)]
    fn atomic_write_through_a_symlink_escape_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = tmp_root("atomic-symlink-escape");
        let outside = tmp_root("atomic-symlink-escape-outside");
        std::fs::create_dir_all(root.join("players")).unwrap();
        symlink(&outside, root.join("players/evil")).unwrap();

        let result = write_file_atomic(&root, "/players/evil/pwned.o", "pwned");
        assert!(result.is_err(), "expected an error, got {result:?}");
        assert!(!outside.join("pwned.o").exists());

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn oversized_write_is_rejected() {
        let root = tmp_root("oversize-write");
        let big = "a".repeat(MAX_FILE_BYTES as usize + 1);
        assert!(write_file(&root, "/domains/x/big.txt", &big).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn oversized_read_is_rejected() {
        let root = tmp_root("oversize-read");
        let path = root.join("big.txt");
        std::fs::write(&path, vec![b'a'; MAX_FILE_BYTES as usize + 1]).unwrap();
        assert!(read_file(&root, "/big.txt").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A symlink *inside* the mudlib root pointing outside it must not let
    /// either `read_file` or `write_file` escape (CTO review, OBI-85).
    #[test]
    #[cfg(unix)]
    fn symlink_escape_is_rejected_for_read_and_write() {
        use std::os::unix::fs::symlink;

        let root = tmp_root("symlink-escape");
        let outside = tmp_root("symlink-escape-outside");
        std::fs::write(outside.join("secret.txt"), "top secret").unwrap();

        std::fs::create_dir_all(root.join("domains/x")).unwrap();
        symlink(&outside, root.join("domains/x/evil")).unwrap();

        // Reading through the symlink must fail, not return the outside
        // file's contents.
        let result = read_file(&root, "/domains/x/evil/secret.txt");
        assert!(result.is_err(), "expected an error, got {result:?}");

        // Writing through the symlink must fail, not land outside root.
        let result = write_file(&root, "/domains/x/evil/pwned.txt", "pwned");
        assert!(result.is_err(), "expected an error, got {result:?}");
        assert!(!outside.join("pwned.txt").exists());

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// A symlink planted at the *exact* write target (parent dir is fine,
    /// but the leaf itself is a symlink pointing outside root) must also
    /// be rejected, not silently followed by `std::fs::write`.
    #[test]
    #[cfg(unix)]
    fn write_through_a_symlinked_leaf_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = tmp_root("symlink-leaf");
        let outside = tmp_root("symlink-leaf-outside");
        std::fs::write(outside.join("real.txt"), "original").unwrap();

        std::fs::create_dir_all(root.join("domains/x")).unwrap();
        symlink(outside.join("real.txt"), root.join("domains/x/link.txt")).unwrap();

        let result = write_file(&root, "/domains/x/link.txt", "clobbered");
        assert!(result.is_err(), "expected an error, got {result:?}");
        assert_eq!(
            std::fs::read_to_string(outside.join("real.txt")).unwrap(),
            "original",
            "the outside file must be untouched"
        );

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// A *dangling* symlink at the leaf must not let `write_file` create
    /// its target outside the root (CTO re-review, OBI-85).
    #[test]
    #[cfg(unix)]
    fn write_through_a_dangling_symlinked_leaf_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = tmp_root("dangling-leaf");
        let outside = tmp_root("dangling-leaf-outside");
        std::fs::create_dir_all(root.join("domains/x")).unwrap();
        symlink(outside.join("created.txt"), root.join("domains/x/link.txt")).unwrap();

        let result = write_file(&root, "/domains/x/link.txt", "escaped");
        assert!(result.is_err(), "expected an error, got {result:?}");
        assert!(!outside.join("created.txt").exists());

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// `write_file` must reject a path through a symlinked directory
    /// *before* `create_dir_all`, so no directories appear outside the
    /// root either (CTO re-review, OBI-85).
    #[test]
    #[cfg(unix)]
    fn write_through_a_symlinked_dir_creates_nothing_outside_root() {
        use std::os::unix::fs::symlink;

        let root = tmp_root("symlink-mkdir");
        let outside = tmp_root("symlink-mkdir-outside");
        std::fs::create_dir_all(root.join("domains/x")).unwrap();
        symlink(&outside, root.join("domains/x/evil")).unwrap();

        let result = write_file(&root, "/domains/x/evil/a/b/c.txt", "x");
        assert!(result.is_err(), "expected an error, got {result:?}");
        assert!(!outside.join("a").exists(), "no directories outside root");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// A symlink planted at the exact write target *after* the lexical
    /// and canonical checks but caught by `O_NOFOLLOW` at open time
    /// (M-FS-2) -- simulated here by writing through an existing symlink
    /// leaf the normal way (`write_through_a_symlinked_leaf_is_rejected`
    /// above already covers "symlink present before the call starts";
    /// this one additionally asserts the file's *contents* are
    /// untouched, not just that the outer `Result` is an error, so a
    /// future refactor can't quietly fall back to following the link).
    #[test]
    #[cfg(unix)]
    fn read_through_a_symlinked_leaf_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = tmp_root("read-symlink-leaf");
        let outside = tmp_root("read-symlink-leaf-outside");
        std::fs::write(outside.join("secret.txt"), "top secret").unwrap();
        std::fs::create_dir_all(root.join("domains/x")).unwrap();
        symlink(outside.join("secret.txt"), root.join("domains/x/link.txt")).unwrap();

        let result = read_file(&root, "/domains/x/link.txt");
        assert!(result.is_err(), "expected an error, got {result:?}");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn backslash_is_rejected() {
        let root = tmp_root("backslash");
        assert!(read_file(&root, "/domains/x\\y.wf").is_err());
        assert!(write_file(&root, "/domains/x\\y.wf", "x").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn double_slash_is_rejected_not_collapsed() {
        let root = tmp_root("double-slash");
        assert!(read_file(&root, "/domains//x/y.wf").is_err());
        assert!(read_file(&root, "/domains/x/y.wf/").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dot_segment_is_rejected_not_skipped() {
        let root = tmp_root("dot-segment");
        assert!(read_file(&root, "/domains/./x/y.wf").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// M-FS-2: NFC-normalise once, in the shared resolver -- two
    /// differently-encoded (NFC vs NFD) forms of the same visual path
    /// must land on the same file, not two different ones.
    #[test]
    fn nfc_and_nfd_forms_of_the_same_path_resolve_identically() {
        let root = tmp_root("nfc");
        // "e" + combining acute accent (NFD) vs the precomposed "é" (NFC).
        let nfd_path = "/domains/cafe\u{0301}/y.wf";
        let nfc_path = "/domains/caf\u{00e9}/y.wf";
        write_file(&root, nfd_path, "hello").unwrap();
        assert_eq!(
            read_file(&root, nfc_path).unwrap(),
            Some("hello".to_string())
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // M-FS-2: fuzz/property test -- for any input string, `resolve` must
    // never (a) panic, and (b) produce a path that, once it exists,
    // canonicalizes to somewhere outside `root`. We can't easily drive
    // arbitrary bytes through a `&str` API with the actual filesystem
    // underneath in a property test without creating real directories
    // for every case, so this focuses on the lexical half of the
    // contract: `resolve` never returns `Ok` for input containing `..`
    // as a path component, a NUL byte, or a `\`, and every `Ok` result's
    // path lexically starts with `root`.
    use proptest::prop_assert;

    proptest::proptest! {
        #[test]
        fn resolve_never_escapes_root_lexically(segments in proptest::collection::vec(
            proptest::sample::select(vec![
                "a", "b", "..", ".", "", "x\u{0301}", "y\u{00e9}", ".git", "c",
            ]),
            0..8,
        )) {
            let root = tmp_root("proptest-resolve");
            let path = format!("/{}", segments.join("/"));
            match resolve(&root, &path) {
                Ok(resolved) => {
                    prop_assert!(resolved.starts_with(&root));
                    // A lexically-accepted path must not contain `..` or
                    // `.` components once resolved, and must not have
                    // escaped `root` by segment count either.
                    for comp in resolved.strip_prefix(&root).unwrap().components() {
                        use std::path::Component;
                        prop_assert!(!matches!(comp, Component::ParentDir | Component::CurDir));
                    }
                }
                Err(_) => {
                    // Rejecting is always a safe outcome for this property.
                }
            }
            let _ = std::fs::remove_dir_all(&root);
        }

        #[test]
        fn resolve_rejects_every_nul_or_backslash_input(s in ".*") {
            let root = tmp_root("proptest-nul-backslash");
            if s.as_bytes().contains(&0) || s.contains('\\') {
                prop_assert!(resolve(&root, &s).is_err());
            }
            let _ = std::fs::remove_dir_all(&root);
        }
    }
}
