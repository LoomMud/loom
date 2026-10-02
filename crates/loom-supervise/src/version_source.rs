// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The desired driver version source (design §9.9): "what version should
//! be running" is deliberately decoupled from *how the supervisor finds
//! out* -- Docker staging (E2.2-docker, OBI-184's own gate) has the
//! reconciler write a version string to a file; the later Flux/K1 slice
//! (OBI-187) reads the same string out of a mounted `loom-release`
//! ConfigMap key. [`VersionSource`] is the seam between them: `loom
//! supervise`'s reconcile loop only ever calls [`VersionSource::poll`],
//! never a file path or a Kubernetes API directly.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Where `loom supervise` currently believes the desired driver version
/// comes from. Both implementations here are polling, not push -- a
/// mounted ConfigMap key updates via `kubelet`'s own periodic resync, and
/// a plain file has no portable "notify me on write" that works
/// identically across bind-mounts/overlays, so `poll` (called on a timer
/// by the reconcile loop, not a `watch`/inotify callback) is the one
/// interface every source implements.
pub trait VersionSource: Send {
    /// Read the current desired version. `Ok(None)` means "the source is
    /// not configured/present yet" (e.g. the file does not exist yet at
    /// boot) -- not an error: the supervisor keeps running whatever
    /// version it already has.
    fn poll(&mut self) -> std::io::Result<Option<String>>;
}

/// Docker staging's [`VersionSource`] (E2.2-docker, D-P2.2): a single file
/// the `loom-gitops` reconciler writes, trimmed of surrounding whitespace.
/// Deliberately tolerant of a missing file (boot ordering: the reconciler
/// may not have written it yet) and of trailing newlines (the simplest
/// thing a reconciler script can do is `printf '%s' "$version" >
/// desired-version` or `echo "$version" > desired-version`; both must
/// parse the same).
pub struct FileVersionSource {
    path: PathBuf,
    last_mtime: Option<SystemTime>,
}

impl FileVersionSource {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            last_mtime: None,
        }
    }
}

impl VersionSource for FileVersionSource {
    fn poll(&mut self) -> std::io::Result<Option<String>> {
        read_version_file(&self.path, &mut self.last_mtime)
    }
}

/// Split out from [`FileVersionSource::poll`] so it's unit-testable
/// without constructing the whole struct, and reused by
/// [`FileVersionSource`] only (kept private: the mtime-skip optimisation
/// is an implementation detail, not something callers should rely on --
/// `poll` always returns the current content, mtime-skip or not).
fn read_version_file(
    path: &Path,
    last_mtime: &mut Option<SystemTime>,
) -> std::io::Result<Option<String>> {
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    // Best-effort change detection: a reconciler that rewrites the file
    // with identical content on every poll is still safe (the caller
    // compares the returned string to what it already runs, same as a
    // `None` mtime), so a `mtime()` failure (some filesystems/platforms)
    // just means every poll re-reads, not an error.
    if let Ok(mtime) = metadata.modified() {
        if *last_mtime == Some(mtime) {
            // Unchanged since last poll -- still return the value (not
            // `None`): the caller decides whether "unchanged" matters,
            // this source only reports what's on disk right now.
        }
        *last_mtime = Some(mtime);
    }
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_none_not_error() {
        let mut src = FileVersionSource::new("/nonexistent/path/does-not-exist");
        assert_eq!(src.poll().unwrap(), None);
    }

    #[test]
    fn reads_trimmed_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("desired-version");
        std::fs::write(&path, "v1.2.3\n").unwrap();
        let mut src = FileVersionSource::new(&path);
        assert_eq!(src.poll().unwrap(), Some("v1.2.3".to_string()));
    }

    #[test]
    fn empty_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("desired-version");
        std::fs::write(&path, "   \n").unwrap();
        let mut src = FileVersionSource::new(&path);
        assert_eq!(src.poll().unwrap(), None);
    }

    #[test]
    fn picks_up_a_later_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("desired-version");
        std::fs::write(&path, "v1.0.0").unwrap();
        let mut src = FileVersionSource::new(&path);
        assert_eq!(src.poll().unwrap(), Some("v1.0.0".to_string()));
        std::fs::write(&path, "v1.1.0").unwrap();
        assert_eq!(src.poll().unwrap(), Some("v1.1.0".to_string()));
    }
}
