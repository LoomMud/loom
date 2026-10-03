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

/// Change detection on top of any [`VersionSource`] (OBI-184's
/// version-watching slice): a bare [`VersionSource::poll`] just reports
/// whatever is currently on disk/in the ConfigMap, every time, whether
/// or not it moved since the last poll -- exactly the right primitive
/// for a source, but not what a reconcile loop wants to act on directly
/// (it would otherwise need its own "is this actually new" bookkeeping
/// at every call site). `VersionWatcher` does that bookkeeping once:
/// [`poll_for_change`](Self::poll_for_change) only ever returns
/// `Some` the first time a given version string is observed.
pub struct VersionWatcher {
    source: Box<dyn VersionSource>,
    current: Option<String>,
}

impl VersionWatcher {
    /// `initial` is the version to treat as already-running (typically
    /// "whatever this supervisor process itself was started with"), so
    /// the very first poll doesn't spuriously report a "change" just
    /// because the source has *always* said that version -- only an
    /// actual difference from `initial` is a change worth reporting.
    pub fn new(source: Box<dyn VersionSource>, initial: Option<String>) -> Self {
        Self {
            source,
            current: initial,
        }
    }

    /// The version this watcher currently believes is running (either
    /// `initial`, or the most recent value a prior
    /// [`poll_for_change`](Self::poll_for_change) reported as a change).
    pub fn current(&self) -> Option<&str> {
        self.current.as_deref()
    }

    /// Poll the underlying source once. Returns `Ok(Some(version))` only
    /// if the source reports a version and it differs from the one this
    /// watcher currently tracks (which is then updated to match); `Ok
    /// (None)` if the source has nothing yet or reports the same version
    /// as before -- the common case on every poll where nothing changed.
    ///
    /// # Errors
    /// Propagates any `io::Error` from the underlying
    /// [`VersionSource::poll`] (e.g. a permissions error reading the
    /// file) without updating the tracked version -- a transient read
    /// failure must not be confused with "the version actually changed
    /// to nothing".
    pub fn poll_for_change(&mut self) -> std::io::Result<Option<String>> {
        let polled = self.source.poll()?;
        match polled {
            Some(version) if Some(version.as_str()) != self.current.as_deref() => {
                self.current = Some(version.clone());
                Ok(Some(version))
            }
            _ => Ok(None),
        }
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

    /// A trivial, fully in-memory [`VersionSource`] for [`VersionWatcher`]
    /// tests -- queueing exact poll results (including errors) gives
    /// tighter control than writing files for each case, and keeps these
    /// tests from depending on `FileVersionSource`'s own behavior (which
    /// has its own tests above).
    struct ScriptedSource {
        results: std::collections::VecDeque<std::io::Result<Option<String>>>,
    }

    impl ScriptedSource {
        fn new(results: Vec<std::io::Result<Option<String>>>) -> Self {
            Self {
                results: results.into(),
            }
        }
    }

    impl VersionSource for ScriptedSource {
        fn poll(&mut self) -> std::io::Result<Option<String>> {
            self.results.pop_front().unwrap_or(Ok(None))
        }
    }

    #[test]
    fn version_watcher_reports_the_first_differing_value_as_a_change() {
        let source = ScriptedSource::new(vec![Ok(Some("v1".to_string()))]);
        let mut watcher = VersionWatcher::new(Box::new(source), None);
        assert_eq!(watcher.poll_for_change().unwrap(), Some("v1".to_string()));
        assert_eq!(watcher.current(), Some("v1"));
    }

    #[test]
    fn version_watcher_does_not_report_a_change_if_the_initial_version_already_matches() {
        let source = ScriptedSource::new(vec![Ok(Some("v1".to_string()))]);
        let mut watcher = VersionWatcher::new(Box::new(source), Some("v1".to_string()));
        assert_eq!(watcher.poll_for_change().unwrap(), None);
    }

    #[test]
    fn version_watcher_does_not_report_the_same_version_twice() {
        let source =
            ScriptedSource::new(vec![Ok(Some("v1".to_string())), Ok(Some("v1".to_string()))]);
        let mut watcher = VersionWatcher::new(Box::new(source), None);
        assert_eq!(watcher.poll_for_change().unwrap(), Some("v1".to_string()));
        assert_eq!(watcher.poll_for_change().unwrap(), None);
    }

    #[test]
    fn version_watcher_reports_each_subsequent_change() {
        let source = ScriptedSource::new(vec![
            Ok(Some("v1".to_string())),
            Ok(Some("v1".to_string())),
            Ok(Some("v2".to_string())),
        ]);
        let mut watcher = VersionWatcher::new(Box::new(source), None);
        assert_eq!(watcher.poll_for_change().unwrap(), Some("v1".to_string()));
        assert_eq!(watcher.poll_for_change().unwrap(), None);
        assert_eq!(watcher.poll_for_change().unwrap(), Some("v2".to_string()));
        assert_eq!(watcher.current(), Some("v2"));
    }

    #[test]
    fn version_watcher_ignores_a_source_reporting_nothing_yet() {
        let source = ScriptedSource::new(vec![Ok(None), Ok(Some("v1".to_string()))]);
        let mut watcher = VersionWatcher::new(Box::new(source), None);
        assert_eq!(watcher.poll_for_change().unwrap(), None);
        assert_eq!(watcher.poll_for_change().unwrap(), Some("v1".to_string()));
    }

    #[test]
    fn version_watcher_propagates_a_source_error_without_updating_current() {
        let source = ScriptedSource::new(vec![
            Err(std::io::Error::other("boom")),
            Ok(Some("v1".to_string())),
        ]);
        let mut watcher = VersionWatcher::new(Box::new(source), Some("v0".to_string()));
        assert!(watcher.poll_for_change().is_err());
        assert_eq!(
            watcher.current(),
            Some("v0"),
            "a poll error must not clobber the previously tracked version"
        );
        assert_eq!(watcher.poll_for_change().unwrap(), Some("v1".to_string()));
    }
}
