// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The tree lock (D-B3.7): held exclusively by the sync loop for the tens
//! of milliseconds it takes to fast-forward the real work tree onto a
//! rebased `live`. A builder write takes a shared, **non-blocking** guard
//! instead -- if the exclusive lock is held, `write_file` must fail fast
//! with "mudlib sync in progress, retry" rather than stall the world
//! thread waiting for it.

use std::sync::{Arc, RwLock};

use crate::cli::GitError;

/// Cheaply cloneable handle shared between the `GitWorker` (which takes
/// the write side during a sync fast-forward) and whatever calls
/// `write_file` (which takes the non-blocking read side around the
/// filesystem write + `git add`).
#[derive(Clone)]
pub struct TreeLock(Arc<RwLock<()>>);

impl Default for TreeLock {
    fn default() -> Self {
        Self::new()
    }
}

impl TreeLock {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(())))
    }

    /// Run `f` while holding the shared/read side, or fail fast with
    /// [`GitError::SyncInProgress`] if the exclusive/write side is
    /// currently held. This is the "write during sync lock fails fast"
    /// contract (D-B3.7) -- it never blocks.
    pub fn with_read<T>(&self, f: impl FnOnce() -> T) -> Result<T, GitError> {
        match self.0.try_read() {
            Ok(_guard) => Ok(f()),
            Err(_) => Err(GitError::SyncInProgress),
        }
    }

    /// Take the exclusive side, blocking until every in-flight read
    /// finishes. The sync loop calls this for the fast-forward step;
    /// public so tests can simulate "sync in progress" from outside the
    /// crate (the `write_during_sync_lock_fails_fast` acceptance test).
    pub fn write_guard(&self) -> std::sync::RwLockWriteGuard<'_, ()> {
        self.0
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_succeeds_with_no_writer() {
        let lock = TreeLock::new();
        assert_eq!(lock.with_read(|| 42), Ok(42));
    }

    #[test]
    fn read_fails_fast_while_writer_held() {
        let lock = TreeLock::new();
        let _guard = lock.write_guard();
        assert_eq!(lock.with_read(|| 1), Err(GitError::SyncInProgress));
    }
}
