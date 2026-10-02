// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `loom-git`: the driver's one `git` client (spec §8.5, P2-B3.2, design
//! doc D-B3.1-D-B3.8/D-B3.11).
//!
//! Every builder save becomes a commit on `live`, pushed asynchronously to
//! `live/<env>`; `main` moves are pulled and `live` is rebased onto them,
//! and the changed set is handed to a [`RecompileHost`] so the world
//! thread can recompile it (spec §7.2, D-B3.14 / OBI-189's
//! `Registry::recompile_set`).
//!
//! # Layering
//! This crate knows nothing about `loom-vm`'s `Registry`/`World` or
//! `bcvm::ChangeSet` -- it only shells out to `git` (D-B3.1: CLI only, one
//! `GitWorker` thread) and calls back through the small [`RecompileHost`]
//! and [`TokenProvider`] traits. The crate that owns both the `World` and
//! this worker (today: a `loom-cli` follow-up, OBI-190 §8 "wiring") is
//! responsible for translating [`RecompileHost::recompile_set`]'s
//! `changed`/`deleted` lists into `bcvm::ChangeSet` and calling
//! `World::recompile_set` -- that is the documented interface contract
//! between B3.1 and B3.2.
//!
//! # What is *not* in this crate yet
//! - The actual hook into `loom-vm`'s `write_file` efun and the B2 files
//!   API PUT (B2 has not landed yet as of this writing). [`TreeLock`] and
//!   [`GitWorkerHandle::record_write`] are the two things a caller needs
//!   to wire in: take a [`TreeLock::with_read`] guard around the
//!   filesystem write, then call `record_write` to queue the commit.
//! - `propose` (B3.3) and the GitHub App token exchange: [`TokenProvider`]
//!   is the seam B3.3 implements.

mod cli;
mod identity;
mod lock;
mod metrics;
mod worker;

pub use cli::{GitError, WorktreeRepo};
pub use identity::Identity;
pub use lock::TreeLock;
pub use worker::{
    AuditSink, GitConfig, GitWorker, GitWorkerHandle, NoopAudit, RecompileHost, RecompileOutcome,
    TokenProvider,
};
