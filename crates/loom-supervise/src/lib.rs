// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `loom supervise`: the in-pod supervisor that owns the listening
//! sockets and performs copyover (design §7.5, §9.2, §9.9; tracked as
//! P2-O1 / OBI-184).
//!
//! This crate is being built incrementally; see OBI-184 for the slice
//! plan. What's here so far:
//!
//! - [`fdpass`]: `SCM_RIGHTS` file-descriptor passing over a `UnixStream`
//!   control socket -- the primitive step 2 of §7.5 needs ("Pass
//!   listening & client sockets to the new process via Unix-domain socket
//!   FD passing"). Fully unit-tested (real socket pairs, real pipe fds).
//! - [`version_source`]: the `VersionSource` seam between "what version
//!   should run" (a file today, written by the Docker-staging reconciler;
//!   a `loom-release` ConfigMap key once K1/OBI-187 lands) and the
//!   supervisor's reconcile loop, which never looks at either source
//!   directly.
//! - [`listener`]: turning a received fd back into a `TcpListener`
//!   (`adopt_tcp_listener`) or an inherited control fd into a
//!   `UnixStream` (`control_stream_from_raw_fd`), plus the `fcntl`
//!   helpers (`clear_cloexec`) the handoff protocol needs.
//! - `loom-cli`'s `supervise` subcommand and `serve --adopt-control-fd`
//!   wire the above into a real, end-to-end first copyover slice (one
//!   standby child, no replace-an-already-running-process handoff yet --
//!   see `loom-cli`'s own doc comments on `supervise`/`spawn_and_handoff`
//!   for exactly what that first slice does and doesn't do).
//!
//! Not yet implemented (each is its own follow-up slice/issue, not
//! silently deferred -- see OBI-184's tracking comments):
//! - Staging a cosign-verified driver artifact + `abi.json` from GHCR.
//! - The standby-boot / snapshot hand-off / `reconnect()` orchestration
//!   against an *already-running* old process (the snapshot save/load and
//!   `reconnect()` apply themselves are OBI-221/Gimli's piece, merged;
//!   this crate's remaining job is driving that interface from a live
//!   copyover, not a fresh boot).
//! - Abort/fallback paths (old driver keeps running on any standby
//!   failure; a re-exec fallback if the *new* process fails after
//!   takeover).
//! - Version-watching (`VersionSource` exists but nothing polls it yet)
//!   and respawn-on-crash.
//! - Signal forwarding (SIGTERM/SIGINT to the child, `PR_SET_PDEATHSIG`)
//!   -- required before `supervise` can become the container entrypoint
//!   without regressing `serve`'s graceful-shutdown path (CTO review,
//!   OBI-225).

pub mod fdpass;
pub mod listener;
pub mod version_source;

pub use version_source::{FileVersionSource, VersionSource};
