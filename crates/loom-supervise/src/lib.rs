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
//!
//! Not yet implemented here (each is its own follow-up slice/issue, not
//! silently deferred -- see OBI-184's tracking comments):
//! - Staging a cosign-verified driver artifact + `abi.json` from GHCR.
//! - The standby-boot / snapshot hand-off / `reconnect()` orchestration
//!   itself (the snapshot save/load and `reconnect()` apply are Gimli's
//!   piece, a child of OBI-184; this crate's job is to call into that at
//!   the right point in the state machine, not to reimplement it).
//! - Abort/fallback paths (old driver keeps running on any standby
//!   failure; a re-exec fallback if the *new* process fails after
//!   takeover).
//! - Wiring `loom-cli`'s `serve()` to accept pre-bound listening fds
//!   (today it always calls `TcpListener::bind` itself) and a
//!   corresponding `supervise` subcommand in `loom-cli`.

pub mod fdpass;
pub mod version_source;

pub use version_source::{FileVersionSource, VersionSource};
