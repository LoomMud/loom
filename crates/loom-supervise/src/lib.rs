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
//!   directly, plus [`VersionWatcher`] (change detection on top of any
//!   `VersionSource`: reports a version only the first time it differs
//!   from what's currently tracked). `loom-cli`'s `supervise` polls one
//!   on a timer, when `LOOM_DESIRED_VERSION_FILE` is set, and logs a
//!   detected change -- *detection* is wired in; actually driving a
//!   copyover off it is not (see below).
//! - [`listener`]: turning a received fd back into a `TcpListener`
//!   (`adopt_tcp_listener`) or an inherited control fd into a
//!   `UnixStream` (`control_stream_from_raw_fd`), plus the `fcntl`
//!   helpers (`clear_cloexec`) the handoff protocol needs.
//! - [`signal`]: `SIGTERM`/`SIGINT` forwarding from the supervisor to its
//!   child, and `PR_SET_PDEATHSIG` so an unexpected supervisor exit
//!   doesn't orphan the child -- required before `supervise` can become
//!   the container entrypoint without regressing `serve`'s graceful-
//!   shutdown path (CTO review, OBI-225). Wired into `loom-cli`'s
//!   `supervise`/`spawn_and_handoff`.
//! - `loom-cli`'s `supervise` subcommand and `serve --adopt-control-fd`
//!   wire the above into a real, end-to-end supervisor: one standby
//!   child at a time, signal-forwarded shutdown, and respawn-on-crash
//!   (any exit the supervisor didn't itself request is treated as
//!   transient and retried against the same already-bound listeners,
//!   bounded by a consecutive-crash limit) -- but still no replace-an-
//!   already-running-process copyover (see `loom-cli`'s own doc comments
//!   on `supervise`/`run_one_child_attempt` for exactly what's built and
//!   what isn't).
//!
//! Not yet implemented (each is its own follow-up slice/issue, not
//! silently deferred -- see OBI-184's tracking comments):
//! - Staging a cosign-verified driver artifact + `abi.json` from GHCR.
//! - The standby-boot / snapshot hand-off / `reconnect()` orchestration
//!   against an *already-running* old process -- the snapshot save/load
//!   and `reconnect()` apply themselves are OBI-221/Gimli's piece,
//!   merged; this crate's remaining job is actually *driving* that
//!   interface from a live copyover (quiesce -> drain -> reclaim fds via
//!   `fdpass::send_fds` -> snapshot -> spawn standby -> adopt fds/
//!   snapshot -> `reconnect_all` -> accept new conns), triggered by
//!   `VersionWatcher` detecting a change -- today a detected change is
//!   only logged, nothing acts on it yet.
//! - Abort/fallback paths specific to a *copyover* failing partway
//!   through (old driver keeps running; a re-exec fallback if the *new*
//!   process fails after takeover) -- distinct from the already-built
//!   respawn-on-crash, which only ever starts a fresh standby from
//!   scratch, never attempts a live hand-off.

pub mod fdpass;
pub mod listener;
pub mod signal;
pub mod version_source;

pub use version_source::{FileVersionSource, VersionSource, VersionWatcher};

// Loom only ever runs on Linux (the runtime image is debian/distroless,
// design §9.2), and this crate leans on Linux-specific ancillary-data
// behaviour `libc` doesn't even expose identically elsewhere (e.g.
// `MSG_CMSG_CLOEXEC`, `SCM_MAX_FD`'s value). Fail the build with a clear
// message rather than a wall of missing-constant errors from `libc` if
// someone ever points this crate at another target (CTO re-review nit,
// OBI-226).
#[cfg(not(target_os = "linux"))]
compile_error!(
    "loom-supervise is Linux-only (SCM_RIGHTS/MSG_CMSG_CLOEXEC semantics are not portable)"
);
